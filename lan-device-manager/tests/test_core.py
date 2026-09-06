"""Offline regression tests.

These exercise the logic that does not need a live network: storage identity
and merging, vendor lookup, classification, DNS parsing, and the honesty rules
around blocking. Run with:

    python -m tests.test_core
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lan_device_manager.db import Database, device_key
from lan_device_manager.net import classify, hostname, oui
from lan_device_manager.net.arp import is_locally_administered, is_multicast_mac
from lan_device_manager.routers.base import (
    BlockMethod, NO_BLOCKING_MESSAGE, RouterInfo,
)
from lan_device_manager.routers.generic import GenericAdapter
from lan_device_manager.routers.huawei import HuaweiAdapter
from lan_device_manager.routers.registry import select_adapter_class


def make_device(ip, mac=None, **extra):
    base = {
        "ip": ip, "mac": mac, "hostname": None, "hostname_source": None,
        "vendor": "Unknown", "category": "Unknown", "category_confidence": "low",
        "category_reason": "", "open_ports": [], "responded_to": ["icmp"],
        "is_gateway": False, "is_self": False,
    }
    base.update(extra)
    return base


class TemporaryDatabase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._dir.name) / "test.db")

    def tearDown(self):
        self.db.close()
        self._dir.cleanup()


class TestDeviceIdentity(TemporaryDatabase):
    def test_mac_is_preferred_identity(self):
        self.assertEqual(device_key("AA:BB:CC:DD:EE:FF", "10.0.0.1"), "mac:aa:bb:cc:dd:ee:ff")
        self.assertEqual(device_key(None, "10.0.0.1"), "ip:10.0.0.1")

    def test_device_survives_ip_change(self):
        self.db.upsert_scan_results([make_device("10.0.0.5", "aa:bb:cc:00:00:01")])
        key = "mac:aa:bb:cc:00:00:01"
        self.db.update_device(key, custom_name="Kitchen tablet")

        self.db.upsert_scan_results([make_device("10.0.0.99", "aa:bb:cc:00:00:01")])

        devices = self.db.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "10.0.0.99")
        self.assertEqual(devices[0]["custom_name"], "Kitchen tablet")

    def test_ip_record_is_promoted_when_mac_appears(self):
        """A host seen before its MAC lands in ARP must not become two rows."""
        self.db.upsert_scan_results([make_device("10.0.0.7")])
        self.db.update_device("ip:10.0.0.7", custom_name="Mystery box",
                              notes="seen at 3am", trust="trusted")

        self.db.upsert_scan_results([make_device("10.0.0.7", "de:ad:be:ef:00:01")])

        devices = self.db.list_devices()
        self.assertEqual(len(devices), 1, "the ip: row should have been promoted, not duplicated")
        record = devices[0]
        self.assertEqual(record["key"], "mac:de:ad:be:ef:00:01")
        self.assertEqual(record["custom_name"], "Mystery box")
        self.assertEqual(record["notes"], "seen at 3am")
        self.assertEqual(record["trust"], "trusted")
        # History follows the device across the promotion.
        self.assertTrue(self.db.list_events(key="mac:de:ad:be:ef:00:01"))

    def test_offline_transition_and_stats(self):
        self.db.upsert_scan_results([
            make_device("10.0.0.1", "aa:bb:cc:00:00:01"),
            make_device("10.0.0.2", "aa:bb:cc:00:00:02"),
        ])
        self.assertEqual(self.db.stats()["online"], 2)

        self.db.upsert_scan_results([make_device("10.0.0.1", "aa:bb:cc:00:00:01")])
        stats = self.db.stats()
        self.assertEqual(stats["online"], 1)
        self.assertEqual(stats["offline"], 1)
        self.assertEqual(stats["total"], 2)

    def test_new_devices_are_reported_once(self):
        first = self.db.upsert_scan_results([make_device("10.0.0.1", "aa:bb:cc:00:00:01")])
        self.assertEqual(len(first["new"]), 1)
        second = self.db.upsert_scan_results([make_device("10.0.0.1", "aa:bb:cc:00:00:01")])
        self.assertEqual(len(second["new"]), 0)

    def test_hostname_is_not_erased_by_a_quiet_scan(self):
        self.db.upsert_scan_results([
            make_device("10.0.0.1", "aa:bb:cc:00:00:01", hostname="pixel", hostname_source="mdns")
        ])
        self.db.upsert_scan_results([make_device("10.0.0.1", "aa:bb:cc:00:00:01")])
        self.assertEqual(self.db.list_devices()[0]["hostname"], "pixel")

    def test_empty_scan_marks_everything_offline(self):
        self.db.upsert_scan_results([make_device("10.0.0.1", "aa:bb:cc:00:00:01")])
        self.db.upsert_scan_results([])
        self.assertEqual(self.db.stats()["online"], 0)


class TestVendorLookup(unittest.TestCase):
    def test_randomised_macs_are_named_as_such(self):
        # Locally administered bit set - these are the addresses modern phones use.
        for mac in ("a6:8f:08:26:18:90", "02:bd:cf:da:52:0b", "9a:a0:b5:fc:61:81"):
            self.assertTrue(is_locally_administered(mac), mac)
            self.assertEqual(oui.lookup(mac), oui.RANDOMISED)
            self.assertFalse(oui.is_identifiable(mac))

    def test_real_oui_resolves(self):
        # The exact string depends on whether the full IEEE registry has been
        # downloaded ("Raspberry Pi Foundation" vs the bundled "Raspberry Pi"),
        # so match on the part that is stable.
        self.assertIn("Raspberry Pi", oui.lookup("b8:27:eb:11:22:33"))
        self.assertIn("Apple", oui.lookup("00:1b:63:11:22:33"))

    def test_unknown_and_malformed_input(self):
        self.assertEqual(oui.lookup(""), oui.UNKNOWN)
        self.assertEqual(oui.lookup("zz"), oui.UNKNOWN)
        self.assertEqual(oui.lookup("01:00:00:00:00:00"), oui.UNKNOWN)

    def test_multicast_detection(self):
        self.assertTrue(is_multicast_mac("01:00:5e:00:00:16"))
        self.assertFalse(is_multicast_mac("b8:27:eb:11:22:33"))


class TestClassification(unittest.TestCase):
    def test_gateway_and_self_win(self):
        self.assertEqual(classify.classify(is_gateway=True).category, classify.ROUTER)
        self.assertEqual(classify.classify(is_self=True).category, classify.COMPUTER)

    def test_ports_identify_services(self):
        self.assertEqual(classify.classify(open_ports=[9100]).category, classify.PRINTER)
        self.assertEqual(classify.classify(open_ports=[554]).category, classify.CAMERA)
        self.assertEqual(classify.classify(open_ports=[62078]).category, classify.PHONE)

    def test_hostname_beats_vendor(self):
        verdict = classify.classify(hostname="Johns-iPhone", vendor="Intel")
        self.assertEqual(verdict.category, classify.PHONE)
        self.assertEqual(verdict.confidence, "high")

    def test_no_signal_is_admitted_not_guessed(self):
        verdict = classify.classify()
        self.assertEqual(verdict.category, classify.UNKNOWN)
        self.assertEqual(verdict.confidence, "low")


class TestLinkDetection(unittest.TestCase):
    """Wired vs Wi-Fi from timing, which is what separates your own kit from
    someone else's phone when every MAC is randomised."""

    def test_switched_ethernet_reads_as_wired(self):
        kind, _ = classify.link_type(0.4, 1.0)
        self.assertEqual(kind, classify.WIRED)

    def test_sleeping_wifi_client_reads_as_wireless(self):
        # Real measurements taken from the network this was built on.
        for avg, jitter in ((47.0, 18.0), (86.0, 234.0), (44.0, 38.0)):
            kind, _ = classify.link_type(avg, jitter)
            self.assertEqual(kind, classify.WIRELESS, f"{avg}/{jitter}")

    def test_high_jitter_alone_is_enough(self):
        # Low average but wildly variable is still a radio.
        kind, _ = classify.link_type(14.0, 44.0)
        self.assertEqual(kind, classify.WIRELESS)

    def test_ambiguous_timing_is_admitted_not_guessed(self):
        # Close-range Wi-Fi can beat 3ms, so this band must not claim "wired".
        kind, _ = classify.link_type(2.5, 2.0)
        self.assertEqual(kind, classify.LINK_UNKNOWN)

    def test_silent_host_is_unknown(self):
        kind, _ = classify.link_type(None, None)
        self.assertEqual(kind, classify.LINK_UNKNOWN)

    def test_known_roles_short_circuit(self):
        self.assertEqual(classify.link_type(99.0, 99.0, is_gateway=True)[0], classify.WIRED)
        self.assertEqual(classify.link_type(99.0, 99.0, is_self=True)[0], classify.WIRED)
        self.assertEqual(
            classify.link_type(0.1, 0.1, is_self=True, self_is_wired=False)[0],
            classify.WIRELESS,
        )


class TestDnsParsing(unittest.TestCase):
    @staticmethod
    def _labels(name):
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"

    def test_skip_name_handles_pointers_and_labels(self):
        raw = self._labels("a.b") + b"XX"
        self.assertEqual(hostname._skip_name(raw, 0), len(raw) - 2)
        self.assertEqual(hostname._skip_name(b"\xc0\x0c", 0), 2)

    def test_decode_name_follows_compression(self):
        data = b"\x00" * 12 + self._labels("host.local")
        self.assertEqual(hostname._decode_name(data, 12), "host.local")

    def test_decode_name_survives_pointer_loop(self):
        # A pointer chain that never terminates must not hang the scanner.
        data = b"\x00" * 12 + b"\xc0\x0c"
        self.assertIsNone(hostname._decode_name(data, 12))


class TestBlockingHonesty(unittest.TestCase):
    """The rules the app exists to keep."""

    def test_huawei_reads_button_login_challenge(self):
        page = '<button id="GenRandom">93xnwn</button>'
        self.assertEqual(HuaweiAdapter._login_challenge(page), "93xnwn")

    def test_huawei_reads_input_login_challenge(self):
        page = '<input name="GenRandom" type="button" value="h7K2qP">'
        self.assertEqual(HuaweiAdapter._login_challenge(page), "h7K2qP")

    def test_huawei_rejects_missing_login_challenge(self):
        self.assertIsNone(HuaweiAdapter._login_challenge('<form></form>'))

    def test_check_code_matches_router_shape(self):
        # getRandomLetterNum(6): six base-36 chars (0-9a-z), as the router's JS.
        code = HuaweiAdapter._check_code(6)
        self.assertEqual(len(code), 6)
        self.assertRegex(code, r"^[0-9a-z]{6}$")

    def test_prefers_add_page_over_list_page(self):
        # The list page (sec_macfilter.asp) has no MAC field; the add sub-page
        # does. Anchoring on the list page but reading fields from the add page
        # is the whole fix - a naive alphabetical match picks the add page as
        # the anchor and breaks the read-back.
        list_body = (
            '<a href="sec_addmacfilter.asp">Add</a>'
            '<table><tr><td>test</td><td>8e:70:5e:28:7c:9c</td></tr></table>'
        )
        pages = {
            "/html/security/sec_macfilter.asp": list_body,
            "/html/security/sec_addmacfilter.asp": '<input name="MACAddress" value="">',
        }
        adapter = HuaweiAdapter(RouterInfo(ip="10.0.0.1", model="HG8547M"))
        adapter._block_page = "/html/security/sec_macfilter.asp"
        found = adapter._find_add_page(list_body, pages)
        self.assertIn("sec_addmacfilter.asp", found)

    def test_add_payload_carries_mac_enable_token_and_code(self):
        body = (
            '<form action="sec_macfilterlist.cgi">'
            '<input type="text" name="FilterName" value="">'
            '<input type="text" name="MACAddress" value="">'
            '<input type="checkbox" name="Enable" value="1" checked>'
            '<input type="text" name="txt_RandomCode" value="">'
            '<input type="hidden" name="x.X_HW_Token" value="abc123token">'
            '</form>'
        )
        adapter = HuaweiAdapter(RouterInfo(ip="10.0.0.1", model="HG8547M"))
        adapter._block_page = "/html/security/sec_macfilter.asp"
        adapter._add_page = "/html/security/sec_addmacfilter.asp"
        adapter._pages = {adapter._add_page: body}

        captured = {}

        def fake_submit(target, payload, referer, mac, expect_present):
            captured["target"], captured["payload"] = target, payload
            from lan_device_manager.routers.base import ActionResult
            return ActionResult(True, "ok")

        adapter._submit_and_confirm = fake_submit
        adapter._add_filter("8e:70:5e:28:7c:9c")

        payload = captured["payload"]
        self.assertEqual(payload["MACAddress"], "8e:70:5e:28:7c:9c")
        self.assertEqual(payload["Enable"], "1")
        self.assertEqual(payload["x.X_HW_Token"], "abc123token")
        self.assertRegex(payload["txt_RandomCode"], r"^[0-9a-z]{6}$")
        self.assertTrue(captured["target"].endswith("sec_macfilterlist.cgi"))

    def test_generic_adapter_never_claims_blocking(self):
        adapter = GenericAdapter(RouterInfo(ip="10.0.0.1"))
        caps = adapter.capabilities()
        self.assertFalse(caps.can_block)
        self.assertEqual(caps.method, BlockMethod.NONE)
        self.assertIn(NO_BLOCKING_MESSAGE, caps.unsupported_reason)
        self.assertTrue(caps.alternatives, "must offer real alternatives instead")

    def test_block_refuses_without_capability(self):
        adapter = GenericAdapter(RouterInfo(ip="10.0.0.1"))
        result = adapter.block("aa:bb:cc:dd:ee:ff")
        self.assertFalse(result.ok)
        self.assertEqual(result.method, BlockMethod.NONE)

    def test_unauthenticated_huawei_reports_no_blocking(self):
        adapter = HuaweiAdapter(RouterInfo(ip="10.0.0.1", model="HG8547M"))
        caps = adapter.capabilities()
        self.assertFalse(caps.can_block)
        self.assertTrue(caps.requires_auth)

    def test_adapter_selection_matches_fingerprint(self):
        huawei = RouterInfo(ip="10.0.0.1", model="HG8547M", vendor="Huawei",
                            http_server="Boa/0.94.13")
        chosen, score = select_adapter_class(huawei)
        self.assertEqual(chosen.name, "huawei")
        self.assertGreaterEqual(score, 70)

        unknown = RouterInfo(ip="10.0.0.1")
        chosen, _ = select_adapter_class(unknown)
        self.assertEqual(chosen.name, "generic")

    def test_openwrt_beats_generic_when_identified(self):
        info = RouterInfo(ip="10.0.0.1", model="OpenWrt 23.05", http_server="uhttpd")
        chosen, _ = select_adapter_class(info)
        self.assertEqual(chosen.name, "openwrt")


class TestCredentialHygiene(unittest.TestCase):
    def test_redaction_never_exposes_the_password(self):
        from lan_device_manager.credentials import RouterCredentials
        creds = RouterCredentials("admin", "s3cret-value")
        self.assertNotIn("s3cret", str(creds.redacted()))
        self.assertEqual(creds.redacted()["username"], "admin")

    def test_round_trip_when_dpapi_is_available(self):
        from lan_device_manager.credentials import decrypt, encrypt, is_available
        if not is_available():
            self.skipTest("DPAPI is Windows-only")
        token = encrypt("correct horse battery staple")
        self.assertIsNotNone(token)
        self.assertNotIn("correct horse", token)
        self.assertEqual(decrypt(token), "correct horse battery staple")

    def test_garbage_tokens_return_none(self):
        from lan_device_manager.credentials import decrypt
        for bad in ("", "not-base64!!", "aGVsbG8="):
            self.assertIsNone(decrypt(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
