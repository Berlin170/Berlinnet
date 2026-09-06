"""OpenWrt adapter, driven through the ubus JSON-RPC endpoint.

OpenWrt is the case where blocking is genuinely clean: it exposes a documented
RPC API, and a block is a real firewall rule that the router enforces. This
adapter is included because it is the honest answer to "what should I buy if I
want this app to be able to block things".

Requires uhttpd-mod-ubus (shipped by default in recent releases) and an ACL
that permits the account to call uci and file.exec.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Optional

import httpx

from ..credentials import RouterCredentials
from .base import (
    ActionResult, AuthState, BlockMethod, Capabilities, RouterAdapter, RouterInfo,
    GENERIC_ALTERNATIVES, NO_BLOCKING_MESSAGE,
)

UBUS_PATH = "/ubus"
RULE_PREFIX = "ldm_block_"


class OpenWrtAdapter(RouterAdapter):
    name = "openwrt"
    vendor = "OpenWrt"

    def __init__(self, info: RouterInfo) -> None:
        super().__init__(info)
        self.base = f"http://{info.ip}"
        self._client: Optional[httpx.Client] = None
        self._session: Optional[str] = None
        self._auth_state = AuthState.UNKNOWN

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        score = 0
        server = (info.http_server or "").lower()
        model = (info.model or "").lower()
        if "openwrt" in model or "luci" in model or "dd-wrt" in model:
            score += 70
        if "uhttpd" in server:
            score += 40
        return min(score, 100)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(base_url=self.base, timeout=httpx.Timeout(10.0),
                                        headers={"User-Agent": "LAN-Device-Manager/1.0"})
        return self._client

    def _call(self, obj: str, method: str, params: Optional[dict] = None) -> Optional[Any]:
        """One ubus JSON-RPC call. Returns the payload, or None on any failure."""
        if not self._session:
            return None
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [self._session, obj, method, params or {}],
        }
        try:
            response = self._http().post(UBUS_PATH, json=body)
            data = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            return None
        result = data.get("result")
        # ubus returns [status, payload]; status 0 means success.
        if isinstance(result, list) and result and result[0] == 0:
            return result[1] if len(result) > 1 else {}
        return None

    def authenticate(self, credentials: RouterCredentials) -> ActionResult:
        try:
            if not ipaddress.ip_address(self.info.ip).is_private:
                return ActionResult(False, "Refusing to send credentials off the LAN.")
        except ValueError:
            return ActionResult(False, "Invalid router address.")

        body = {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": ["00000000000000000000000000000000", "session", "login",
                       {"username": credentials.username, "password": credentials.password}],
        }
        try:
            response = self._http().post(UBUS_PATH, json=body)
            data = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            return ActionResult(False, f"Could not reach the ubus endpoint: {exc.__class__.__name__}")

        result = data.get("result")
        if not (isinstance(result, list) and result and result[0] == 0):
            self._auth_state = AuthState.FAILED
            return ActionResult(False, "OpenWrt rejected those credentials.")

        self._session = (result[1] or {}).get("ubus_rpc_session")
        if not self._session:
            self._auth_state = AuthState.FAILED
            return ActionResult(False, "OpenWrt did not return a session token.")

        self.credentials = credentials
        self._auth_state = AuthState.AUTHENTICATED
        self._capabilities = None
        return ActionResult(True, "Signed in to OpenWrt.")

    def probe_capabilities(self) -> Capabilities:
        probed = [f"POST {UBUS_PATH} (ubus JSON-RPC)"]
        if self._auth_state != AuthState.AUTHENTICATED:
            return Capabilities(
                can_block=False, method=BlockMethod.NONE, requires_auth=True,
                auth_state=AuthState.REQUIRED,
                unsupported_reason="Sign in to OpenWrt to enable blocking.",
                alternatives=GENERIC_ALTERNATIVES, probed=probed,
            )

        firewall = self._call("uci", "get", {"config": "firewall"})
        probed.append("uci get firewall -> " + ("ok" if firewall is not None else "denied"))
        leases = self._call("luci-rpc", "getDHCPLeases") or self._call("dhcp", "ipv4leases")
        probed.append("DHCP leases -> " + ("ok" if leases is not None else "unavailable"))

        if firewall is None:
            return Capabilities(
                can_block=False, method=BlockMethod.NONE, requires_auth=True,
                auth_state=AuthState.AUTHENTICATED,
                unsupported_reason=(
                    NO_BLOCKING_MESSAGE + " The signed-in OpenWrt account is not "
                    "permitted to read or write the firewall configuration. Grant it "
                    "the uci ACL, or sign in as root."
                ),
                alternatives=GENERIC_ALTERNATIVES, probed=probed,
            )

        return Capabilities(
            can_block=True, method=BlockMethod.FIREWALL_RULE,
            can_list_clients=leases is not None,
            requires_auth=True, auth_state=AuthState.AUTHENTICATED, probed=probed,
        )

    def _rule_name(self, mac: str) -> str:
        return RULE_PREFIX + mac.replace(":", "").lower()

    def _commit(self) -> bool:
        if self._call("uci", "commit", {"config": "firewall"}) is None:
            return False
        # Reload so the rule is actually in the running ruleset.
        self._call("file", "exec", {"command": "/etc/init.d/firewall", "params": ["reload"]})
        return True

    def _block(self, mac: str, ip: Optional[str]) -> ActionResult:
        name = self._rule_name(mac)
        added = self._call("uci", "add", {
            "config": "firewall", "type": "rule", "name": name,
            "values": {
                "name": name, "src": "lan", "dest": "wan",
                "src_mac": mac.upper(), "target": "REJECT", "enabled": "1",
            },
        })
        if added is None:
            return ActionResult(False, "OpenWrt refused to add the firewall rule.")
        if not self._commit():
            return ActionResult(False, "The rule was staged but could not be committed.")
        return ActionResult(True, f"{mac} blocked by an OpenWrt firewall rule.",
                            method=BlockMethod.FIREWALL_RULE, detail=name)

    def _unblock(self, mac: str, ip: Optional[str]) -> ActionResult:
        name = self._rule_name(mac)
        if self._call("uci", "delete", {"config": "firewall", "section": name}) is None:
            return ActionResult(False, "No matching rule was found to remove.")
        if not self._commit():
            return ActionResult(False, "The rule was removed but could not be committed.")
        return ActionResult(True, f"{mac} unblocked.", method=BlockMethod.FIREWALL_RULE,
                            detail=name)

    def blocked_macs(self) -> list[str]:
        config = self._call("uci", "get", {"config": "firewall"}) or {}
        found: list[str] = []
        for section in (config.get("values") or {}).values():
            if not isinstance(section, dict):
                continue
            if str(section.get("name", "")).startswith(RULE_PREFIX) and section.get("src_mac"):
                found.append(str(section["src_mac"]).lower())
        return sorted(set(found))

    def list_clients(self) -> dict[str, dict]:
        leases = self._call("luci-rpc", "getDHCPLeases") or {}
        clients: dict[str, dict] = {}
        for entry in (leases.get("dhcp_leases") or []):
            mac = str(entry.get("macaddr") or "").lower()
            if mac:
                clients[mac] = {"ip": entry.get("ipaddr"),
                                "hostname": entry.get("hostname"),
                                "source": "openwrt-dhcp"}
        return clients

    def logout(self) -> None:
        if self._session:
            self._call("session", "destroy", {"ubus_rpc_session": self._session})
        if self._client is not None:
            self._client.close()
            self._client = None
        self._session = None
        self._auth_state = AuthState.UNKNOWN
        super().logout()
