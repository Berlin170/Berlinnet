"""Fallback adapters.

GenericAdapter is what you get when the router is not one this app knows how to
drive. It is deliberately honest: it reports no blocking capability and hands
the user the list of things that would actually work, rather than offering a
Block button that quietly does nothing.

LocalGatewayAdapter covers the one case where this PC can legitimately enforce
a block itself: when traffic from the device is routed through this machine
(internet connection sharing, a hosted hotspot, a VM bridge). Then a Windows
Firewall rule is a real block, because the packets pass through here.
"""

from __future__ import annotations

import re
from typing import Optional

from .base import (
    ActionResult, AuthState, BlockMethod, Capabilities, RouterAdapter, RouterInfo,
    GENERIC_ALTERNATIVES, NO_BLOCKING_MESSAGE,
)
from ..net.shell import run

RULE_PREFIX = "LDM Block "


class GenericAdapter(RouterAdapter):
    """Matches anything, at the lowest possible confidence."""

    name = "generic"
    vendor = "Unknown"

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        return 1        # always the last resort

    def probe_capabilities(self) -> Capabilities:
        evidence = []
        if self.info.http_server:
            evidence.append(f"HTTP server banner: {self.info.http_server}")
        if self.info.open_ports:
            evidence.append(f"Open ports: {self.info.open_ports}")
        return Capabilities(
            can_block=False,
            method=BlockMethod.NONE,
            can_list_clients=False,
            requires_auth=True,
            auth_state=AuthState.UNKNOWN,
            unsupported_reason=(
                NO_BLOCKING_MESSAGE + " No adapter in this app recognises the router "
                "at this gateway, so there is no supported mechanism to drive."
            ),
            alternatives=GENERIC_ALTERNATIVES,
            probed=evidence or ["No identifying information from the gateway"],
        )


class LocalGatewayAdapter(RouterAdapter):
    """Blocks at this machine, for devices whose traffic actually routes here.

    This is a real block only for such devices. It is never offered as a way to
    cut off a device that talks to the router directly - that traffic never
    passes through this PC, so a local firewall rule cannot touch it.
    """

    name = "local_gateway"
    vendor = "This computer"

    @classmethod
    def detect(cls, info: RouterInfo) -> int:
        return 0        # only selected explicitly, never auto-detected

    @staticmethod
    def _is_elevated() -> bool:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def _forwarding_enabled() -> bool:
        """Whether this machine actually routes traffic for other hosts."""
        out = run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-NetIPInterface -AddressFamily IPv4 | "
            "Where-Object Forwarding -eq 'Enabled' | Measure-Object).Count",
        ], timeout=15)
        try:
            return int(out.strip() or "0") > 0
        except ValueError:
            return False

    def probe_capabilities(self) -> Capabilities:
        elevated = self._is_elevated()
        forwarding = self._forwarding_enabled()
        probed = [
            f"IP forwarding enabled on this PC: {forwarding}",
            f"Running as administrator: {elevated}",
        ]

        if not forwarding:
            return Capabilities(
                can_block=False, method=BlockMethod.NONE, requires_auth=False,
                auth_state=AuthState.NOT_REQUIRED,
                unsupported_reason=(
                    "This computer is not acting as a gateway, so traffic from other "
                    "devices does not pass through it. A firewall rule here would not "
                    "block anything."
                ),
                alternatives=GENERIC_ALTERNATIVES, probed=probed,
            )

        if not elevated:
            return Capabilities(
                can_block=False, method=BlockMethod.NONE, requires_auth=False,
                auth_state=AuthState.NOT_REQUIRED,
                unsupported_reason=(
                    "This computer is routing traffic, so local blocking would work, "
                    "but adding a firewall rule needs administrator rights. Restart "
                    "the app as administrator to enable it."
                ),
                alternatives=GENERIC_ALTERNATIVES, probed=probed,
            )

        return Capabilities(
            can_block=True, method=BlockMethod.LOCAL_GATEWAY, requires_auth=False,
            auth_state=AuthState.NOT_REQUIRED, probed=probed,
        )

    def _block(self, mac: str, ip: Optional[str]) -> ActionResult:
        if not ip:
            return ActionResult(False, "A local firewall rule needs the device's IP address.")
        name = f"{RULE_PREFIX}{ip}"
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
             "dir=in", "action=block", f"remoteip={ip}"], timeout=20)
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
             "dir=out", "action=block", f"remoteip={ip}"], timeout=20)
        if not self._rule_exists(name):
            return ActionResult(False, "Windows Firewall did not accept the rule.")
        return ActionResult(
            True,
            f"{ip} blocked by a Windows Firewall rule on this computer. This stops "
            f"traffic that routes through this PC only.",
            method=BlockMethod.LOCAL_GATEWAY, detail=name,
        )

    def _unblock(self, mac: str, ip: Optional[str]) -> ActionResult:
        if not ip:
            return ActionResult(False, "The device's IP address is needed to remove the rule.")
        name = f"{RULE_PREFIX}{ip}"
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], timeout=20)
        if self._rule_exists(name):
            return ActionResult(False, "The firewall rule could not be removed.")
        return ActionResult(True, f"Firewall rule for {ip} removed.",
                            method=BlockMethod.LOCAL_GATEWAY, detail=name)

    @staticmethod
    def _rule_exists(name: str) -> bool:
        out = run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                  timeout=20)
        return "No rules match" not in out and name in out

    def blocked_macs(self) -> list[str]:
        return []

    def blocked_ips(self) -> list[str]:
        out = run(["netsh", "advfirewall", "firewall", "show", "rule",
                   "name=all"], timeout=30)
        return sorted(set(re.findall(re.escape(RULE_PREFIX) + r"(\d+\.\d+\.\d+\.\d+)", out)))
