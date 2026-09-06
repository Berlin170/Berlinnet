"""The RouterAdapter interface.

This is the seam between discovery and blocking. Discovery works on any
network; blocking only works if the router in front of you actually exposes a
mechanism for it, and the whole point of this layer is to answer that question
honestly rather than pretend.

An adapter must be able to say, before anything is attempted:

  * which router it thinks it is talking to (detect);
  * whether it can block at all, and by what mechanism (capabilities);
  * what the user should do instead when it cannot (unsupported_reason).

Rules every adapter follows:
  * authentication is never bypassed, guessed or brute-forced;
  * no vulnerability is exploited to gain access;
  * credentials come from the user and are never logged;
  * if a mechanism is not confirmed to exist, capabilities must report NONE.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from ..credentials import RouterCredentials


class BlockMethod(str, Enum):
    """How an adapter would enforce a block, if it can."""

    NONE = "none"                     # no supported mechanism on this router
    MAC_FILTER = "mac_filter"         # wired/wireless MAC allow or deny list
    ACCESS_CONTROL = "access_control" # per-client access control list
    FIREWALL_RULE = "firewall_rule"   # firewall rule keyed on IP or MAC
    WLAN_CONTROL = "wlan_control"     # per-SSID client control
    PARENTAL_CONTROL = "parental_control"
    LOCAL_GATEWAY = "local_gateway"   # this PC is the gateway; block locally


class AuthState(str, Enum):
    UNKNOWN = "unknown"
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"


@dataclass
class RouterInfo:
    """What we could learn about the box at the gateway address."""

    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    http_server: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)
    adapter: Optional[str] = None
    confidence: str = "low"           # high | medium | low
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Capabilities:
    """What this adapter can actually do against this router, right now."""

    can_block: bool = False
    method: BlockMethod = BlockMethod.NONE
    can_list_clients: bool = False
    requires_auth: bool = True
    auth_state: AuthState = AuthState.UNKNOWN
    # Shown verbatim in the UI when can_block is False.
    unsupported_reason: str = ""
    # Concrete things the user can do instead.
    alternatives: list[str] = field(default_factory=list)
    # What the adapter checked, so the verdict is auditable.
    probed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["method"] = self.method.value
        data["auth_state"] = self.auth_state.value
        return data


@dataclass
class ActionResult:
    ok: bool
    message: str
    method: BlockMethod = BlockMethod.NONE
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["method"] = self.method.value
        return data


# The message the app must show when router-level blocking is not available.
NO_BLOCKING_MESSAGE = (
    "Device discovery is available, but router-level blocking is not currently "
    "supported on this network."
)

# Generic, honest alternatives. Adapters may extend these with specifics.
GENERIC_ALTERNATIVES = [
    "Use the MAC filtering page in your router's own web interface, if it has one.",
    "Use the router's access-control list to deny the device by MAC or IP.",
    "Add a firewall rule on the router, or on a firewall appliance behind it.",
    "Put the network behind a managed access point that supports client blocking.",
    "Replace or supplement the ISP box with an OpenWrt-compatible router, which "
    "exposes a proper client-blocking API this app can drive.",
    "If this PC is acting as the gateway for the device, block it here with a "
    "Windows Firewall rule.",
    "As a last resort, change the Wi-Fi password to remove unknown devices, then "
    "reconnect only the ones you recognise.",
]


class RouterAdapter(abc.ABC):
    """Base class for router integrations.

    Subclasses are registered in registry.py. Adding support for a new router
    means adding one subclass; nothing in the scanner or the UI changes.
    """

    #: Short identifier used in the API and the UI.
    name: str = "generic"
    #: Human-readable vendor this adapter targets.
    vendor: str = "Unknown"

    def __init__(self, info: RouterInfo) -> None:
        self.info = info
        self.credentials: Optional[RouterCredentials] = None
        self._capabilities: Optional[Capabilities] = None

    # -------------------------------------------------------------- detection

    @classmethod
    @abc.abstractmethod
    def detect(cls, info: RouterInfo) -> int:
        """Confidence from 0-100 that this adapter matches the router.

        Called with whatever fingerprinting produced. Must not authenticate.
        """

    # ----------------------------------------------------------- capabilities

    @abc.abstractmethod
    def probe_capabilities(self) -> Capabilities:
        """Determine what is actually possible against this router.

        Must return can_block=False unless a mechanism has been confirmed to
        exist. Guessing here is what produces fake blocking features.
        """

    def capabilities(self, refresh: bool = False) -> Capabilities:
        if self._capabilities is None or refresh:
            self._capabilities = self.probe_capabilities()
        return self._capabilities

    # ------------------------------------------------------------------ auth

    def authenticate(self, credentials: RouterCredentials) -> ActionResult:
        """Log in with user-supplied credentials.

        Default: this router needs no login, or the adapter cannot log in.
        """
        return ActionResult(False, "This adapter does not support authentication.")

    def logout(self) -> None:
        self.credentials = None
        self._capabilities = None

    # --------------------------------------------------------------- clients

    def list_clients(self) -> dict[str, dict]:
        """DHCP leases or attached-client list, keyed by MAC. Best effort."""
        return {}

    # -------------------------------------------------------------- blocking

    def block(self, mac: str, ip: Optional[str] = None) -> ActionResult:
        caps = self.capabilities()
        if not caps.can_block:
            return ActionResult(False, caps.unsupported_reason or NO_BLOCKING_MESSAGE)
        return self._block(mac, ip)

    def unblock(self, mac: str, ip: Optional[str] = None) -> ActionResult:
        caps = self.capabilities()
        if not caps.can_block:
            return ActionResult(False, caps.unsupported_reason or NO_BLOCKING_MESSAGE)
        return self._unblock(mac, ip)

    def _block(self, mac: str, ip: Optional[str]) -> ActionResult:
        return ActionResult(False, NO_BLOCKING_MESSAGE)

    def _unblock(self, mac: str, ip: Optional[str]) -> ActionResult:
        return ActionResult(False, NO_BLOCKING_MESSAGE)

    def blocked_macs(self) -> list[str]:
        """MACs the router currently blocks, if the adapter can read them."""
        return []
