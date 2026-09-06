"""Application state and the background monitor.

This is the only place that knows about all four layers at once. It keeps them
in the order the architecture requires:

    Network Scanner -> Device Database -> Router Integration -> Blocking

The scanner never talks to the router; the router layer never writes device
records; blocking always goes through an adapter that has confirmed it can
actually block.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from .credentials import CredentialStore, RouterCredentials
from .db import Database, TRUST_BLOCKED, TRUST_UNKNOWN
from .net.interfaces import Interface, list_interfaces, primary_interface
from .net.scanner import Scanner, nmap_available
from .routers import registry
from .routers.base import ActionResult, BlockMethod, RouterAdapter, RouterInfo

DEFAULT_INTERVAL = 300          # seconds between automatic scans
MIN_INTERVAL = 60


class AppState:
    def __init__(self) -> None:
        self.db = Database()
        self.scanner = Scanner()
        self.credentials = CredentialStore(self.db)

        self._lock = threading.Lock()
        self._interface: Optional[Interface] = None
        # True once the user picks an interface by hand, which stops the app
        # from silently switching back to whichever one Windows prefers.
        self._interface_pinned = False
        self._router_info: Optional[RouterInfo] = None
        self._adapter: Optional[RouterAdapter] = None

        self.last_scan_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self.notifications: list[dict] = []

        self._monitor: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------- interface

    def interface(self, refresh: bool = False) -> Optional[Interface]:
        # Detection touches WMI and the routing table, so it runs outside the
        # lock; the lock only guards the assignment.
        if self._interface is None or refresh:
            detected = primary_interface()
            with self._lock:
                if detected is not None:
                    self._interface = detected
            return self._interface
        with self._lock:
            return self._interface

    def refresh_interface_if_stale(self) -> bool:
        """Re-detect the active interface and notice if the network moved.

        DHCP renewals, docking, and switching between Ethernet and Wi-Fi all
        change the subnet underneath us. Without this the app would keep
        sweeping a range it is no longer on and report everything as offline.
        Returns True if the network changed.
        """
        if self._interface_pinned:
            return False
        detected = primary_interface()
        if detected is None:
            return False
        with self._lock:
            current = self._interface
            moved = current is None or (
                detected.ipv4 != current.ipv4
                or detected.cidr != current.cidr
                or detected.gateway != current.gateway
                or detected.name != current.name
            )
            self._interface = detected
            if moved:
                # A different network means a different router.
                self._router_info = None
                self._adapter = None
        if moved and current is not None:
            self.db.log_event(
                None, "network_changed",
                f"Network changed: now {detected.name} {detected.cidr} "
                f"via {detected.gateway or 'no gateway'}",
            )
        return moved

    def interfaces(self) -> list[Interface]:
        return list_interfaces()

    def select_interface(self, name: str) -> Optional[Interface]:
        for iface in list_interfaces():
            if iface.name == name:
                with self._lock:
                    self._interface = iface
                    self._interface_pinned = True
                    # A different network means a different router.
                    self._router_info = None
                    self._adapter = None
                return iface
        return None

    # ---------------------------------------------------------------- router

    def router_info(self, refresh: bool = False) -> Optional[RouterInfo]:
        iface = self.interface()
        if iface is None or not iface.gateway:
            return None

        with self._lock:
            cached = self._router_info
            fresh = cached is not None and cached.ip == iface.gateway
            if fresh and not refresh:
                return cached

        # identify() port-scans the gateway and fetches pages, which takes
        # seconds. Doing that under the lock would stall every /api/overview
        # poll, so it runs outside and the result is published afterwards.
        info = registry.identify(iface.gateway)
        adapter = registry.build_adapter(info)

        with self._lock:
            # Another caller may have finished first; keep whichever matches
            # the current gateway rather than clobbering a live session.
            if (self._router_info is not None
                    and self._router_info.ip == iface.gateway and not refresh):
                return self._router_info
            self._router_info = info
            self._adapter = adapter
            return self._router_info

    def adapter(self) -> Optional[RouterAdapter]:
        self.router_info()
        return self._adapter

    def use_adapter(self, name: str) -> Optional[RouterAdapter]:
        """Override the auto-selected adapter, e.g. to use local gateway blocking."""
        info = self.router_info()
        if info is None:
            return None
        adapter = registry.adapter_by_name(name, info)
        if adapter is None:
            return None
        with self._lock:
            self._adapter = adapter
        return adapter

    def router_login(self, username: str, password: str, remember: bool = False) -> ActionResult:
        adapter = self.adapter()
        if adapter is None:
            return ActionResult(False, "No router has been detected on this network.")
        creds = RouterCredentials(username, password)
        result = adapter.authenticate(creds)
        if result.ok:
            self.credentials.set(adapter.info.ip, username, password, remember=remember)
            # The message is safe to log; the password is not part of it.
            self.db.log_event(None, "router_login",
                              f"Signed in to the router at {adapter.info.ip}")
        else:
            self.db.log_event(None, "router_login_failed",
                              f"Router sign-in failed at {adapter.info.ip}")
        return result

    def router_logout(self) -> None:
        adapter = self.adapter()
        if adapter is not None:
            adapter.logout()

    def try_saved_login(self) -> Optional[ActionResult]:
        """Sign in automatically if the user chose to save credentials."""
        adapter = self.adapter()
        if adapter is None:
            return None
        saved = self.credentials.get(adapter.info.ip)
        if saved is None:
            return None
        return adapter.authenticate(saved)

    # ----------------------------------------------------------------- scans

    def scan_now(self) -> dict:
        """Run one scan and merge it into the database."""
        # Cheap compared with the sweep, and it keeps a long-running app
        # pointed at the network it is actually on.
        self.refresh_interface_if_stale()
        iface = self.interface()
        if iface is None:
            self.last_error = "No active IPv4 network interface was found."
            raise RuntimeError(self.last_error)

        leases: dict[str, dict] = {}
        adapter = self.adapter()
        if adapter is not None:
            try:
                caps = adapter.capabilities()
                if caps.can_list_clients:
                    leases = adapter.list_clients()
            except Exception:
                leases = {}      # router enrichment is never allowed to fail a scan

        use_nmap = bool(self.db.get_setting("use_nmap", True))
        devices = self.scanner.scan(interface=iface, use_nmap=use_nmap, dhcp_leases=leases)
        changes = self.db.upsert_scan_results(devices)

        self.last_scan_at = time.time()
        self.last_error = None

        for record in changes["new"]:
            self.push_notification(
                "new_device",
                f"New device detected: {record['ip']} - {record.get('mac') or 'MAC unknown'}",
                key=record["key"],
            )

        return {
            "found": len(devices),
            "new": len(changes["new"]),
            "returned": len(changes["returned"]),
            "at": self.last_scan_at,
        }

    # --------------------------------------------------------- notifications

    def push_notification(self, kind: str, message: str, key: Optional[str] = None) -> None:
        with self._lock:
            self.notifications.append(
                {"kind": kind, "message": message, "key": key, "at": time.time()}
            )
            del self.notifications[:-100]

    def drain_notifications(self) -> list[dict]:
        with self._lock:
            pending, self.notifications = self.notifications, []
        return pending

    # -------------------------------------------------------------- blocking

    def block_device(self, key: str) -> ActionResult:
        device = self.db.get_device(key)
        if device is None:
            return ActionResult(False, "That device is not in the database.")
        if device["is_self"]:
            return ActionResult(False, "This is the computer running the app; it will not block itself.")
        if device["is_gateway"]:
            return ActionResult(False, "This is the router itself. Blocking it would cut the whole network off.")

        adapter = self.adapter()
        if adapter is None:
            return ActionResult(False, "No router has been detected on this network.")

        caps = adapter.capabilities()
        if not caps.can_block:
            return ActionResult(False, caps.unsupported_reason)

        mac = device.get("mac")
        if not mac and caps.method != BlockMethod.LOCAL_GATEWAY:
            return ActionResult(False, "This device has no known MAC address to block.")

        result = adapter.block(mac or "", device.get("ip"))
        if result.ok:
            self.db.update_device(key, blocked=1, trust=TRUST_BLOCKED,
                                  block_method=result.method.value)
            self.db.log_event(key, "blocked", result.message)
        return result

    def unblock_device(self, key: str) -> ActionResult:
        device = self.db.get_device(key)
        if device is None:
            return ActionResult(False, "That device is not in the database.")

        adapter = self.adapter()
        if adapter is None:
            return ActionResult(False, "No router has been detected on this network.")

        caps = adapter.capabilities()
        if not caps.can_block:
            return ActionResult(False, caps.unsupported_reason)

        result = adapter.unblock(device.get("mac") or "", device.get("ip"))
        if result.ok:
            self.db.update_device(key, blocked=0, trust=TRUST_UNKNOWN, block_method=None)
            self.db.log_event(key, "unblocked", result.message)
        return result

    # -------------------------------------------------------------- monitor

    @property
    def interval(self) -> int:
        return max(MIN_INTERVAL, int(self.db.get_setting("scan_interval", DEFAULT_INTERVAL)))

    def set_interval(self, seconds: int) -> int:
        value = max(MIN_INTERVAL, int(seconds))
        self.db.set_setting("scan_interval", value)
        return value

    @property
    def monitoring(self) -> bool:
        return self._monitor is not None and self._monitor.is_alive()

    def start_monitor(self) -> None:
        if self.monitoring:
            return
        self._stop.clear()
        self._monitor = threading.Thread(target=self._monitor_loop, name="ldm-monitor",
                                         daemon=True)
        self._monitor.start()
        self.db.set_setting("monitor_enabled", True)

    def stop_monitor(self) -> None:
        self._stop.set()
        self.db.set_setting("monitor_enabled", False)

    def _monitor_loop(self) -> None:
        # Give the UI a moment to come up before the first automatic scan.
        if self._stop.wait(3):
            return
        while not self._stop.is_set():
            try:
                if not self.scanner.is_running:
                    self.scan_now()
            except Exception as exc:
                self.last_error = str(exc)
            if self._stop.wait(self.interval):
                return

    # --------------------------------------------------------------- summary

    def overview(self) -> dict[str, Any]:
        iface = self.interface()
        info = self.router_info()
        adapter = self.adapter()
        caps = None
        if adapter is not None:
            try:
                caps = adapter.capabilities().to_dict()
            except Exception as exc:
                self.last_error = str(exc)
        return {
            "interface": iface.to_dict() if iface else None,
            "router": info.to_dict() if info else None,
            "capabilities": caps,
            "stats": self.db.stats(),
            "scan": self.scanner.snapshot(),
            "last_scan_at": self.last_scan_at,
            "last_error": self.last_error,
            "monitoring": self.monitoring,
            "interval": self.interval,
            "nmap_available": nmap_available(),
            "credentials_securable": self.credentials is not None,
        }
