"""Discovery orchestration.

One scan is:

  1. Read the neighbour cache for a free head start.
  2. ICMP-sweep the subnet, then TCP-probe whatever stayed quiet.
  3. Re-read the neighbour cache - the sweep has now populated it with MACs.
  4. Resolve hostnames for everything that answered.
  5. Look up vendors and classify.
  6. Optionally fold in nmap and router DHCP leases if either is available.

Steps 1-5 need no administrator rights. Step 6 is best-effort.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from . import arp, hostname as hostname_mod, oui, probe
from .classify import classify, link_type
from .interfaces import Interface, primary_interface


@dataclass
class DiscoveredDevice:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    hostname_source: Optional[str] = None
    vendor: str = oui.UNKNOWN
    category: str = "Unknown"
    category_confidence: str = "low"
    category_reason: str = ""
    open_ports: list[int] = field(default_factory=list)
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    link_type: str = "unknown"
    link_reason: str = ""
    responded_to: list[str] = field(default_factory=list)
    is_gateway: bool = False
    is_self: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "hostname_source": self.hostname_source,
            "vendor": self.vendor,
            "category": self.category,
            "category_confidence": self.category_confidence,
            "category_reason": self.category_reason,
            "open_ports": self.open_ports,
            "ttl": self.ttl,
            "latency_ms": self.latency_ms,
            "jitter_ms": self.jitter_ms,
            "link_type": self.link_type,
            "link_reason": self.link_reason,
            "responded_to": self.responded_to,
            "is_gateway": self.is_gateway,
            "is_self": self.is_self,
        }


@dataclass
class ScanProgress:
    running: bool = False
    phase: str = "idle"
    done: int = 0
    total: int = 0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    found: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        percent = int(self.done * 100 / self.total) if self.total else 0
        return {
            "running": self.running,
            "phase": self.phase,
            "done": self.done,
            "total": self.total,
            "percent": percent,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "found": self.found,
            "error": self.error,
        }


def _is_wireless_adapter(iface) -> bool:
    """Cheap check on the adapter description; Windows names Wi-Fi NICs plainly."""
    text = f"{iface.name} {iface.description}".lower()
    return any(word in text for word in ("wi-fi", "wifi", "wireless", "802.11", "wlan"))


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(cidr: str, timeout: float = 240.0) -> dict[str, dict]:
    """Optional enrichment via nmap if the user has it installed.

    Uses -sn (host discovery only, no port scan) so this stays a discovery tool.
    Returns {ip: {mac, vendor, hostname}}.
    """
    if not nmap_available():
        return {}
    try:
        proc = subprocess.run(
            ["nmap", "-sn", "-oX", "-", "--host-timeout", "10s", cidr],
            capture_output=True, text=True, timeout=timeout,
            creationflags=0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if proc.returncode != 0 or not proc.stdout:
        return {}
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return {}

    results: dict[str, dict] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        entry: dict = {}
        ip = None
        for address in host.findall("address"):
            kind = address.get("addrtype")
            if kind == "ipv4":
                ip = address.get("addr")
            elif kind == "mac":
                entry["mac"] = (address.get("addr") or "").lower()
                if address.get("vendor"):
                    entry["vendor"] = address.get("vendor")
        names = host.find("hostnames")
        if names is not None:
            first = names.find("hostname")
            if first is not None and first.get("name"):
                entry["hostname"] = first.get("name")
        if ip:
            results[ip] = entry
    return results


class Scanner:
    """Runs scans one at a time and exposes live progress."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.progress = ScanProgress()

    def _set(self, **kwargs) -> None:
        with self._lock:
            for key, value in kwargs.items():
                setattr(self.progress, key, value)

    def snapshot(self) -> dict:
        with self._lock:
            return self.progress.to_dict()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self.progress.running

    def scan(
        self,
        interface: Optional[Interface] = None,
        use_nmap: bool = True,
        resolve_hostnames: bool = True,
        dhcp_leases: Optional[dict[str, dict]] = None,
    ) -> list[DiscoveredDevice]:
        """Run one full discovery pass. Raises RuntimeError if already running."""
        with self._lock:
            if self.progress.running:
                raise RuntimeError("A scan is already in progress")
            self.progress = ScanProgress(
                running=True, phase="starting", started_at=time.time()
            )

        try:
            return self._scan(interface, use_nmap, resolve_hostnames, dhcp_leases or {})
        except Exception as exc:
            self._set(running=False, phase="failed", error=str(exc),
                      finished_at=time.time())
            raise
        finally:
            with self._lock:
                if self.progress.running:
                    self.progress.running = False
                    self.progress.phase = "done"
                    self.progress.finished_at = time.time()

    def _scan(
        self,
        interface: Optional[Interface],
        use_nmap: bool,
        resolve_hostnames: bool,
        dhcp_leases: dict[str, dict],
    ) -> list[DiscoveredDevice]:
        iface = interface or primary_interface()
        if iface is None:
            raise RuntimeError("No active IPv4 network interface was found")

        network = iface.network
        gateway = iface.gateway
        me = iface.ipv4

        # 1. Free head start from the neighbour cache.
        self._set(phase="reading ARP table")
        pre_arp = arp.read_table(network)

        # 2. Sweep.
        self._set(phase="pinging hosts")
        hosts = probe.enumerate_hosts(network)

        def on_progress(done: int, total: int) -> None:
            self._set(done=done, total=total)

        results = probe.sweep(hosts, do_tcp=True, progress=on_progress)
        self._set(phase="TCP discovery complete")

        # 3. The sweep has populated the neighbour cache; read it again.
        post_arp = arp.read_table(network)
        neighbours = {**pre_arp, **post_arp}

        alive: dict[str, DiscoveredDevice] = {}

        for ip, result in results.items():
            responded = []
            if result.icmp:
                responded.append("icmp")
            if result.open_ports:
                responded.append("tcp")
            in_arp = ip in post_arp
            if in_arp:
                responded.append("arp")
            if not (result.alive or in_arp):
                continue
            alive[ip] = DiscoveredDevice(
                ip=ip,
                mac=neighbours[ip].mac if ip in neighbours else None,
                open_ports=result.open_ports,
                ttl=result.ttl,
                latency_ms=result.latency_ms,
                responded_to=responded,
            )

        # Hosts known only from the neighbour cache (seen recently, quiet now).
        for ip, entry in neighbours.items():
            if ip not in alive and entry.is_fresh:
                alive[ip] = DiscoveredDevice(ip=ip, mac=entry.mac, responded_to=["arp"])

        # The gateway and this machine are always part of the picture.
        for special in (gateway, me):
            if special and special not in alive:
                entry = neighbours.get(special)
                alive[special] = DiscoveredDevice(
                    ip=special,
                    mac=entry.mac if entry else (iface.mac if special == me else None),
                    responded_to=["local"],
                )
        if me in alive and not alive[me].mac:
            alive[me].mac = iface.mac

        # Hosts that answered ICMP were never port-probed by the sweep, so they
        # arrive with no service data at all and classify as Unknown. Probing the
        # handful that are actually alive is cheap and is what makes categories
        # useful, so it is worth the extra pass.
        # Timing pass: a few extra pings per live host is cheap and is what
        # tells a cabled machine apart from someone else's phone on the Wi-Fi.
        timing_targets = [ip for ip in alive if ip not in (me, gateway)]
        if timing_targets:
            self._set(phase="measuring link quality", done=0, total=len(timing_targets))
            done = 0
            with ThreadPoolExecutor(max_workers=min(16, len(timing_targets))) as pool:
                for ip, (avg, jitter) in zip(timing_targets,
                                             pool.map(probe.link_probe, timing_targets)):
                    alive[ip].latency_ms = avg if avg is not None else alive[ip].latency_ms
                    alive[ip].jitter_ms = jitter
                    done += 1
                    self._set(done=done)

        unprobed = [ip for ip, d in alive.items() if not d.open_ports and ip != me]
        if unprobed:
            self._set(phase="probing services", done=0, total=len(unprobed))
            done = 0
            with ThreadPoolExecutor(max_workers=min(24, len(unprobed))) as pool:
                for ip, ports in zip(unprobed, pool.map(probe.tcp_probe, unprobed)):
                    if ports:
                        alive[ip].open_ports = ports
                        if "tcp" not in alive[ip].responded_to:
                            alive[ip].responded_to.append("tcp")
                    done += 1
                    self._set(done=done)

        # 4. Optional nmap enrichment.
        if use_nmap and nmap_available():
            self._set(phase="running nmap")
            for ip, extra in nmap_scan(iface.cidr).items():
                device = alive.setdefault(ip, DiscoveredDevice(ip=ip, responded_to=["nmap"]))
                if extra.get("mac") and not device.mac:
                    device.mac = extra["mac"]
                if extra.get("hostname") and not device.hostname:
                    device.hostname = extra["hostname"]
                    device.hostname_source = "nmap"
                if "nmap" not in device.responded_to:
                    device.responded_to.append("nmap")

        # 5. DHCP lease names from the router, when the adapter could read them.
        for mac, lease in dhcp_leases.items():
            ip = lease.get("ip")
            if not ip:
                continue
            device = alive.get(ip)
            if device is None:
                continue
            if lease.get("hostname") and not device.hostname:
                device.hostname = lease["hostname"]
                device.hostname_source = "dhcp"
            if not device.mac:
                device.mac = mac
            if "dhcp" not in device.responded_to:
                device.responded_to.append("dhcp")

        # 6. Hostnames.
        if resolve_hostnames:
            self._set(phase="resolving hostnames", done=0, total=len(alive))
            pending = [ip for ip, d in alive.items() if not d.hostname]
            for ip, (name, source) in hostname_mod.resolve_many(pending).items():
                if name:
                    alive[ip].hostname = name
                    alive[ip].hostname_source = source

        # 7. Vendor + classification.
        self._set(phase="identifying devices")
        # 802.3 is Ethernet; anything else (802.11, etc.) is not a cable.
        self_is_wired = "802.3" in (iface.description or "") or not _is_wireless_adapter(iface)
        for ip, device in alive.items():
            device.is_gateway = (ip == gateway)
            device.is_self = (ip == me)
            device.vendor = oui.lookup(device.mac or "")
            if device.is_self and device.vendor == oui.UNKNOWN and iface.description:
                # We know exactly what NIC this machine has - no need to guess.
                device.vendor = iface.description
            verdict = classify(
                is_gateway=device.is_gateway,
                is_self=device.is_self,
                hostname=device.hostname,
                vendor=device.vendor,
                open_ports=device.open_ports,
                ttl=device.ttl,
            )
            device.category = verdict.category
            device.category_confidence = verdict.confidence
            device.category_reason = verdict.reason

            device.link_type, device.link_reason = link_type(
                device.latency_ms, device.jitter_ms,
                is_self=device.is_self, is_gateway=device.is_gateway,
                self_is_wired=self_is_wired,
            )

        devices = sorted(alive.values(), key=lambda d: ipaddress.IPv4Address(d.ip))
        self._set(found=len(devices), phase="done")
        return devices
