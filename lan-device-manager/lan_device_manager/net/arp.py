"""ARP / neighbour cache reading.

The kernel already knows the MAC of every host it has recently talked to. That
is the cheapest and most reliable source of MAC addresses on Windows, and it
needs no administrator rights and no raw sockets.

This module only *reads* the neighbour table. It never writes to it - the app
does not do ARP spoofing, and ARP is not used as a blocking mechanism anywhere.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

from .shell import powershell_json, as_list, run

# Entries that are not real hosts: broadcast and IPv4 multicast.
_BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

_ARP_LINE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\w+)"
)

_PS_NEIGHBORS = r"""
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Select-Object ifIndex, IPAddress, LinkLayerAddress, State |
  ConvertTo-Json -Depth 3 -Compress
"""


@dataclass
class Neighbor:
    ip: str
    mac: str
    state: str          # Reachable / Stale / Delay / Probe / Permanent / dynamic
    interface_index: Optional[int] = None

    @property
    def is_fresh(self) -> bool:
        return self.state.lower() in ("reachable", "permanent", "dynamic")


def _normalise(mac: str) -> str:
    return mac.replace("-", ":").lower()


def _is_real_host(ip: str, mac: str) -> bool:
    if mac in _BROADCAST_MACS:
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return False
    # 01:00:5e:.. is the IPv4 multicast MAC range.
    if mac.startswith("01:00:5e"):
        return False
    return True


def _from_powershell() -> list[Neighbor]:
    data = powershell_json(_PS_NEIGHBORS)
    found: list[Neighbor] = []
    for entry in as_list(data):
        if not isinstance(entry, dict):
            continue
        ip = entry.get("IPAddress") or ""
        mac = _normalise(entry.get("LinkLayerAddress") or "")
        state = str(entry.get("State") or "")
        if state.lower() in ("unreachable", "incomplete"):
            continue
        if not mac or not _is_real_host(ip, mac):
            continue
        found.append(Neighbor(ip=ip, mac=mac, state=state,
                              interface_index=entry.get("ifIndex")))
    return found


def _from_arp_command() -> list[Neighbor]:
    text = run(["arp", "-a"], timeout=15)
    found: list[Neighbor] = []
    for line in text.splitlines():
        match = _ARP_LINE.match(line)
        if not match:
            continue
        ip, mac, kind = match.group(1), _normalise(match.group(2)), match.group(3)
        if not _is_real_host(ip, mac):
            continue
        found.append(Neighbor(ip=ip, mac=mac, state=kind))
    return found


def read_table(network: Optional[ipaddress.IPv4Network] = None) -> dict[str, Neighbor]:
    """Read the neighbour cache, keyed by IP.

    Prefers Get-NetNeighbor (which reports entry state) and falls back to the
    classic `arp -a` parser. If a network is given, entries outside it are
    dropped so a scan of one subnet never reports hosts from another.
    """
    neighbors = _from_powershell() or _from_arp_command()

    table: dict[str, Neighbor] = {}
    for entry in neighbors:
        if network is not None:
            try:
                if ipaddress.IPv4Address(entry.ip) not in network:
                    continue
            except ValueError:
                continue
        # A fresher entry wins if the same IP shows up on several interfaces.
        existing = table.get(entry.ip)
        if existing is None or (entry.is_fresh and not existing.is_fresh):
            table[entry.ip] = entry
    return table


def lookup_mac(ip: str) -> Optional[str]:
    """MAC for a single IP, or None if it is not in the neighbour cache."""
    entry = read_table().get(ip)
    return entry.mac if entry else None


def is_locally_administered(mac: str) -> bool:
    """True if the MAC is randomised / locally assigned rather than a real OUI.

    Bit 1 of the first octet is the local bit. Modern phones set it when they
    use per-network private addresses, which means no vendor can be derived and
    the address will change on its own schedule.
    """
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10)


def is_multicast_mac(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b1)
