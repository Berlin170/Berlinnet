"""Active network interface, local address, subnet and gateway detection.

Nothing here is hardcoded: the gateway and prefix come from the routing table
and the adapter configuration, so the app works on 10.0.0.0/8, 172.16/12 or any
other private range just as well as on 192.168.1.0/24.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from .shell import powershell_json, as_list, run


@dataclass
class Interface:
    name: str                       # friendly name, e.g. "Ethernet"
    description: str                # adapter model, e.g. "Realtek Gaming 2.5GbE"
    index: int
    mac: str
    ipv4: str
    netmask: str
    prefix_length: int
    gateway: Optional[str]
    dhcp_server: Optional[str]
    dns_servers: list[str] = field(default_factory=list)
    is_primary: bool = False

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.ipv4}/{self.prefix_length}", strict=False)

    @property
    def cidr(self) -> str:
        return f"{self.network.network_address}/{self.prefix_length}"

    @property
    def host_count(self) -> int:
        if self.prefix_length < 31:
            return self.network.num_addresses - 2
        return self.network.num_addresses

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["cidr"] = self.cidr
        d["host_count"] = self.host_count
        return d


_PS_ADAPTERS = r"""
$cfgs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'
$adapters = Get-CimInstance Win32_NetworkAdapter
$out = foreach ($c in $cfgs) {
  $a = $adapters | Where-Object { $_.DeviceID -eq $c.Index } | Select-Object -First 1
  [pscustomobject]@{
    Name        = if ($a) { $a.NetConnectionID } else { $c.Description }
    Description = $c.Description
    Index       = $c.InterfaceIndex
    MAC         = $c.MACAddress
    IPs         = @($c.IPAddress)
    Masks       = @($c.IPSubnet)
    Gateways    = @($c.DefaultIPGateway)
    DHCPServer  = $c.DHCPServer
    DNS         = @($c.DNSServerSearchOrder)
  }
}
$out | ConvertTo-Json -Depth 4 -Compress
"""


def _local_ip_via_socket() -> Optional[str]:
    """Ask the OS which source address it would use to reach the internet.

    No packet is sent - connect() on a UDP socket only resolves the route.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("198.51.100.1", 9))  # TEST-NET-2, never routed anywhere
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _mask_to_prefix(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 24


def _is_ipv4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _normalise_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    return mac.replace("-", ":").lower()


def _from_powershell() -> list[Interface]:
    data = powershell_json(_PS_ADAPTERS)
    interfaces: list[Interface] = []
    for entry in as_list(data):
        if not isinstance(entry, dict):
            continue
        ips = [i for i in as_list(entry.get("IPs")) if _is_ipv4(i)]
        if not ips:
            continue
        ipv4 = ips[0]
        masks = [m for m in as_list(entry.get("Masks")) if _is_ipv4(m)]
        mask = masks[0] if masks else "255.255.255.0"
        gateways = [g for g in as_list(entry.get("Gateways")) if _is_ipv4(g)]
        dns = [d for d in as_list(entry.get("DNS")) if _is_ipv4(d)]
        dhcp = entry.get("DHCPServer")
        interfaces.append(
            Interface(
                name=entry.get("Name") or entry.get("Description") or "Unknown",
                description=entry.get("Description") or "",
                index=int(entry.get("Index") or 0),
                mac=_normalise_mac(entry.get("MAC")),
                ipv4=ipv4,
                netmask=mask,
                prefix_length=_mask_to_prefix(mask),
                gateway=gateways[0] if gateways else None,
                dhcp_server=dhcp if _is_ipv4(dhcp) else None,
                dns_servers=dns,
            )
        )
    return interfaces


def _gateway_from_route_table() -> dict[str, str]:
    """Map interface IP -> gateway by parsing the IPv4 routing table.

    Needed when an adapter reports only an IPv6 link-local default gateway but
    still has a working IPv4 default route, which is what some ISP ONTs produce.
    """
    text = run(["route", "print", "-4"], timeout=15)
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] in ("0.0.0.0", "default"):
            gateway, iface = parts[2], parts[3]
            if _is_ipv4(gateway) and _is_ipv4(iface):
                mapping.setdefault(iface, gateway)
    return mapping


def _from_ipconfig() -> list[Interface]:
    """Last-resort parser, used only if WMI and PowerShell are both unavailable."""
    text = run(["ipconfig", "/all"], timeout=15)
    interfaces: list[Interface] = []
    state: dict[str, Any] = {}

    def flush() -> None:
        if state.get("name") and state.get("ipv4"):
            mask = state.get("mask") or "255.255.255.0"
            interfaces.append(
                Interface(
                    name=state["name"],
                    description=state.get("description") or "",
                    index=0,
                    mac=_normalise_mac(state.get("mac")),
                    ipv4=state["ipv4"],
                    netmask=mask,
                    prefix_length=_mask_to_prefix(mask),
                    gateway=state.get("gateway"),
                    dhcp_server=state.get("dhcp"),
                    dns_servers=list(state.get("dns") or []),
                )
            )

    for line in text.splitlines():
        header = re.match(r"^(\S.*adapter\s+)(.+):\s*$", line, re.IGNORECASE)
        if header:
            flush()
            state = {"name": header.group(2).strip(), "dns": []}
            continue
        if ":" not in line:
            continue
        value = line.split(":", 1)[1].strip().replace("(Preferred)", "").strip()
        low = line.lower()
        if "description" in low:
            state["description"] = value
        elif "physical address" in low:
            state["mac"] = value
        elif "ipv4 address" in low and _is_ipv4(value):
            state["ipv4"] = value
        elif "subnet mask" in low and _is_ipv4(value):
            state["mask"] = value
        elif "default gateway" in low and _is_ipv4(value):
            state["gateway"] = value
        elif "dhcp server" in low and _is_ipv4(value):
            state["dhcp"] = value
        elif "dns servers" in low and _is_ipv4(value):
            state.setdefault("dns", []).append(value)
    flush()
    return interfaces


def list_interfaces() -> list[Interface]:
    """Every IPv4-enabled interface, with the primary one flagged."""
    interfaces = _from_powershell() or _from_ipconfig()

    missing = [i for i in interfaces if not i.gateway]
    if missing:
        route_map = _gateway_from_route_table()
        for iface in missing:
            iface.gateway = route_map.get(iface.ipv4)

    primary_ip = _local_ip_via_socket()
    chosen: Optional[Interface] = None
    if primary_ip:
        chosen = next((i for i in interfaces if i.ipv4 == primary_ip), None)
    if chosen is None:
        routable = [i for i in interfaces if i.gateway and not i.ipv4.startswith("169.254.")]
        chosen = routable[0] if routable else (interfaces[0] if interfaces else None)
    if chosen is not None:
        chosen.is_primary = True

    interfaces.sort(key=lambda i: (not i.is_primary, i.ipv4))
    return interfaces


def primary_interface() -> Optional[Interface]:
    for iface in list_interfaces():
        if iface.is_primary:
            return iface
    return None
