"""Hostname resolution for LAN hosts.

Three independent sources, tried cheapest first:

  1. Reverse DNS  - works when the router registers DHCP names in its resolver.
  2. NetBIOS      - Windows machines, printers, NAS boxes.
  3. mDNS         - Apple devices, Android, Chromecasts, most modern IoT.

Consumer ONTs like the one this was written against run a DNS forwarder that
does not serve PTR records for the LAN, so in practice mDNS does most of the
work. All three are ordinary queries; none of them require privileges.
"""

from __future__ import annotations

import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .. import config
from .shell import run

_NBT_NAME = re.compile(r"^\s*(\S+)\s+<(\d\d)>\s+UNIQUE\s+Registered", re.IGNORECASE)

_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT = 5353


def reverse_dns(ip: str, timeout: float = 1.5) -> Optional[str]:
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(original)
    # A resolver that answers every PTR with the same name is not useful.
    if not name or name == ip:
        return None
    return name.split(".")[0] if name.endswith(".local") else name


def netbios_name(ip: str) -> Optional[str]:
    """Query the NetBIOS name table. Only Windows-family hosts answer."""
    out = run(["nbtstat", "-A", ip], timeout=6)
    if "Host not found" in out or not out.strip():
        return None
    for line in out.splitlines():
        match = _NBT_NAME.match(line)
        if not match:
            continue
        name, suffix = match.group(1), match.group(2)
        # <00> is the workstation service; <20> is the file server service.
        if suffix in ("00", "20") and not name.startswith("__"):
            return name
    return None


def _build_ptr_query(ip: str) -> bytes:
    """A DNS PTR query for <reversed-ip>.in-addr.arpa with a zero transaction id."""
    labels = ip.split(".")[::-1] + ["in-addr", "arpa"]
    question = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + question + struct.pack(">HH", 12, 1)  # QTYPE=PTR, QCLASS=IN


def _skip_name(data: bytes, offset: int) -> int:
    """Advance past a DNS name and return the offset of whatever follows.

    A compression pointer is two bytes and terminates the name; an uncompressed
    name ends at its zero-length label.
    """
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += length + 1
    return offset


def _decode_name(data: bytes, offset: int) -> Optional[str]:
    """Decode a DNS name, following at most a few compression pointers."""
    parts: list[str] = []
    hops = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:                      # compression pointer
            if offset + 1 >= len(data) or hops > 5:
                return None
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            continue
        offset += 1
        if offset + length > len(data):
            return None
        parts.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(parts) if parts else None


def mdns_name(ip: str, timeout: float = 1.2) -> Optional[str]:
    """Reverse mDNS lookup.

    The query goes to the multicast group, but we also unicast it straight at
    the host, which is what actually gets an answer from devices that only
    listen for directed queries.
    """
    query = _build_ptr_query(ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        try:
            sock.sendto(query, (ip, _MDNS_PORT))
            sock.sendto(query, (_MDNS_GROUP, _MDNS_PORT))
        except OSError:
            return None

        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                return None
            if addr[0] != ip or len(data) < 12:
                continue
            answer_count = struct.unpack(">H", data[6:8])[0]
            if answer_count == 0:
                continue

            offset = 12
            question_count = struct.unpack(">H", data[4:6])[0]
            for _ in range(question_count):
                offset = _skip_name(data, offset)
                offset += 4                     # QTYPE + QCLASS

            # Responders commonly bundle several records and the PTR is not
            # always first, so walk them and take the first PTR rather than
            # decoding whatever RDATA happens to lead.
            for _ in range(answer_count):
                offset = _skip_name(data, offset)
                if offset + 10 > len(data):
                    return None
                rtype, _rclass, _ttl, rdlength = struct.unpack(
                    ">HHIH", data[offset:offset + 10]
                )
                offset += 10
                if rtype == 12:                 # PTR
                    name = _decode_name(data, offset)
                    if name:
                        return name[:-6] if name.endswith(".local") else name
                offset += rdlength
            return None
    finally:
        sock.close()


_SSDP_GROUP = "239.255.255.250"
_SSDP_PORT = 1900
_LOCATION_RE = re.compile(rb"^location:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_FRIENDLY_RE = re.compile(r"<friendlyName>\s*(.*?)\s*</friendlyName>", re.IGNORECASE | re.DOTALL)


def _friendly_name(location: str, timeout: float = 1.5) -> Optional[str]:
    """Fetch a UPnP device-description URL and read its <friendlyName>."""
    import urllib.request

    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return None
    match = _FRIENDLY_RE.search(body)
    if not match:
        return None
    name = re.sub(r"\s+", " ", match.group(1)).strip()
    # Some devices pad the field with the model or a URL - keep it short.
    return name[:48] or None


def ssdp_names(timeout: float = 2.0) -> dict[str, str]:
    """One SSDP sweep -> {ip: friendlyName} for every UPnP device that answers.

    Smart TVs, consoles, speakers, printers and NAS boxes advertise a
    <friendlyName> over UPnP even when they ignore mDNS and NetBIOS, so this is
    often the only automatic source of a real name for them. Phones generally do
    not run a UPnP server, so it will not name those - nothing here can.
    """
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {_SSDP_GROUP}:{_SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    locations: dict[str, str] = {}     # ip -> first LOCATION seen
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(request, (_SSDP_GROUP, _SSDP_PORT))
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            if ip in locations:
                continue
            m = _LOCATION_RE.search(data)
            if m:
                locations[ip] = m.group(1).decode("ascii", errors="replace")
    finally:
        sock.close()

    if not locations:
        return {}
    # Fetch descriptions in parallel; each is a small HTTP GET on the LAN.
    workers = min(config.HOSTNAME_WORKERS, len(locations))
    names: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, name in zip(locations, pool.map(_friendly_name, locations.values())):
            if name:
                names[ip] = name
    return names


def resolve(ip: str) -> tuple[Optional[str], Optional[str]]:
    """Best hostname for an IP, plus which method produced it."""
    for method, fn in (("mdns", mdns_name), ("dns", reverse_dns), ("netbios", netbios_name)):
        try:
            name = fn(ip)
        except Exception:
            name = None
        if name:
            return name.strip(), method
    return None, None


def resolve_many(ips: list[str]) -> dict[str, tuple[Optional[str], Optional[str]]]:
    if not ips:
        return {}
    # One SSDP sweep for the whole subnet, then per-host mDNS/DNS/NetBIOS. The
    # active probes win when they find a name; SSDP fills in the media and IoT
    # devices that answer nothing else.
    try:
        ssdp = ssdp_names()
    except Exception:
        ssdp = {}
    workers = min(config.HOSTNAME_WORKERS, len(ips))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        resolved = dict(zip(ips, pool.map(resolve, ips)))
    for ip in ips:
        name, source = resolved.get(ip, (None, None))
        if not name and ip in ssdp:
            resolved[ip] = (ssdp[ip], "ssdp")
    return resolved
