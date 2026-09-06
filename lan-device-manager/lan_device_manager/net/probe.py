"""Host liveness probes: ICMP ping and TCP connect.

Both run in thread pools. Neither needs administrator rights - ping.exe is used
rather than raw ICMP sockets precisely so the app works as a normal user, and
TCP discovery is an ordinary connect() that any process may perform.

The TCP sweep matters more than it looks: phones on battery saver and Windows
machines with the default firewall silently drop ICMP, so a ping-only scan
misses them. A host that refuses a connection is still a host that answered.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .. import config
from .shell import run

_PING_OK_MARKERS = ("ttl=", "ttl =")


@dataclass
class ProbeResult:
    ip: str
    icmp: bool = False
    open_ports: list[int] = field(default_factory=list)
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None

    @property
    def alive(self) -> bool:
        return self.icmp or bool(self.open_ports)


def ping(ip: str, timeout_ms: int = config.PING_TIMEOUT_MS) -> ProbeResult:
    """Single ICMP echo via ping.exe. Also captures TTL, which hints at OS."""
    out = run(["ping", "-n", "1", "-w", str(timeout_ms), ip],
              timeout=(timeout_ms / 1000.0) + 4).lower()
    result = ProbeResult(ip=ip)
    if not any(marker in out for marker in _PING_OK_MARKERS):
        return result
    # A reply from a *different* host ("Destination host unreachable") also
    # contains no TTL for the target, so requiring TTL keeps this honest.
    result.icmp = True
    for token in out.replace("<", " ").split():
        if token.startswith("ttl="):
            try:
                result.ttl = int(token.split("=", 1)[1])
            except ValueError:
                pass
        elif token.startswith("time="):
            try:
                result.latency_ms = float(token.split("=", 1)[1].rstrip("ms"))
            except ValueError:
                pass
    return result


def link_probe(ip: str, samples: int = 4) -> tuple[Optional[float], Optional[float]]:
    """Average round-trip and jitter over a few pings.

    This is what separates a wired client from a wireless one. On a switched
    LAN a cabled host answers in well under a millisecond and barely varies.
    A Wi-Fi client with power saving parks its radio between beacons, so replies
    land tens of milliseconds later and swing wildly from ping to ping. The
    spread matters as much as the average - a distant, weak-signal client is
    erratic in a way a cable never is.

    Returns (average_ms, jitter_ms), or (None, None) if the host stayed silent.
    """
    timings: list[float] = []
    for _ in range(max(1, samples)):
        result = ping(ip)
        if result.icmp and result.latency_ms is not None:
            timings.append(result.latency_ms)
        elif result.icmp:
            timings.append(0.0)        # Windows prints "<1ms" as no time= value
    if not timings:
        return None, None
    average = sum(timings) / len(timings)
    jitter = max(timings) - min(timings)
    return average, jitter


def tcp_port_open(ip: str, port: int, timeout: float = config.TCP_TIMEOUT_S) -> bool:
    """True if a TCP handshake completes. A refusal means the host exists but
    is not listening, which we treat separately in tcp_probe()."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def tcp_probe(ip: str, ports: Optional[Iterable[int]] = None) -> list[int]:
    """Return the subset of ports that accepted a connection."""
    ports = list(ports if ports is not None else config.DISCOVERY_PORTS)
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(len(ports), 16)) as pool:
        for port, is_open in zip(ports, pool.map(lambda p: tcp_port_open(ip, p), ports)):
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def sweep(
    hosts: list[str],
    do_tcp: bool = True,
    progress: Optional[Callable[[int, int], None]] = None,
) -> dict[str, ProbeResult]:
    """Ping every host, then TCP-probe the ones that stayed silent.

    Two passes rather than one keeps the TCP work proportional to the number of
    quiet hosts instead of the size of the subnet.
    """
    results: dict[str, ProbeResult] = {}
    total = len(hosts)
    done = 0

    with ThreadPoolExecutor(max_workers=config.PING_WORKERS) as pool:
        for result in pool.map(ping, hosts):
            results[result.ip] = result
            done += 1
            if progress and done % 16 == 0:
                progress(done, total)

    if progress:
        progress(total, total)

    if not do_tcp:
        return results

    quiet = [ip for ip, r in results.items() if not r.icmp]
    if not quiet:
        return results

    def probe_one(ip: str) -> tuple[str, list[int]]:
        return ip, tcp_probe(ip)

    workers = max(1, min(config.TCP_WORKERS // max(len(config.DISCOVERY_PORTS), 1), len(quiet)))
    with ThreadPoolExecutor(max_workers=max(workers, 8)) as pool:
        for ip, ports in pool.map(probe_one, quiet):
            results[ip].open_ports = ports

    return results


def enumerate_hosts(network: ipaddress.IPv4Network, skip: Optional[set[str]] = None) -> list[str]:
    """Host addresses in a network, with a hard cap on how large a sweep may be."""
    skip = skip or set()
    hosts = [str(ip) for ip in network.hosts() if str(ip) not in skip]
    if len(hosts) > config.MAX_SCAN_HOSTS:
        raise ValueError(
            f"Refusing to scan {len(hosts)} addresses ({network}). "
            f"The limit is {config.MAX_SCAN_HOSTS}; scan a smaller subnet instead."
        )
    return hosts
