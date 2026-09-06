"""Router detection and adapter selection.

Fingerprinting is read-only and unauthenticated: a TCP port sweep of the
gateway, the HTTP server banner, whatever the login page volunteers about its
own model, and the MAC vendor. That is enough to pick an adapter, and it is all
this app is willing to do before the user supplies credentials.
"""

from __future__ import annotations

import re
from typing import Optional, Type

import httpx

from ..net import oui, probe
from ..net.arp import read_table
from .base import RouterAdapter, RouterInfo
from .generic import GenericAdapter, LocalGatewayAdapter
from .huawei import HuaweiAdapter
from .openwrt import OpenWrtAdapter
from .tplink import TPLinkAdapter, ZTEAdapter

#: Every adapter the app knows about. Add new ones here.
ADAPTERS: list[Type[RouterAdapter]] = [
    HuaweiAdapter,
    OpenWrtAdapter,
    TPLinkAdapter,
    ZTEAdapter,
    GenericAdapter,
]

ALL_ADAPTERS: list[Type[RouterAdapter]] = ADAPTERS + [LocalGatewayAdapter]

ROUTER_PORTS = [80, 443, 8080, 8443, 22, 23, 53, 7547, 5555, 1900]

# Model strings routers leak in page titles or inline script.
_MODEL_PATTERNS = [
    re.compile(r"RES_TITLE_NAME\s*=\s*[\"\']([^\"\']+)[\"\']"),
    re.compile(r"<title>\s*([^<]{3,60}?)\s*</title>", re.IGNORECASE),
    re.compile(r"ProductName\s*=\s*[\"\']([^\"\']+)[\"\']"),
    re.compile(r"var\s+MODEL\s*=\s*[\"\']([^\"\']+)[\"\']"),
]

# Login pages worth reading a model string out of, per firmware family.
_FINGERPRINT_PATHS = ["/", "/cgi-bin/index2.asp", "/login.html", "/index.html",
                      "/cgi-bin/luci", "/webpages/login.html"]

_GENERIC_TITLES = {"login", "index", "home", "router", "untitled", "document"}


def _fetch_banner(ip: str) -> tuple[Optional[str], Optional[str], list[str]]:
    """HTTP server header and any model string, plus what was tried."""
    server: Optional[str] = None
    model: Optional[str] = None
    evidence: list[str] = []

    try:
        client = httpx.Client(base_url=f"http://{ip}", timeout=6.0,
                              follow_redirects=True,
                              headers={"User-Agent": "LAN-Device-Manager/1.0"})
    except httpx.HTTPError:
        return None, None, evidence

    with client:
        for path in _FINGERPRINT_PATHS:
            try:
                response = client.get(path)
            except httpx.HTTPError:
                continue
            if server is None and response.headers.get("server"):
                server = response.headers["server"]
                evidence.append(f"HTTP Server header: {server}")
            # 401 still tells us the path exists and gives us the banner.
            if response.status_code not in (200, 401):
                continue
            evidence.append(f"GET {path} -> {response.status_code}")
            if model is not None:
                continue
            try:
                body = response.content.decode("gb2312", errors="replace")
            except LookupError:
                body = response.text
            for pattern in _MODEL_PATTERNS:
                match = pattern.search(body)
                if not match:
                    continue
                candidate = match.group(1).strip()
                if candidate.lower() in _GENERIC_TITLES or len(candidate) < 3:
                    continue
                model = candidate
                evidence.append(f"Model string from {path}: {model}")
                break
    return server, model, evidence


def identify(gateway_ip: str) -> RouterInfo:
    """Fingerprint the box at the gateway address. Read-only, no auth."""
    info = RouterInfo(ip=gateway_ip)

    entry = read_table().get(gateway_ip)
    if entry:
        info.mac = entry.mac
        vendor = oui.lookup(entry.mac)
        if vendor not in (oui.UNKNOWN, oui.RANDOMISED):
            info.vendor = vendor
            info.evidence.append(f"MAC {entry.mac} belongs to {vendor}")
        elif vendor == oui.RANDOMISED:
            info.evidence.append(
                f"MAC {entry.mac} is a private/randomised address, so it identifies "
                f"no manufacturer"
            )

    info.open_ports = probe.tcp_probe(gateway_ip, ROUTER_PORTS)
    if info.open_ports:
        info.evidence.append(f"Open ports: {info.open_ports}")

    if 80 in info.open_ports or 443 in info.open_ports or 8080 in info.open_ports:
        server, model, evidence = _fetch_banner(gateway_ip)
        info.http_server = server
        info.model = model
        info.evidence.extend(evidence)

    # A model string is usually enough to name the vendor even when the MAC is not.
    if not info.vendor and info.model:
        lowered = info.model.lower()
        for needle, vendor in (("hg8", "Huawei"), ("echolife", "Huawei"), ("huawei", "Huawei"),
                               ("archer", "TP-Link"), ("tp-link", "TP-Link"),
                               ("zxhn", "ZTE"), ("zte", "ZTE"), ("openwrt", "OpenWrt")):
            if needle in lowered:
                info.vendor = vendor
                info.evidence.append(f"Vendor inferred from model string {info.model!r}")
                break

    best, score = select_adapter_class(info)
    info.adapter = best.name
    info.confidence = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return info


def select_adapter_class(info: RouterInfo) -> tuple[Type[RouterAdapter], int]:
    ranked = sorted(
        ((adapter, adapter.detect(info)) for adapter in ADAPTERS),
        key=lambda pair: pair[1],
        reverse=True,
    )
    return ranked[0]


def build_adapter(info: RouterInfo) -> RouterAdapter:
    adapter_class, _ = select_adapter_class(info)
    return adapter_class(info)


def adapter_by_name(name: str, info: RouterInfo) -> Optional[RouterAdapter]:
    for adapter in ALL_ADAPTERS:
        if adapter.name == name:
            return adapter(info)
    return None


def available_adapters() -> list[dict]:
    return [{"name": a.name, "vendor": a.vendor, "description": (a.__doc__ or "").strip().split("\n")[0]}
            for a in ALL_ADAPTERS]
