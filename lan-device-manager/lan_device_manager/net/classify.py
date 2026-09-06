"""Device type inference.

Every rule here is a heuristic, and the result carries a confidence so the UI
can say "probably a phone" rather than asserting it. Signals used, in rough
order of reliability: role on the network, open ports, hostname, vendor, TTL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Categories the UI knows how to badge.
ROUTER = "Router / Gateway"
COMPUTER = "Computer"
PHONE = "Phone / Tablet"
TV = "TV / Streaming"
PRINTER = "Printer"
NAS = "NAS / Server"
IOT = "IoT / Smart home"
CAMERA = "Camera"
CONSOLE = "Games console"
VIRTUAL = "Virtual machine"
UNKNOWN = "Unknown"


@dataclass
class Classification:
    category: str
    confidence: str          # high | medium | low
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"category": self.category, "confidence": self.confidence, "reason": self.reason}


_HOSTNAME_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi", "poco",
      "huawei-", "honor", "oppo", "vivo", "mi-phone", "phone"), PHONE),
    (("macbook", "imac", "desktop", "laptop", "pc-", "-pc", "workstation", "win-"), COMPUTER),
    (("chromecast", "roku", "firetv", "shield", "appletv", "apple-tv", "bravia",
      "samsungtv", "lgtv", "webos", "smart-tv", "tv-"), TV),
    (("printer", "hpprint", "brother", "epson", "canon", "officejet", "deskjet",
      "laserjet", "envy"), PRINTER),
    (("nas", "synology", "diskstation", "qnap", "truenas", "freenas", "unraid",
      "server", "srv-"), NAS),
    (("echo", "alexa", "nest", "hue", "shelly", "tasmota", "esp-", "esp32", "esp8266",
      "sonoff", "tuya", "smartlife", "thermostat", "doorbell", "plug", "bulb"), IOT),
    (("cam", "ipcam", "camera", "hikvision", "dahua", "reolink", "wyze"), CAMERA),
    (("xbox", "playstation", "ps4", "ps5", "nintendo", "switch"), CONSOLE),
    (("router", "gateway", "modem", "ont", "openwrt", "dd-wrt", "unifi", "mikrotik"), ROUTER),
]

_VENDOR_HINTS: list[tuple[tuple[str, ...], str, str]] = [
    (("raspberry pi",), IOT, "medium"),
    (("espressif", "tuya", "sonoff", "shelly", "philips hue", "microchip"), IOT, "high"),
    (("hikvision", "dahua", "zhejiang dahua", "reolink"), CAMERA, "high"),
    (("brother", "epson", "canon", "lexmark"), PRINTER, "medium"),
    (("synology", "qnap"), NAS, "high"),
    (("nintendo", "sony interactive"), CONSOLE, "high"),
    (("roku",), TV, "high"),
    (("vmware", "virtualbox", "xen", "parallels", "realtek/qemu", "microsoft (hyper-v)"), VIRTUAL, "high"),
    (("intel", "realtek", "dell", "hp", "lenovo", "asus", "acer", "foxconn", "azurewave", "liteon"),
     COMPUTER, "low"),
    (("apple", "samsung", "xiaomi", "oneplus", "oppo", "vivo", "motorola", "nokia", "lg"),
     PHONE, "low"),
    (("huawei", "zte", "tp-link", "netgear", "d-link", "tenda", "ubiquiti", "cisco-linksys"),
     ROUTER, "low"),
]

# Ports that say something specific about what a host is.
_PORT_HINTS: list[tuple[set[int], str, str]] = [
    ({9100, 631, 515}, PRINTER, "high"),
    ({554, 8554, 37777}, CAMERA, "high"),
    ({32400, 8096, 5000, 5001, 548}, NAS, "medium"),
    ({8009, 8008, 1900, 7000}, TV, "medium"),
    ({3389, 445, 139, 135}, COMPUTER, "medium"),
    ({62078}, PHONE, "high"),          # iOS lockdown service
    ({1883, 8883}, IOT, "medium"),     # MQTT
    ({7547, 53}, ROUTER, "medium"),    # TR-069 CWMP + DNS forwarder
]


WIRED = "wired"
WIRELESS = "wireless"
LINK_UNKNOWN = "unknown"


def link_type(
    average_ms: Optional[float],
    jitter_ms: Optional[float],
    *,
    is_self: bool = False,
    is_gateway: bool = False,
    self_is_wired: bool = True,
) -> tuple[str, str]:
    """Guess whether a host is on cable or Wi-Fi, from timing alone.

    Useful when the freeloaders are all on the router's Wi-Fi and you are on
    Ethernet: it separates "my equipment" from "someone else's phone" without
    needing any cooperation from the device.

    Thresholds are deliberately conservative, with a band in the middle that
    reports unknown rather than guessing.
    """
    if is_self:
        return (WIRED if self_is_wired else WIRELESS), "This computer"
    if is_gateway:
        return WIRED, "The router itself"
    if average_ms is None:
        return LINK_UNKNOWN, "Host did not answer ping"

    # A cable is fast and boring; Wi-Fi power saving is neither. The wired
    # threshold is deliberately tight: switched Ethernet answers in well under a
    # millisecond, while Wi-Fi close to the access point can manage 2-5ms. Being
    # loose here would wrongly clear a wireless device as "one of mine", which is
    # the expensive mistake, so anything in between is reported as unknown.
    if average_ms < 1.5 and (jitter_ms or 0) < 3:
        return WIRED, f"{average_ms:.1f}ms round trip, steady"
    if average_ms >= 15 or (jitter_ms or 0) >= 25:
        return WIRELESS, f"{average_ms:.0f}ms round trip, {jitter_ms:.0f}ms spread"
    return LINK_UNKNOWN, f"{average_ms:.1f}ms round trip, between wired and Wi-Fi"


def _ttl_family(ttl: Optional[int]) -> Optional[str]:
    """Initial TTL leaks the OS family: 64 = Linux/Android/Apple, 128 = Windows."""
    if ttl is None:
        return None
    if 100 < ttl <= 128:
        return "windows"
    if 0 < ttl <= 64:
        return "unix"
    if 128 < ttl <= 255:
        return "network-device"
    return None


def classify(
    *,
    is_gateway: bool = False,
    is_self: bool = False,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Optional[list[int]] = None,
    ttl: Optional[int] = None,
) -> Classification:
    ports = set(open_ports or [])
    host = (hostname or "").lower()
    vend = (vendor or "").lower()

    if is_gateway:
        return Classification(ROUTER, "high", "This address is the default gateway")
    if is_self:
        return Classification(COMPUTER, "high", "This computer")

    for needles, category in _HOSTNAME_HINTS:
        for needle in needles:
            if needle in host:
                return Classification(category, "high", f"Hostname contains {needle!r}")

    for port_set, category, confidence in _PORT_HINTS:
        matched = ports & port_set
        if matched:
            listed = ", ".join(str(p) for p in sorted(matched))
            return Classification(category, confidence, f"Listening on port {listed}")

    for needles, category, confidence in _VENDOR_HINTS:
        for needle in needles:
            if needle in vend:
                return Classification(category, confidence, f"MAC vendor is {vendor}")

    family = _ttl_family(ttl)
    if family == "windows":
        return Classification(COMPUTER, "low", "TTL suggests a Windows host")
    if family == "network-device":
        return Classification(ROUTER, "low", "TTL suggests a network appliance")
    if family == "unix":
        return Classification(UNKNOWN, "low", "TTL suggests Linux, Android or Apple")

    return Classification(UNKNOWN, "low", "Not enough signals to categorise")
