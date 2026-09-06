"""MAC address -> manufacturer lookup.

Uses a bundled prefix table by default, and merges the full IEEE registry over
it if the user has downloaded one. Randomised (locally administered) MACs are
reported as such rather than as "Unknown", because the distinction matters: a
randomised address has no manufacturer to look up and will change by itself.
"""

from __future__ import annotations

import csv
import threading
from typing import Optional

from .. import config
from .arp import is_locally_administered
from .oui_data import OUI_PREFIXES

RANDOMISED = "Randomised MAC (private address)"
UNKNOWN = "Unknown"

_lock = threading.Lock()
_registry: Optional[dict[str, str]] = None


def _load_ieee_registry() -> dict[str, str]:
    """Merge an IEEE oui.csv if present.

    Expected columns: Registry, Assignment, Organization Name, Organization Address.
    """
    path = config.OUI_PATH
    if not path.exists():
        return {}
    merged: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                assignment = (row.get("Assignment") or "").strip()
                org = (row.get("Organization Name") or "").strip()
                if len(assignment) != 6 or not org:
                    continue
                prefix = ":".join(assignment[i:i + 2] for i in (0, 2, 4)).lower()
                merged[prefix] = org
    except (OSError, csv.Error, UnicodeDecodeError):
        return {}
    return merged


def _registry_table() -> dict[str, str]:
    global _registry
    with _lock:
        if _registry is None:
            table = dict(OUI_PREFIXES)
            table.update(_load_ieee_registry())   # IEEE data wins where it overlaps
            _registry = table
        return _registry


def reload() -> int:
    """Drop the cache so a freshly downloaded registry is picked up."""
    global _registry
    with _lock:
        _registry = None
    return len(_registry_table())


def registry_size() -> int:
    return len(_registry_table())


def has_full_registry() -> bool:
    return config.OUI_PATH.exists()


def lookup(mac: str) -> str:
    """Vendor for a MAC address."""
    if not mac:
        return UNKNOWN
    mac = mac.replace("-", ":").lower()
    if is_locally_administered(mac):
        return RANDOMISED
    parts = mac.split(":")
    if len(parts) < 3:
        return UNKNOWN
    prefix = ":".join(parts[:3])
    return _registry_table().get(prefix, UNKNOWN)


def is_identifiable(mac: str) -> bool:
    """Whether the vendor could actually be determined."""
    return lookup(mac) not in (UNKNOWN, RANDOMISED)
