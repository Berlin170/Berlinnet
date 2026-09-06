"""Application paths and tunable settings."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Per-user data directory. Everything the app stores lives here."""
    base = os.environ.get("LDM_DATA_DIR")
    if base:
        path = Path(base)
    elif os.name == "nt":
        path = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LanDeviceManager"
    else:
        path = Path.home() / ".local" / "share" / "lan-device-manager"
    path.mkdir(parents=True, exist_ok=True)
    return path


DB_PATH = data_dir() / "devices.db"
OUI_PATH = data_dir() / "oui.csv"          # optional full IEEE registry

# Discovery tuning
PING_TIMEOUT_MS = 700
PING_WORKERS = 96
TCP_TIMEOUT_S = 0.6
TCP_WORKERS = 200
HOSTNAME_WORKERS = 32
MAX_SCAN_HOSTS = 4096       # refuse to sweep anything larger than a /20

# Ports probed to find hosts that ignore ICMP, and to help classify them.
DISCOVERY_PORTS = [80, 443, 22, 445, 139, 135, 8080, 53, 3389, 62078, 5555, 7547, 9100, 554, 1883, 32400, 8009, 5000]

# Server
HOST = "127.0.0.1"
PORT = 8765
