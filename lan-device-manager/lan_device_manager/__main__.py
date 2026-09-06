"""Entry point: python -m lan_device_manager"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser

import uvicorn

from . import config


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lan-device-manager",
        description="Discover and manage the devices on your local network.",
    )
    parser.add_argument("--host", default=config.HOST,
                        help="Bind address (default: 127.0.0.1, loopback only)")
    parser.add_argument("--port", type=int, default=config.PORT)
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser window on start")
    parser.add_argument("--scan", action="store_true",
                        help="Run a single scan, print the results and exit")
    parser.add_argument("--fetch-oui", action="store_true",
                        help="Download the full IEEE OUI registry for better vendor names")
    args = parser.parse_args(argv)

    if args.fetch_oui:
        return _fetch_oui()
    if args.scan:
        return _scan_once()

    if args.host not in ("127.0.0.1", "localhost"):
        print("Warning: binding off loopback exposes the API, which can drive router",
              "credentials, to your whole network. The API has no authentication.",
              sep="\n", file=sys.stderr)

    if not _port_free(args.host, args.port):
        print(f"Port {args.port} is already in use. Is the app already running?",
              file=sys.stderr)
        print(f"Try: http://{args.host}:{args.port}/", file=sys.stderr)
        return 1

    url = f"http://{args.host}:{args.port}/"
    print("BerlinNet - Berlin's Network Panel")
    print(f"  Interface : {url}")
    print(f"  Data      : {config.data_dir()}")
    print("  Press Ctrl+C to stop.\n")

    if not args.no_browser:
        threading.Thread(
            target=lambda: (time.sleep(1.2), webbrowser.open(url)),
            daemon=True,
        ).start()

    uvicorn.run("lan_device_manager.api:app", host=args.host, port=args.port,
                log_level="warning")
    return 0


IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _fetch_oui() -> int:
    """Download the IEEE OUI registry.

    This is the only outbound internet request the app ever makes, and it only
    happens when you ask for it on the command line.
    """
    import httpx

    from .net import oui

    print(f"Downloading {IEEE_OUI_URL}")
    # The IEEE server rejects unrecognised clients with a 418, so identify as a
    # normal browser would.
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"),
        "Accept": "text/csv,*/*",
    }
    try:
        with httpx.Client(timeout=180.0, follow_redirects=True, headers=headers) as client:
            response = client.get(IEEE_OUI_URL)
            response.raise_for_status()
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        print("The app still works with its built-in vendor table.", file=sys.stderr)
        return 1

    config.OUI_PATH.write_bytes(response.content)
    count = oui.reload()
    print(f"Saved to {config.OUI_PATH}")
    print(f"{count} vendor prefixes now available.")
    return 0


def _scan_once() -> int:
    """Headless scan, useful for checking discovery without the UI."""
    from .service import AppState

    state = AppState()
    iface = state.interface()
    if iface is None:
        print("No active IPv4 interface found.", file=sys.stderr)
        return 1

    print(f"Interface : {iface.name} ({iface.description})")
    print(f"Address   : {iface.ipv4}/{iface.prefix_length}")
    print(f"Subnet    : {iface.cidr}  ({iface.host_count} addresses)")
    print(f"Gateway   : {iface.gateway}")
    print(f"DHCP      : {iface.dhcp_server}")
    print("\nScanning...\n")

    summary = state.scan_now()
    devices = state.db.list_devices()

    row = "{:<15} {:<18} {:<20} {:<24} {:<18} {}"
    print(row.format("IP", "MAC", "NAME", "VENDOR", "CATEGORY", "STATUS"))
    print("-" * 118)
    for device in devices:
        print(row.format(
            device["ip"] or "-",
            device["mac"] or "-",
            (device["display_name"] or "-")[:19],
            (device["vendor"] or "-")[:23],
            (device["category"] or "-")[:17],
            "online" if device["online"] else "offline",
        ))

    print(f"\n{summary['found']} responding, {summary['new']} new.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
