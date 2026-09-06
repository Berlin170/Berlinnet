"""Thin wrappers around Windows command-line tools.

Everything here is read-only. Commands are launched without a console window so
the app can run from a shortcut without flashing terminals.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

_NO_WINDOW = 0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def run(args: list[str], timeout: float = 20.0) -> str:
    """Run a command and return stdout, or '' on any failure."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout or ""


def powershell_json(script: str, timeout: float = 25.0) -> Any:
    """Run a PowerShell snippet that emits JSON and return the parsed result.

    Returns None if PowerShell is unavailable or the output is not valid JSON,
    so every caller has to have a non-PowerShell fallback path.
    """
    out = run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def as_list(value: Any) -> list:
    """PowerShell's ConvertTo-Json collapses single-element arrays to objects."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
