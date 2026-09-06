"""Router credential storage.

Passwords are encrypted with the Windows Data Protection API (DPAPI) before
they touch the disk. The key is derived by Windows from the logged-in user
account, so the stored blob is useless to another user and useless if the file
is copied to another machine.

Rules this module exists to enforce:
  * no plaintext password is ever written to disk;
  * no password is ever written to a log or returned by the API;
  * saving credentials is opt-in - the app works without it, prompting per session.

On a non-Windows host DPAPI does not exist, and rather than fall back to a
fake-secure XOR scheme this module refuses to persist at all. Session-only
credentials still work everywhere.
"""

from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

IS_WINDOWS = os.name == "nt"


@dataclass
class RouterCredentials:
    username: str
    password: str

    def redacted(self) -> dict:
        """Safe to log or return over the API."""
        return {"username": self.username, "password": "********" if self.password else ""}


if IS_WINDOWS:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    # Declaring these matters on 64-bit: without them ctypes assumes int-sized
    # returns and arguments, which truncates pointers.
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), wintypes.LPCWSTR, ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _to_blob(data: bytes) -> tuple[_DATA_BLOB, ctypes.Array]:
        """Wrap bytes in a DATA_BLOB.

        The backing buffer is returned alongside the blob and the caller must
        hold on to it: the blob only stores a raw pointer into it, so if the
        buffer is collected the blob is left dangling.
        """
        buffer = ctypes.create_string_buffer(data, len(data))
        blob = _DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        return blob, buffer

    def _from_blob(blob: _DATA_BLOB) -> bytes:
        """Copy a blob DPAPI allocated for us, then release it."""
        if not blob.pbData:
            return b""
        out = ctypes.string_at(blob.pbData, int(blob.cbData))
        # Zero the API's copy before handing it back to the allocator so the
        # plaintext does not linger in freed heap memory.
        ctypes.memset(blob.pbData, 0, int(blob.cbData))
        _kernel32.LocalFree(blob.pbData)
        return out


def is_available() -> bool:
    """Whether credentials can be stored securely on this machine."""
    return IS_WINDOWS


def encrypt(plaintext: str, description: str = "LAN Device Manager") -> Optional[str]:
    """DPAPI-encrypt a string and return it base64-encoded, or None if unavailable."""
    if not IS_WINDOWS or plaintext is None:
        return None
    # `backing` is unused by name but must stay referenced for the duration of
    # the call - it owns the memory data_in points at.
    data_in, backing = _to_blob(plaintext.encode("utf-8"))
    data_out = _DATA_BLOB()
    try:
        ok = _crypt32.CryptProtectData(
            ctypes.byref(data_in),
            description,
            None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(data_out),
        )
        if not ok:
            return None
        return base64.b64encode(_from_blob(data_out)).decode("ascii")
    finally:
        ctypes.memset(backing, 0, len(backing))


def decrypt(token: str) -> Optional[str]:
    """Reverse of encrypt(). Returns None if the blob is not ours or is corrupt."""
    if not IS_WINDOWS or not token:
        return None
    try:
        raw = base64.b64decode(token.encode("ascii"))
    except (ValueError, TypeError):
        return None
    data_in, backing = _to_blob(raw)
    data_out = _DATA_BLOB()
    try:
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(data_in),
            None, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(data_out),
        )
        if not ok:
            return None
        try:
            return _from_blob(data_out).decode("utf-8")
        except UnicodeDecodeError:
            return None
    finally:
        ctypes.memset(backing, 0, len(backing))


class CredentialStore:
    """Keeps router credentials for the current session, and optionally on disk."""

    _SETTING = "router_credentials"

    def __init__(self, database) -> None:
        self._db = database
        self._session: dict[str, RouterCredentials] = {}

    def set(self, host: str, username: str, password: str, remember: bool = False) -> bool:
        """Store credentials. Returns True if they were also persisted."""
        self._session[host] = RouterCredentials(username, password)
        if not remember:
            return False
        token = encrypt(password)
        if token is None:
            return False
        saved = self._db.get_setting(self._SETTING, {}) or {}
        saved[host] = {"username": username, "token": token}
        self._db.set_setting(self._SETTING, saved)
        return True

    def get(self, host: str) -> Optional[RouterCredentials]:
        if host in self._session:
            return self._session[host]
        saved = self._db.get_setting(self._SETTING, {}) or {}
        entry = saved.get(host)
        if not entry:
            return None
        password = decrypt(entry.get("token") or "")
        if password is None:
            return None
        creds = RouterCredentials(entry.get("username") or "", password)
        self._session[host] = creds
        return creds

    def forget(self, host: str) -> None:
        self._session.pop(host, None)
        saved = self._db.get_setting(self._SETTING, {}) or {}
        if host in saved:
            saved.pop(host)
            self._db.set_setting(self._SETTING, saved)

    def has_saved(self, host: str) -> bool:
        saved = self._db.get_setting(self._SETTING, {}) or {}
        return host in saved

    def known_hosts(self) -> list[str]:
        saved = self._db.get_setting(self._SETTING, {}) or {}
        return sorted(set(saved) | set(self._session))
