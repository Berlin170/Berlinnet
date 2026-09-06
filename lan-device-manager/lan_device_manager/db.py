"""Local SQLite storage.

Identity is keyed on MAC where one is known, and falls back to IP otherwise, so
a device that changes address is still recognised as the same device. Note that
a phone using a private (randomised) MAC will legitimately appear as a new
device when it rotates its address - that is the privacy feature working, not a
bug, and the UI says so.

Nothing here stores a plaintext credential. Router passwords live in
credentials.py, encrypted with the Windows user key.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable, Optional

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    key                 TEXT PRIMARY KEY,
    mac                 TEXT,
    ip                  TEXT,
    hostname            TEXT,
    hostname_source     TEXT,
    vendor              TEXT,
    category            TEXT,
    category_confidence TEXT,
    category_reason     TEXT,
    custom_name         TEXT,
    notes               TEXT,
    trust               TEXT NOT NULL DEFAULT 'unknown',
    blocked             INTEGER NOT NULL DEFAULT 0,
    block_method        TEXT,
    open_ports          TEXT,
    responded_to        TEXT,
    link_type           TEXT NOT NULL DEFAULT 'unknown',
    link_reason         TEXT,
    is_gateway          INTEGER NOT NULL DEFAULT 0,
    is_self             INTEGER NOT NULL DEFAULT 0,
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    online              INTEGER NOT NULL DEFAULT 0,
    times_seen          INTEGER NOT NULL DEFAULT 1,
    acknowledged        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key       TEXT,
    kind      TEXT NOT NULL,
    message   TEXT NOT NULL,
    detail    TEXT,
    at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    name  TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_at ON events(at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
"""

# Trust states a device can be in.
TRUST_TRUSTED = "trusted"
TRUST_UNKNOWN = "unknown"
TRUST_BLOCKED = "blocked"


def device_key(mac: Optional[str], ip: str) -> str:
    """Stable identity for a device."""
    if mac:
        return f"mac:{mac.lower()}"
    return f"ip:{ip}"


class Database:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = str(path or config.DB_PATH)
        self._local = threading.local()
        # Connections are per-thread, so close() needs its own registry to find
        # them all - otherwise handles from worker threads stay open and the
        # file cannot be deleted on Windows.
        self._connections: list[sqlite3.Connection] = []
        self._conn_lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after a database was first created."""
        have = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
        for column, ddl in (
            ("link_type", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("link_reason", "TEXT"),
        ):
            if column not in have:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {ddl}")

    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
            with self._conn_lock:
                self._connections.append(conn)
        return conn

    def close(self) -> None:
        """Close every connection this database has handed out."""
        with self._conn_lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()

    # ---------------------------------------------------------------- devices

    def upsert_scan_results(self, discovered: Iterable[Any]) -> dict[str, list[dict]]:
        """Merge a scan into storage.

        Returns the devices that are newly seen and the ones that just came
        back online, so the caller can raise notifications for them.
        """
        now = time.time()
        conn = self._connect()
        new_devices: list[dict] = []
        returning: list[dict] = []
        seen_keys: list[str] = []
        # Events are collected and written after the merge commits, so we never
        # open a nested transaction on the same connection.
        pending_events: list[tuple[Optional[str], str, str, Optional[str]]] = []

        with conn:
            for device in discovered:
                data = device.to_dict() if hasattr(device, "to_dict") else dict(device)
                key = device_key(data.get("mac"), data["ip"])
                seen_keys.append(key)

                row = conn.execute("SELECT * FROM devices WHERE key = ?", (key,)).fetchone()
                ports = json.dumps(data.get("open_ports") or [])
                via = json.dumps(data.get("responded_to") or [])

                # A host often answers ICMP before its MAC lands in the ARP
                # cache, so it gets stored under an ip: key. Once the MAC is
                # known, promote that record instead of creating a second one -
                # otherwise the custom name and notes are stranded on the old row.
                if row is None and data.get("mac"):
                    legacy_key = f"ip:{data['ip']}"
                    legacy = conn.execute(
                        "SELECT * FROM devices WHERE key = ?", (legacy_key,)
                    ).fetchone()
                    if legacy is not None:
                        conn.execute("UPDATE devices SET key = ?, mac = ? WHERE key = ?",
                                     (key, data["mac"], legacy_key))
                        conn.execute("UPDATE events SET key = ? WHERE key = ?",
                                     (key, legacy_key))
                        row = conn.execute("SELECT * FROM devices WHERE key = ?",
                                           (key,)).fetchone()

                if row is None:
                    conn.execute(
                        """INSERT INTO devices
                           (key, mac, ip, hostname, hostname_source, vendor, category,
                            category_confidence, category_reason, open_ports, responded_to,
                            link_type, link_reason,
                            is_gateway, is_self, first_seen, last_seen, online, times_seen)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1)""",
                        (key, data.get("mac"), data["ip"], data.get("hostname"),
                         data.get("hostname_source"), data.get("vendor"), data.get("category"),
                         data.get("category_confidence"), data.get("category_reason"),
                         ports, via,
                         data.get("link_type") or "unknown", data.get("link_reason"),
                         int(bool(data.get("is_gateway"))),
                         int(bool(data.get("is_self"))), now, now),
                    )
                    record = self.get_device(key)
                    if record:
                        new_devices.append(record)
                        pending_events.append((
                            key, "new_device",
                            f"New device detected: {data['ip']} - {data.get('mac') or 'MAC unknown'}",
                            data.get("vendor"),
                        ))
                else:
                    was_online = bool(row["online"])
                    conn.execute(
                        """UPDATE devices SET
                             ip = ?, vendor = ?, category = ?, category_confidence = ?,
                             category_reason = ?, open_ports = ?, responded_to = ?,
                             link_type = ?, link_reason = ?,
                             is_gateway = ?, is_self = ?, last_seen = ?, online = 1,
                             times_seen = times_seen + 1,
                             hostname = COALESCE(?, hostname),
                             hostname_source = COALESCE(?, hostname_source)
                           WHERE key = ?""",
                        (data["ip"], data.get("vendor"), data.get("category"),
                         data.get("category_confidence"), data.get("category_reason"),
                         ports, via,
                         data.get("link_type") or "unknown", data.get("link_reason"),
                         int(bool(data.get("is_gateway"))),
                         int(bool(data.get("is_self"))), now,
                         data.get("hostname"), data.get("hostname_source"), key),
                    )
                    if not was_online:
                        record = self.get_device(key)
                        if record:
                            returning.append(record)
                            pending_events.append((
                                key, "online",
                                f"{record['display_name']} came back online", None,
                            ))

            # Anything not in this scan is offline.
            if seen_keys:
                placeholders = ",".join("?" * len(seen_keys))
                gone = conn.execute(
                    f"SELECT key FROM devices WHERE online = 1 AND key NOT IN ({placeholders})",
                    seen_keys,
                ).fetchall()
                conn.execute(
                    f"UPDATE devices SET online = 0 WHERE key NOT IN ({placeholders})",
                    seen_keys,
                )
            else:
                gone = conn.execute("SELECT key FROM devices WHERE online = 1").fetchall()
                conn.execute("UPDATE devices SET online = 0")

        for row in gone:
            record = self.get_device(row["key"])
            if record:
                pending_events.append((
                    row["key"], "offline", f"{record['display_name']} went offline", None,
                ))

        if pending_events:
            with conn:
                conn.executemany(
                    "INSERT INTO events (key, kind, message, detail, at) VALUES (?,?,?,?,?)",
                    [(k, kind, msg, detail, now) for k, kind, msg, detail in pending_events],
                )

        return {"new": new_devices, "returned": returning}

    def _row_to_device(self, row: sqlite3.Row) -> dict:
        data = dict(row)
        data["open_ports"] = json.loads(data.get("open_ports") or "[]")
        data["responded_to"] = json.loads(data.get("responded_to") or "[]")
        data["online"] = bool(data["online"])
        data["blocked"] = bool(data["blocked"])
        data["is_gateway"] = bool(data["is_gateway"])
        data["is_self"] = bool(data["is_self"])
        data["acknowledged"] = bool(data["acknowledged"])
        data["display_name"] = (
            data.get("custom_name") or data.get("hostname") or data.get("ip") or "Unknown device"
        )
        data["is_new"] = not data["acknowledged"]
        return data

    def list_devices(self) -> list[dict]:
        rows = self._connect().execute(
            "SELECT * FROM devices ORDER BY online DESC, last_seen DESC"
        ).fetchall()
        return [self._row_to_device(r) for r in rows]

    def get_device(self, key: str) -> Optional[dict]:
        row = self._connect().execute("SELECT * FROM devices WHERE key = ?", (key,)).fetchone()
        return self._row_to_device(row) if row else None

    def update_device(self, key: str, **fields) -> Optional[dict]:
        allowed = {
            "custom_name", "notes", "trust", "blocked", "block_method", "acknowledged",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_device(key)
        assignments = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [key]
        conn = self._connect()
        with conn:
            conn.execute(f"UPDATE devices SET {assignments} WHERE key = ?", values)
        return self.get_device(key)

    def delete_device(self, key: str) -> None:
        conn = self._connect()
        with conn:
            conn.execute("DELETE FROM devices WHERE key = ?", (key,))
            conn.execute("DELETE FROM events WHERE key = ?", (key,))

    def acknowledge_all(self) -> int:
        conn = self._connect()
        with conn:
            cursor = conn.execute("UPDATE devices SET acknowledged = 1 WHERE acknowledged = 0")
        return cursor.rowcount

    def stats(self) -> dict:
        conn = self._connect()
        row = conn.execute(
            """SELECT
                 COUNT(*)                                           AS total,
                 SUM(CASE WHEN online = 1 THEN 1 ELSE 0 END)        AS online,
                 SUM(CASE WHEN online = 0 THEN 1 ELSE 0 END)        AS offline,
                 SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END)  AS new,
                 SUM(CASE WHEN trust = 'unknown' THEN 1 ELSE 0 END) AS unknown,
                 SUM(CASE WHEN trust = 'trusted' THEN 1 ELSE 0 END) AS trusted,
                 SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END)       AS blocked,
                 SUM(CASE WHEN link_type = 'wireless' AND online = 1
                          THEN 1 ELSE 0 END)                       AS wireless
               FROM devices"""
        ).fetchone()
        return {k: (row[k] or 0) for k in row.keys()}

    # ----------------------------------------------------------------- events

    def log_event(self, key: Optional[str], kind: str, message: str,
                  detail: Optional[str] = None) -> None:
        conn = self._connect()
        with conn:
            conn.execute(
                "INSERT INTO events (key, kind, message, detail, at) VALUES (?,?,?,?,?)",
                (key, kind, message, detail, time.time()),
            )

    def list_events(self, limit: int = 100, key: Optional[str] = None) -> list[dict]:
        conn = self._connect()
        if key:
            rows = conn.execute(
                "SELECT * FROM events WHERE key = ? ORDER BY at DESC LIMIT ?", (key, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------- settings

    def set_setting(self, name: str, value: Any) -> None:
        conn = self._connect()
        with conn:
            conn.execute(
                "INSERT INTO settings (name, value) VALUES (?,?) "
                "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                (name, json.dumps(value)),
            )

    def get_setting(self, name: str, default: Any = None) -> Any:
        row = self._connect().execute(
            "SELECT value FROM settings WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return default
