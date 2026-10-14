# -*- coding: utf-8 -*-
"""SQLite layer for the OpenWRT Fleet Manager."""
import os
import sqlite3
import threading
from datetime import datetime, timezone


def _now_iso() -> str:
    """SQLite-compatible UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

DB_PATH = os.environ.get("OPENWRT_FLEET_DB", "/data/openwrtfleet.db")
_lock = threading.RLock()


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                user TEXT NOT NULL DEFAULT 'root',
                password TEXT NOT NULL DEFAULT '',
                firmware_dir TEXT NOT NULL DEFAULT '',
                auth_mode TEXT NOT NULL DEFAULT 'password',
                ssh_key TEXT,
                auto_update INTEGER NOT NULL DEFAULT 0,
                kind TEXT NOT NULL DEFAULT 'openwrt',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS device_info (
                device_id INTEGER NOT NULL,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (device_id)
            );

            CREATE TABLE IF NOT EXISTS online_status (
                device_id INTEGER NOT NULL,
                online INTEGER NOT NULL DEFAULT 0,
                checked_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (device_id)
            );

            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                iface TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS lldp_local (
                device_id INTEGER NOT NULL,
                chassis_id TEXT NOT NULL DEFAULT '',
                mac TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                descr TEXT NOT NULL DEFAULT '',
                mgmt_ip TEXT NOT NULL DEFAULT '',
                lldpd TEXT NOT NULL DEFAULT 'missing',
                version TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (device_id)
            );

            CREATE TABLE IF NOT EXISTS lldp_neighbors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                iface TEXT NOT NULL DEFAULT '',
                mac TEXT NOT NULL DEFAULT '',
                chassis_id TEXT NOT NULL DEFAULT '',
                port_id TEXT NOT NULL DEFAULT '',
                neighbor_name TEXT NOT NULL DEFAULT '',
                neighbor_descr TEXT NOT NULL DEFAULT '',
                port_descr TEXT NOT NULL DEFAULT '',
                mgmt_ip TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE (device_id, iface, chassis_id, port_id, mac)
            );
            CREATE INDEX IF NOT EXISTS idx_lldp_dev ON lldp_neighbors (device_id);

            CREATE TABLE IF NOT EXISTS bridge_fdb (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                bridge TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                port_name TEXT NOT NULL DEFAULT '',
                mac TEXT NOT NULL DEFAULT '',
                seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE (device_id, bridge, port, mac)
            );
            CREATE INDEX IF NOT EXISTS idx_fdb_dev ON bridge_fdb (device_id);

            CREATE TABLE IF NOT EXISTS firmware_state (
                device_id INTEGER NOT NULL,
                current_version TEXT NOT NULL DEFAULT '',
                latest_version TEXT NOT NULL DEFAULT '',
                has_update INTEGER NOT NULL DEFAULT 0,
                check_time TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (device_id)
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS config_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS central_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS survey_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                ts TEXT NOT NULL DEFAULT (datetime('now')),
                uptime_s INTEGER NOT NULL DEFAULT 0,
                rx_bps INTEGER NOT NULL DEFAULT 0,
                tx_bps INTEGER NOT NULL DEFAULT 0,
                rx_total INTEGER NOT NULL DEFAULT 0,
                tx_total INTEGER NOT NULL DEFAULT 0,
                wifi_clients INTEGER NOT NULL DEFAULT 0,
                lan_clients INTEGER NOT NULL DEFAULT 0,
                ssids_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_snap_device_ts
                ON survey_snapshots (device_id, ts);

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );


            CREATE TABLE IF NOT EXISTS update_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                source TEXT NOT NULL DEFAULT 'auto',
                target_version TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                started_at TEXT,
                finished_at TEXT
            );
            """
        )
        # migration: signal column for WLAN clients (older DBs)
        try:
            conn.execute("ALTER TABLE clients ADD COLUMN signal TEXT NOT NULL DEFAULT ''")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        # migration: SSH-Key-Login + Auto-Update columns (older DBs)
        for _col, _ddl in (("auth_mode", "TEXT NOT NULL DEFAULT 'password'"),
                           ("ssh_key", "TEXT"),
                           ("ssh_key_passphrase", "TEXT"),
                           ("auto_update", "INTEGER NOT NULL DEFAULT 0"),
                           ("kind", "TEXT NOT NULL DEFAULT 'openwrt'")):
            try:
                conn.execute("ALTER TABLE devices ADD COLUMN %s %s" % (_col, _ddl))
                conn.commit()
            except sqlite3.OperationalError:
                pass
        # migration: spezialisierter HP-Typ (frueher "hp", jetzt "hp1810")
        try:
            conn.execute("UPDATE devices SET kind='hp1810' WHERE kind='hp'")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        conn.commit()


def get_db() -> sqlite3.Connection:
    return _connect()


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

def add_device(name: str, ip: str, port: int, user: str, password: str,
               firmware_dir: str, ssh_key: str = "", auth_mode: str = "password",
               auto_update: bool = False, kind: str = "openwrt",
               ssh_key_passphrase: str = "") -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO devices (name, ip, port, user, password, firmware_dir, "
            "ssh_key, auth_mode, auto_update, kind, ssh_key_passphrase) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (name, ip, port, user, password, firmware_dir,
             ssh_key or None, auth_mode or "password", 1 if auto_update else 0,
             kind or "openwrt", ssh_key_passphrase or None),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_devices() -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY id")]


def get_device(device_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return dict(row) if row else None


def get_device_by_ip(ip: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None


def remove_device(device_id: int) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.execute("DELETE FROM device_info WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM online_status WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM clients WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM lldp_local WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM lldp_neighbors WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM firmware_state WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM update_jobs WHERE device_id=?", (device_id,))
        conn.commit()


# ---------------------------------------------------------------------------
# Device info / status
# ---------------------------------------------------------------------------

def upsert_device_info(device_id: int, data_json: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO device_info (device_id, data_json, updated_at) "
            "VALUES (?,?,datetime('now')) "
            "ON CONFLICT(device_id) DO UPDATE SET data_json=excluded.data_json, "
            "updated_at=excluded.updated_at",
            (device_id, data_json),
        )
        conn.commit()


def get_device_info(device_id: int):
    """Return the stored device info as a dict (or None if missing)."""
    import json as _json
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT data_json FROM device_info WHERE device_id=?",
            (device_id,),
        ).fetchone()
    if not row:
        return None
    try:
        return _json.loads(row[0])
    except Exception:
        return None


def upsert_online(device_id: int, online: bool) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO online_status (device_id, online, checked_at) "
            "VALUES (?,?,datetime('now')) "
            "ON CONFLICT(device_id) DO UPDATE SET online=excluded.online, "
            "checked_at=excluded.checked_at",
            (device_id, 1 if online else 0),
        )
        conn.commit()


def last_check(device_id: int) -> tuple | None:
    """Return (online, checked_at) or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT online, checked_at FROM online_status WHERE device_id=?",
            (device_id,),
        ).fetchone()
        return (row["online"], row["checked_at"]) if row else None


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

def replace_clients(device_id: int, kind: str, rows: list) -> None:
    """rows: (ip, mac, hostname, iface[, signal]) – signal optional."""
    norm = []
    for r in rows:
        r = list(r)
        while len(r) < 5:
            r.append("")
        norm.append((device_id, kind, r[0], r[1], r[2], r[3], r[4]))
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM clients WHERE device_id=? AND kind=?", (device_id, kind))
        conn.executemany(
            "INSERT INTO clients (device_id, kind, ip, mac, hostname, iface, signal) "
            "VALUES (?,?,?,?,?,?,?)",
            norm,
        )
        conn.commit()


def list_clients(device_id: int, kind: str) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM clients WHERE device_id=? AND kind=? ORDER BY ip",
            (device_id, kind),
        )]


# ---------------------------------------------------------------------------
# LLDP topology
# ---------------------------------------------------------------------------

def save_lldp(device_id: int, local: dict, neighbors: list) -> None:
    """Persist one LLDP poll. `local` is the local-chassis dict from
    `poll_lldp`; `neighbors` is its parsed neighbor list. Neighbors are
    upserted (surviving entries are not dropped, so a transient empty
    poll never erases the topology)."""
    lc = local.get("local_chassis") or {}
    def _g(x, key):
        if isinstance(x, dict):
            v = x.get(key)
            if isinstance(v, list):
                v = v[0] if v else None
            if isinstance(v, dict):
                v = v.get("value", "")
            return v or ""
        return x if isinstance(x, str) else ("" if x is None else str(x))
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO lldp_local (device_id, chassis_id, mac, name, descr, "
            "mgmt_ip, lldpd, version, error, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,datetime('now')) "
            "ON CONFLICT(device_id) DO UPDATE SET "
            "chassis_id=excluded.chassis_id, mac=excluded.mac, "
            "name=excluded.name, descr=excluded.descr, "
            "mgmt_ip=excluded.mgmt_ip, lldpd=excluded.lldpd, "
            "version=excluded.version, error=excluded.error, "
            "updated_at=excluded.updated_at",
            (device_id, _g(lc, "id"), _g(lc, "mac"), _g(lc, "name"),
             _g(lc, "descr"), _g(lc, "mgmt-ip"),
             local.get("lldpd") or "", local.get("version") or "",
             (local.get("error") or "")[:300]),
        )
        for n in neighbors:
            conn.execute(
                "INSERT INTO lldp_neighbors (device_id, iface, mac, chassis_id, "
                "port_id, neighbor_name, neighbor_descr, port_descr, mgmt_ip, "
                "hostname, seen_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now')) "
                "ON CONFLICT(device_id, iface, chassis_id, port_id, mac) "
                "DO UPDATE SET neighbor_name=excluded.neighbor_name, "
                "neighbor_descr=excluded.neighbor_descr, "
                "port_descr=excluded.port_descr, mgmt_ip=excluded.mgmt_ip, "
                "hostname=excluded.hostname, seen_at=excluded.seen_at",
                (device_id, n.get("interface") or "", n.get("mac") or "",
                 n.get("chassis_id") or "", n.get("port_id") or "",
                 n.get("neighbor_name") or "", n.get("neighbor_descr") or "",
                 n.get("port_descr") or "", n.get("mgmt_ip") or "",
                 n.get("hostname") or ""),
            )
        conn.commit()


def lldp_local(device_id: int):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM lldp_local WHERE device_id=?", (device_id,)).fetchone()
        return dict(row) if row else None


def lldp_neighbors(device_id: int | None = None) -> list:
    if device_id is None:
        with _connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT n.*, d.name AS device_name, d.ip AS device_ip "
                "FROM lldp_neighbors n JOIN devices d ON d.id=n.device_id "
                "ORDER BY d.name, n.iface")]
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM lldp_neighbors WHERE device_id=? ORDER BY iface",
            (device_id,),
        )]


def save_fdb(device_id: int, rows: list) -> None:
    """Persist a bridge-FDB poll. `rows`: (bridge, port, port_name, mac).

    Snapshot-replace per device: the whole device FDB is dropped and
    re-inserted so stale (aged-out) entries vanish. A brand-new empty
    result (e.g. first poll) is still written so the device is marked
    as polled. Port numbering follows brctl (decimal) and port_name is
    resolved on the host side from sysfs, so it is stable across polls.
    """
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM bridge_fdb WHERE device_id=?", (device_id,))
        if rows:
            conn.executemany(
                "INSERT INTO bridge_fdb (device_id, bridge, port, port_name, mac, "
                "seen_at) VALUES (?,?,?,?,?,datetime('now'))",
                [(device_id, b, p, pn, m) for (b, p, pn, m) in rows],
            )
        conn.commit()


def fdb(device_id: int) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM bridge_fdb WHERE device_id=? ORDER BY bridge, port, mac",
            (device_id,),
        )]


def search_clients(query: str, limit: int = 200) -> list:
    """Global search over all cached clients by hostname or MAC address."""
    q = query.strip()
    if not q:
        return []
    like = f"%{q}%"
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT c.*, d.name AS device_name, d.ip AS device_ip "
            "FROM clients c JOIN devices d ON d.id=c.device_id "
            "WHERE c.hostname LIKE ? OR c.mac LIKE ? "
            "ORDER BY c.hostname, c.ip LIMIT ?",
            (like, like, limit),
        )]


# ---------------------------------------------------------------------------
# Device rename
# ---------------------------------------------------------------------------

def rename_device(device_id: int, name: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
        conn.commit()


# ---------------------------------------------------------------------------
# Survey snapshots (history)
# ---------------------------------------------------------------------------

def add_snapshot(device_id: int, uptime_s: int, rx_bps: int, tx_bps: int,
                 rx_total: int, tx_total: int, wifi_clients: int,
                 lan_clients: int, ssids: list) -> None:
    import json as _json
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO survey_snapshots (device_id, ts, uptime_s, rx_bps, tx_bps, "
            "rx_total, tx_total, wifi_clients, lan_clients, ssids_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (device_id, _now_iso(), uptime_s, rx_bps, tx_bps, rx_total,
             tx_total, wifi_clients, lan_clients, _json.dumps(ssids)),
        )
        conn.execute(
            "DELETE FROM survey_snapshots WHERE ts < datetime('now','-14 days')")
        conn.commit()


def list_snapshots(device_id: int, since_hours: int = 24) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM survey_snapshots WHERE device_id=? AND ts >= datetime('now',?) "
            "ORDER BY ts", (device_id, f"-{int(since_hours)} hours"),
        )]


def list_snapshots_all(since_hours: int = 24) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT s.*, d.name AS device_name FROM survey_snapshots s "
            "JOIN devices d ON d.id=s.device_id "
            "WHERE s.ts >= datetime('now',?) ORDER BY s.ts",
            (f"-{int(since_hours)} hours",),
        )]


def prune_snapshots(days: int = 14) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "DELETE FROM survey_snapshots WHERE ts < datetime('now',?)",
            (f"-{int(days)} days",),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Users / auth
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    import hashlib
    import secrets
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", salt.encode(), password.encode(), 200_000)
    return f"{salt}${digest.hex()}"


def _verify_password(stored: str, password: str) -> bool:
    try:
        salt, hexdigest = stored.split("$", 1)
    except (ValueError, AttributeError):
        return False
    import hashlib
    digest = hashlib.pbkdf2_hmac("sha256", salt.encode(), password.encode(), 200_000)
    return digest.hex() == hexdigest


def list_users() -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, username, display_name, role, created_at FROM users "
            "ORDER BY username")]


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?",
                           (username,)).fetchone()
        return dict(row) if row else None


def add_user(username: str, password: str, display_name: str, role: str) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, display_name, role) "
            "VALUES (?,?,?,?)",
            (username, _hash_password(password), display_name, role),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_user(user_id: int, password: str | None, display_name: str | None,
                role: str | None) -> None:
    with _lock, _connect() as conn:
        if password:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (_hash_password(password), user_id))
        if display_name is not None:
            conn.execute("UPDATE users SET display_name=? WHERE id=?",
                         (display_name, user_id))
        if role is not None:
            conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        conn.commit()


def remove_user(user_id: int) -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.execute("DELETE FROM auth_tokens WHERE user_id=?", (user_id,))
        conn.commit()


def create_token(user_id: int) -> str:
    import secrets
    token = secrets.token_urlsafe(32)
    with _lock, _connect() as conn:
        conn.execute("INSERT INTO auth_tokens (token, user_id) VALUES (?,?)",
                     (token, user_id))
        conn.commit()
    return token


def user_for_token(token: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id "
            "WHERE t.token=?", (token,)).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------

def set_firmware_state(device_id: int, current_version: str, latest_version: str,
                       has_update: bool) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO firmware_state (device_id, current_version, latest_version, "
            "has_update, check_time) VALUES (?,?,?,?,datetime('now')) "
            "ON CONFLICT(device_id) DO UPDATE SET "
            "current_version=excluded.current_version, "
            "latest_version=excluded.latest_version, "
            "has_update=excluded.has_update, check_time=excluded.check_time",
            (device_id, current_version, latest_version, 1 if has_update else 0),
        )
        conn.commit()


def get_firmware_state(device_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM firmware_state WHERE device_id=?", (device_id,)
        ).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def add_job(device_id: int, kind: str, status: str, message: str) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO jobs (device_id, kind, status, message) VALUES (?,?,?,?)",
            (device_id, kind, status, message),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_jobs(limit: int = 100) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
        ]


def update_device(device_id: int, name: str, ip: str, port: int, user: str,
                  password: str, firmware_dir: str, ssh_key: str = "",
                  auth_mode: str = "password", auto_update: bool = False,
                  kind: str = "openwrt", ssh_key_passphrase: str = "") -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE devices SET name=?, ip=?, port=?, user=?, password=?, "
            "firmware_dir=?, ssh_key=?, auth_mode=?, auto_update=?, kind=?, "
            "ssh_key_passphrase=? WHERE id=?",
            (name, ip, port, user, password, firmware_dir,
             ssh_key or None, auth_mode or "password", 1 if auto_update else 0,
             kind or "openwrt", ssh_key_passphrase or None, device_id))
        conn.commit()


def set_device_auto_update(device_id: int, auto: bool) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE devices SET auto_update=? WHERE id=?",
                     (1 if auto else 0, device_id))
        conn.commit()


def list_auto_update_devices() -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM devices WHERE auto_update=1 ORDER BY id")]


def add_update_job(device_id: int, name: str, status: str, source: str = "auto",
                   target_version: str = "", message: str = "") -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO update_jobs (device_id, name, status, source, "
            "target_version, message, started_at) "
            "VALUES (?,?,?,?,?,?,datetime('now'))",
            (device_id, name, status, source, target_version, message))
        conn.commit()
        return int(cur.lastrowid)


def last_update_job(device_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM update_jobs WHERE device_id=? ORDER BY id DESC LIMIT 1",
            (device_id,)).fetchone()
        return dict(row) if row else None


def finish_update_job(job_id: int, status: str, message: str = "") -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE update_jobs SET status=?, message=?, finished_at=datetime('now') "
            "WHERE id=?",
            (status, message, job_id))
        conn.commit()


def list_update_jobs(limit: int = 100) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT j.*, d.ip AS device_ip FROM update_jobs j "
            "LEFT JOIN devices d ON d.id=j.device_id "
            "ORDER BY j.id DESC LIMIT ?", (limit,))]


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

def add_backup(device_id: int, filename: str, size: int) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO config_backups (device_id, filename, size) VALUES (?,?,?)",
            (device_id, filename, size),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_backups(device_id: int) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM config_backups WHERE device_id=? ORDER BY id DESC",
            (device_id,),
        )]


# ---------------------------------------------------------------------------
# Central config
# ---------------------------------------------------------------------------

def add_central(device_id: int, payload_json: str, result_json: str) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO central_config (device_id, payload_json, result_json) "
            "VALUES (?,?,?)",
            (device_id, payload_json, result_json),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_central(limit: int = 100) -> list:
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM central_config ORDER BY id DESC LIMIT ?", (limit,))
        ]
