# -*- coding: utf-8 -*-
"""OpenWRT Fleet Manager – FastAPI app.

OpenWRT-router per SSH verwalten:
  - Firmware-Check + sysupgrade (downloads.openwrt.org)
  - Konfigurationssicherung (backup / restore)
  - Zentrale Konfiguration (uci-Werte auf mehrere Router anwenden)
  - Erfassung von LAN- (ARP) und WLAN- (wifi status) Endgeräten pro Router
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response, \
    UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, \
    RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, scheduler, updater
from .sshx import OpenWRT, wait_for_reboot

db.init_db()

BACKUP_DIR = os.environ.get("OPENWRT_FLEET_BACKUPS", "/data/backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

app = FastAPI(title="OpenWRT Fleet Manager")

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ---------------------------------------------------------------- auth

SESSION_SECRET_FILE = os.path.join(
    os.environ.get("OPENWRT_FLEET_DATA", "/data"), ".session_secret")
COOKIE = "owf_session"
SESSION_TTL = 12 * 3600


def _load_secret() -> str:
    try:
        with open(SESSION_SECRET_FILE) as f:
            s = f.read().strip()
        if s:
            return s
    except FileNotFoundError:
        pass
    s = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(SESSION_SECRET_FILE), exist_ok=True)
        with open(SESSION_SECRET_FILE, "w") as f:
            f.write(s)
        os.chmod(SESSION_SECRET_FILE, 0o600)
    except Exception:
        pass
    return s


SESSION_SECRET = _load_secret()
SESSIONS = {}  # token -> (expiry_ts, username)
FAIL_COUNT = {}


def _sig(token: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), token.encode(),
                    hashlib.sha256).hexdigest()


def _new_session(username: str) -> str:
    t = secrets.token_urlsafe(32)
    SESSIONS[t] = (time.time() + SESSION_TTL, username)
    return f"{t}.{_sig(t)}"


def _check_session(cookie_val: str):
    if not cookie_val or "." not in cookie_val:
        return None
    t, _, sig = cookie_val.partition(".")
    if not hmac.compare_digest(_sig(t), sig):
        return None
    entry = SESSIONS.pop(t, None)
    if entry is None:
        return None
    if entry[0] < time.time():
        return None
    SESSIONS[t] = entry
    return entry[1]


def _kill_session(cookie_val: str):
    if cookie_val and "." in cookie_val:
        t, _, sig = cookie_val.partition(".")
        if hmac.compare_digest(_sig(t), sig):
            SESSIONS.pop(t, None)


def verify_password(username: str, password: str) -> bool:
    u = db.get_user(username)
    return bool(u) and db._verify_password(u.get("password_hash", ""), password)


def auth(request: Request) -> dict:
    """Returns the acting user dict {username, role}."""
    user = _check_session(request.cookies.get(COOKIE, ""))
    if user:
        u = db.get_user(user)
        if u:
            return {"username": u["username"], "role": u["role"]}
    b = request.headers.get("Authorization", "")
    if b.startswith("Bearer "):
        u = db.user_for_token(b[7:].strip())
        if u:
            return {"username": u["username"], "role": u["role"]}
    raise HTTPException(401, "unauthorized")


def require_admin(user: dict = Depends(auth)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(403, "adminrechte erforderlich")
    return user


def _authed(request: Request) -> bool:
    try:
        auth(request)
        return True
    except HTTPException:
        return False


class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str = ""
    display_name: str = ""
    role: str = "user"


class PasswordIn(BaseModel):
    old: str
    new: str


_USER_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

LOGIN_HTML = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenWRT Fleet Manager – Login</title>
<style>
:root { --bg:#0f1419; --card:#1a222c; --tx:#dfe7f0; --mut:#8ba0b6; --acc:#4d9dff; --bad:#e05252; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
       font-family:system-ui,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--tx); }
.box { background:var(--card); border:1px solid #2a3644; border-radius:12px; padding:30px; width:340px; max-width:92vw; }
h1 { font-size:17px; margin:0 0 4px; }
.sub { color:var(--mut); font-size:12.5px; margin-bottom:18px; }
label { display:block; font-size:12.5px; color:var(--mut); margin:12px 0 4px; }
input { width:100%; background:#0b0f14; border:1px solid #34445a; color:var(--tx); padding:9px 10px; border-radius:6px; font-size:13.5px; }
button { width:100%; margin-top:18px; background:var(--acc); border:0; color:#fff; padding:10px; border-radius:6px; cursor:pointer; font-size:14px; }
.err { color:var(--bad); font-size:12.5px; margin-top:10px; min-height:16px; }
</style>
</head>
<body>
<div class="box">
  <h1>&#128246; OpenWRT Fleet Manager</h1>
  <div class="sub">Bitte anmelden</div>
  <form onsubmit="return doLogin(event)">
    <label>Benutzername</label>
    <input id="u" autocomplete="username" autofocus>
    <label>Passwort</label>
    <input id="p" type="password" autocomplete="current-password">
    <button type="submit">Anmelden</button>
    <div class="err" id="err"></div>
  </form>
</div>
<script>
async function doLogin(e) {
  e.preventDefault();
  const err = document.getElementById('err');
  err.textContent = '';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: document.getElementById('u').value,
                              password: document.getElementById('p').value })
    });
    if (!r.ok) { err.textContent = r.status === 429 ? 'Zu viele Versuche – kurz warten.' : 'Anmeldung fehlgeschlagen'; return false; }
    location.replace('/');
  } catch (ex) { err.textContent = 'Fehler: ' + ex.message; }
  return false;
}
</script>
</body>
</html>"""


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if _authed(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(LOGIN_HTML,
                        headers={"Cache-Control": "no-store, max-age=0"})


@app.post("/api/login", include_in_schema=False)
def login(body: LoginIn, response: Response):
    now = time.time()
    f = FAIL_COUNT.get(body.username, [0, now])
    if f[0] >= 5 and now - f[1] < 300:
        raise HTTPException(429, "too many attempts")
    if verify_password(body.username, body.password):
        FAIL_COUNT.pop(body.username, None)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, _new_session(body.username),
                        max_age=SESSION_TTL, httponly=True, samesite="Lax")
        return resp
    f[0] += 1
    FAIL_COUNT[body.username] = f
    raise HTTPException(401, "bad credentials")


@app.post("/api/logout", include_in_schema=False)
def logout(request: Request, response: Response):
    _kill_session(request.cookies.get(COOKIE, ""))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/whoami")
def whoami(user: dict = Depends(auth)):
    return user


@app.post("/api/password")
def change_password(body: PasswordIn, user: dict = Depends(auth)):
    if not verify_password(user["username"], body.old):
        raise HTTPException(401, "altes Passwort falsch")
    if len(body.new) < 8:
        raise HTTPException(400, "min. 8 Zeichen")
    u = db.get_user(user["username"])
    db.update_user(u["id"], body.new, None, None)
    return {"ok": True}


# ------------------------------------------------- user management (admin)

@app.get("/api/users")
def api_users(_u: dict = Depends(require_admin)):
    return db.list_users()


@app.post("/api/users")
def api_add_user(body: UserIn, _u: dict = Depends(require_admin)):
    if not _USER_RE.match(body.username or ""):
        raise HTTPException(400, "Benutzername: 3–32 Zeichen, Buchstaben/Zahlen/_.-")
    if len(body.password or "") < 8:
        raise HTTPException(400, "Passwort: min. 8 Zeichen")
    if db.get_user(body.username):
        raise HTTPException(409, "Benutzer existiert bereits")
    if body.role not in ("admin", "user"):
        raise HTTPException(400, "Rolle: admin oder user")
    uid = db.add_user(body.username, body.password,
                      body.display_name or body.username, body.role)
    return {"id": uid}


@app.post("/api/users/{user_id}")
def api_update_user(user_id: int, body: dict,
                    _u: dict = Depends(require_admin)):
    new_pw = body.get("password") or None
    if new_pw and len(new_pw) < 8:
        raise HTTPException(400, "Passwort: min. 8 Zeichen")
    role = body.get("role")
    if role and role not in ("admin", "user"):
        raise HTTPException(400, "Rolle: admin oder user")
    if not db.list_users() or not any(
            x["id"] == user_id for x in db.list_users()):
        raise HTTPException(404, "Benutzer nicht gefunden")
    db.update_user(user_id, new_pw, body.get("display_name"), role)
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: int, user: dict = Depends(require_admin)):
    me = db.get_user(user["username"])
    if me and me["id"] == user_id:
        raise HTTPException(400, "Eigenen Benutzer kannst du nicht löschen")
    db.remove_user(user_id)
    return {"ok": True}


@app.post("/api/users/{user_id}/token")
def api_user_token(user_id: int, _u: dict = Depends(require_admin)):
    """API-Token für Skript-Zugang (nur Admins)."""
    return {"token": db.create_token(user_id)}


# --------------------------------------------------------------- bootstrap


def _bootstrap_admin() -> None:
    """First start: create a default admin (password via env or generated)."""
    if db.list_users():
        return
    user = os.environ.get("OWF_ADMIN_USER", "admin")
    pw = os.environ.get("OWF_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    db.add_user(user, pw, "Administrator", "admin")
    print(f"[bootstrap] created default admin user '{user}' – password:\n"
          f"{'=' * 60}\n{pw}\n{'=' * 60}", flush=True)


# ----------------------------------------------------------------- models


class UciSet(BaseModel):
    key: str          # z. B. wireless.radio0.ht
    value: str


class PkgUpdateIn(BaseModel):
    """Körper für POST /api/devices/{id}/packages/update.
    names leer = alle upgradbaren Pakete, sonst nur die aufgeführten."""
    names: list = []


class CentralApply(BaseModel):
    device_ids: list[int]
    assignments: list[UciSet]
    commit: bool = True
    backup_before: bool = True


# ----------------------------------------------------------------- helpers


def _device_or_404(device_id: int) -> dict:
    row = db.get_device(device_id)
    if not row:
        raise HTTPException(404, "device not found")
    return row


def _mask(row: dict) -> dict:
    out = dict(row)
    out["password"] = "********" if row.get("password") else ""
    out["ssh_key"] = "********" if row.get("ssh_key") else ""
    return out


def _job(device_id, kind, status, message):
    try:
        db.add_job(device_id, kind, status, message)
    except Exception:
        pass


def _is_hp(row: dict) -> bool:
    return (row.get("kind") or "openwrt") == "hp1810"


def _ssh_only(row: dict) -> None:
    """Endpunkte, die zwingend SSH brauchen, fuer den HP-1810-Switch sperren."""
    if _is_hp(row):
        raise HTTPException(
            400,
            "HP 1810: Dieser Switch wird per Web-Interface verwaltet – "
            "SSH ist nicht verfuegbar.")


def _hp_virtual_info(device_id: int, row: dict) -> dict:
    """Info-Bar des Switches aus Web-Interface-Daten (LLDP/FDB) – ohne SSH."""
    local = db.lldp_local(device_id) or {}
    info = {
        "kind": "hp1810",
        "ip": row.get("ip") or "",
        "model": local.get("name") or "HP 1810-24G",
        "version": "Web-Interface (kein SSH)",
        "lldp_neighbors": len(db.lldp_neighbors(device_id)),
        "fdb_entries": len(db.fdb(device_id)),
        "refreshed_at": local.get("updated_at") or "",
        "no_ssh": True,
    }
    cur = db.get_device_info(device_id)
    if isinstance(cur, dict) and cur.get("manual"):
        info["manual"] = True   # manuellen Namen nicht verlieren
    db.upsert_device_info(device_id, json.dumps(info))
    return info


# -------------------------------------------------------------------- boot


@app.on_event("startup")
def _startup():
    _bootstrap_admin()
    scheduler.start()


@app.get("/")
def index(request: Request):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ---------------------------------------------------------------- devices


@app.get("/api/devices")
def api_devices(user: dict = Depends(auth)):
    out = []
    for d in db.list_devices():
        row = _mask(d)
        row["status"] = db.last_check(d["id"])
        row["firmware"] = db.get_firmware_state(d["id"])
        info = db.get_device_info(d["id"])
        row["info"] = info if isinstance(info, dict) else {}
        row["clients"] = {
            "lan": len(db.list_clients(d["id"], "lan")),
            "wlan": len(db.list_clients(d["id"], "wlan")),
        }
        out.append(row)
    return out


class DeviceIn(BaseModel):
    name: str
    ip: str
    port: int = 22
    user: str = "root"
    password: str = ""
    firmware_dir: str = "https://downloads.openwrt.org/releases"
    ssh_key: str = ""
    auth_mode: str = "password"
    auto_update: bool = False
    kind: str = "openwrt"


@app.post("/api/devices")
def api_device_add(d: DeviceIn, _u: dict = Depends(require_admin)):
    if not d.name or not d.ip:
        raise HTTPException(400, "name and ip required")
    did = db.add_device(d.name, d.ip, d.port, d.user, d.password,
                        d.firmware_dir or "https://downloads.openwrt.org/releases",
                        ssh_key=d.ssh_key, auth_mode=d.auth_mode,
                        auto_update=d.auto_update, kind=d.kind)
    return {"id": did}


class BulkIn(BaseModel):
    devices: list[DeviceIn]


@app.post("/api/devices/bulk")
def api_device_bulk(b: BulkIn, _u: dict = Depends(require_admin)):
    """Mehrfach-Hinzufügen: List aus dem Editor (1 Router pro Zeile)."""
    added, errors = [], []
    for d in b.devices:
        if not d.ip or not d.name:
            errors.append({"ip": d.ip, "error": "Name und IP fehlen"})
            continue
        if db.get_device_by_ip(d.ip):
            errors.append({"ip": d.ip, "error": "IP bereits vorhanden"})
            continue
        added.append({"id": db.add_device(
            d.name, d.ip, d.port, d.user, d.password,
            d.firmware_dir or "https://downloads.openwrt.org/releases")})
    return {"added": added, "errors": errors}


@app.delete("/api/devices/{device_id}")
def api_device_delete(device_id: int, _u: dict = Depends(require_admin)):
    _device_or_404(device_id)
    db.remove_device(device_id)
    return {"ok": True}


class DevicePut(BaseModel):
    name: str
    ip: str
    port: int = 22
    user: str = "root"
    password: str | None = None
    firmware_dir: str = "https://downloads.openwrt.org/releases"
    ssh_key: str | None = None
    auth_mode: str = "password"
    auto_update: bool = False
    kind: str = "openwrt"


@app.put("/api/devices/{device_id}")
def api_device_update(device_id: int, body: DevicePut,
                      _u: dict = Depends(require_admin)):
    row = _device_or_404(device_id)
    # masked/empty fields keep the stored secret
    pw = row["password"] if body.password in (None, "", "********") else body.password
    key = (row.get("ssh_key") or "") if body.ssh_key in (None, "", "********") else body.ssh_key
    db.update_device(device_id, body.name, body.ip, body.port, body.user, pw,
                     body.firmware_dir or "https://downloads.openwrt.org/releases",
                     key, body.auth_mode, body.auto_update, body.kind)
    _job(device_id, "device", "ok", "Zugangsdaten aktualisiert")
    return {"ok": True}


# ------------------------------------------------------------ per-device


@app.post("/api/devices/{device_id}/status")
def api_device_status(device_id: int, _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    if _is_hp(row):
        online = scheduler.make_hp(row).is_online()
        db.upsert_online(device_id, online)
        _job(device_id, "status", "ok" if online else "down",
             "online (Web-Interface)" if online else "Switch nicht erreichbar")
        return {"online": online}
    dev = scheduler.make_device(row)
    online = dev.is_online()
    db.upsert_online(device_id, online)
    _job(device_id, "status", "ok" if online else "down",
         "online" if online else "unreachable")
    return {"online": online}


@app.post("/api/devices/{device_id}/info")
def api_device_info(device_id: int, _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    if _is_hp(row):
        return _hp_virtual_info(device_id, row)
    dev = scheduler.make_device(row)
    try:
        info = dev.full_info()
    except Exception as exc:
        raise HTTPException(502, f"device unreachable: {exc}")
    db.upsert_device_info(device_id, json.dumps(info))
    db.upsert_online(device_id, True)
    return info


# ---------------------------------------------------------------- clients


@app.post("/api/devices/{device_id}/clients")
def api_scan_clients(device_id: int, _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    if _is_hp(row):
        # Switch ohne SSH: die MAC-Tabelle (FDB) ist die "Client"-Liste.
        scheduler.poll_lldp(device_id)
        label_map = _client_label_map()
        lan = []
        for r in db.fdb(device_id):
            mac = (r.get("mac") or "").lower()
            hm = label_map.get(mac) or ("", "", "")
            lan.append({"ip": hm[1], "mac": mac,
                        "hostname": hm[0] or (r.get("port_name") or ""),
                        "iface": r.get("port_name") or ("Port %s" % r.get("port"))})
        db.replace_clients(device_id, "lan",
                           [(c["ip"], c["mac"], c["hostname"], c["iface"])
                            for c in lan])
        db.replace_clients(device_id, "wlan", [])
        return {"lan": db.list_clients(device_id, "lan"),
                "wlan": []}
    dev = scheduler.make_device(row)
    try:
        lan = dev.lan_clients()
        wlan = dev.wlan_clients()
    except Exception as exc:
        raise HTTPException(502, f"device unreachable: {exc}")
    # enrich WLAN entries with IP/hostname from the ARP table
    macmap = {c["mac"]: c for c in lan}
    for w in wlan:
        m = macmap.get(w["mac"])
        if m:
            if not w.get("ip"):
                w["ip"] = m["ip"]
            if not w.get("hostname"):
                w["hostname"] = m["hostname"]
    db.replace_clients(device_id, "lan",
                       [(c["ip"], c["mac"], c["hostname"], c["iface"])
                        for c in lan])
    db.replace_clients(device_id, "wlan",
                       [(c["ip"], c["mac"], c["hostname"],
                         c.get("ssid") or "", c.get("signal") or "")
                        for c in wlan])
    db.upsert_online(device_id, True)
    _job(device_id, "scan", "ok",
         f"{len(lan)} LAN / {len(wlan)} WLAN")
    return {"lan": db.list_clients(device_id, "lan"),
            "wlan": db.list_clients(device_id, "wlan")}


@app.get("/api/devices/{device_id}/clients")
def api_clients(device_id: int, kind: str = "lan", _u: dict = Depends(auth)):
    _device_or_404(device_id)
    return db.list_clients(device_id, kind if kind in ("lan", "wlan") else "lan")


# -------------------------------------------------------------- firmware


def _probe_remote_image(dev, path: str) -> tuple[int, bytes]:
    """Size + first 128 bytes of a file on the router."""
    rc, out, _ = dev.run(f"wc -c < {shlex.quote(path)}", timeout=30)
    size = int(out.strip() or 0) if rc == 0 else 0
    rc2, out2, _ = dev.run(
        f"head -c 128 {shlex.quote(path)} | hexdump -v -e '16/1 \\\"%02x\\\"' 2>/dev/null "
        f"|| head -c 128 {shlex.quote(path)} | od -An -v -tx1", timeout=30)
    hexd = re.sub(r"\s+", "", out2)[:256]
    magic = bytes.fromhex(hexd) if len(hexd) >= 2 else b""
    return size, magic


def _image_ok(size: int, magic: bytes, expected: int = 0) -> bool:
    if size <= 0:
        return False
    # squashfs magic "hsqs" at offset 0x48 – decisive if present
    if len(magic) > 76 and magic[72:76] == b"hsqs":
        return expected == 0 or size >= expected * 0.99
    if magic[:1] == b"<" or b"<html" in magic.lower():
        return False  # HTML error page, not a firmware image
    return True


def _stage_image_on_device(dev, url: str) -> dict:
    """Download the firmware image onto the router into /tmp.

    Try a router-side download first (wget/uclient-fetch/curl). Busybox
    tooling on minimal images often lacks TLS support, so fall back to a
    server-side download piped over SSH into /tmp when that fails or the
    file looks invalid.
    """
    import urllib.request
    dest = "/tmp/firmware.bin"

    expected = 0
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=20) as resp:
            expected = int(resp.headers.get("Content-Length") or 0)
    except Exception:
        expected = 0

    rc, out, _err = dev.download_image(url, dest)
    size, magic = _probe_remote_image(dev, dest)
    if "DLRC=0" in out and _image_ok(size, magic, expected):
        return {"image": dest, "via": "router", "size": size}

    # Fallback: download here (full TLS), pipe to /tmp on the router.
    with urllib.request.urlopen(url, timeout=300) as resp:
        data = resp.read()
    if len(data) < 512 * 1024:
        raise HTTPException(
            502, f"Firmware-Download fehlgeschlagen "
                 f"(nur {len(data)} Bytes statt ~{expected} Bytes)")
    dev.write_file(dest, data)
    size, magic = _probe_remote_image(dev, dest)
    if not _image_ok(size, magic, len(data)):
        raise HTTPException(502, "Image nach Upload auf Router ungültig")
    return {"image": dest, "via": "server", "size": size}


@app.post("/api/devices/{device_id}/firmware/check")
def api_firmware_check(device_id: int, _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    _ssh_only(row)
    dev = scheduler.make_device(row)
    try:
        res = dev.check_update()
    except Exception as exc:
        raise HTTPException(502, f"firmware check failed: {exc}")
    db.set_firmware_state(device_id, res.get("current", ""),
                          res.get("latest", ""), bool(res.get("has_update")))
    db.upsert_online(device_id, True)
    _job(device_id, "firmware",
         "update" if res.get("has_update") else "ok", json.dumps(res))
    return res


@app.post("/api/devices/{device_id}/firmware/upgrade")
def api_firmware_upgrade(device_id: int,
                         _adm: dict = Depends(require_admin),
                         url: str = "",
                         preserve_config: bool = True,
                         test_only: bool = False):
    row = _device_or_404(device_id)
    _ssh_only(row)
    dev = scheduler.make_device(row)
    try:
        if not url:
            state = db.get_firmware_state(device_id)
            if not state or not state.get("latest_version"):
                raise HTTPException(400,
                                    "kein URL und noch keine Firmware-Prüfung – "
                                    "erst /firmware/check aufrufen")
            res = dev.check_update()
            url = res.get("url", "")
            if not url:
                raise HTTPException(400, "keine gültige Image-URL ermittelt")
        db.upsert_online(device_id, True)
        if url.startswith("http://") or url.startswith("https://"):
            staged = _stage_image_on_device(dev, url)
            image = staged["image"]
        else:
            image = url
        if not test_only:
            # Paketstand vor dem Flash merken -> nach dem Reboot
            # installieren wir Fehlende zurueck (updater.finalize_manual)
            updater.snapshot_packages(device_id, dev)
        rc, out, err = dev.sysupgrade(image, preserve_config, test_only)
        if rc != 0 and "started" not in out:
            raise HTTPException(500, f"sysupgrade konnte nicht gestartet werden: {err}")
        state = db.get_firmware_state(device_id) or {}
        db.add_update_job(device_id, row["name"],
                          "done" if test_only else "running", "manual",
                          state.get("latest_version", "") if not test_only else "",
                          ("Image-Test beendet" if test_only else
                           "Update gestartet: %s (preserve=%s)" % (image, preserve_config)))
        _job(device_id, "firmware-upgrade",
             "ok" if test_only else "running",
             f"{'Test-' if test_only else ''}upgrade gestartet: {url} → {image} (preserve={preserve_config})")
        result = {"started": True, "test": test_only, "url": url, "image": image}
        if test_only:
            time.sleep(3)
            result["log"] = dev.upgrade_log()
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"upgrade failed: {exc}")


@app.post("/api/devices/{device_id}/firmware/wait")
def api_firmware_wait(device_id: int, timeout_s: int = 300,
                      _adm: dict = Depends(require_admin)):
    row = _device_or_404(device_id)
    _ssh_only(row)
    dev = scheduler.make_device(row)
    back = time.time()
    ok = wait_for_reboot(dev, wait_s=15, poll=10, timeout=min(timeout_s, 240))
    db.upsert_online(device_id, ok)
    updater.finalize_manual(device_id, ok)
    return {"online": ok, "waited_s": int(time.time() - back)}


# ------------------------------------------------------ package updates
# "Paket-Updates durchführen" aus der Detailansicht: apk/opkg upgrade läuft
# im Hintergrund-Thread (kann mehrere Minuten dauern), die UI pollt
# /packages/update/status und zeigt die Live-Ausgabe im Log-Feld.
PKG_RUNNING: set = set()
_PKG_OUT: dict = {}


def _pkg_worker(device_id: int, row: dict, job: int, names: list) -> None:
    dev = scheduler.make_device(row)
    _PKG_OUT[device_id] = ""

    def emit(chunk: str) -> None:
        _PKG_OUT[device_id] = (_PKG_OUT.get(device_id, "") + chunk)[-8000:]

    try:
        res = dev.update_packages(names or None, timeout=900,
                                  on_output=emit)
        if res.get("error"):
            msg = "Paket-Update fehlgeschlagen: %s" % res["error"]
            status = "error"
        else:
            msg = "Paket-Update abgeschlossen (rc=%s)" % res.get("rc")
            status = "done"
        db.finish_update_job(job, status, msg)
        db.add_job(device_id, "packages-update",
                   "ok" if status == "done" else "error", msg)
        # frischen Paketstand in device_info (ohne neuen Index-Refresh)
        try:
            pkg = dev.package_check(refresh=False)
            updater._store_pkg_state(device_id, pkg)
        except Exception:  # pragma: no cover
            pass
    except Exception as exc:  # pragma: no cover
        db.finish_update_job(job, "error",
                             "Paket-Update fehlgeschlagen: %s" % str(exc)[:200])
    finally:
        PKG_RUNNING.discard(device_id)


@app.post("/api/devices/{device_id}/packages/update")
def api_pkg_update(device_id: int, body: PkgUpdateIn = PkgUpdateIn(),
                   _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    _ssh_only(row)
    if device_id in PKG_RUNNING:
        raise HTTPException(409, "Paket-Update läuft bereits auf diesem Router")
    dev = scheduler.make_device(row)
    if not dev.is_online():
        db.upsert_online(device_id, False)
        raise HTTPException(502, "Router nicht erreichbar")
    db.upsert_online(device_id, True)
    names = [str(x).strip() for x in (body.names or []) if str(x).strip()]
    n = len(names)
    job = db.add_update_job(
        device_id, row["name"], "running", "manual", "",
        "Paket-Update: %s" % ("alle Pakete" if not n
                              else "%d Pakete" % n))
    db.add_job(device_id, "packages-update", "running",
               "Paket-Update gestartet%s" % (
                   ": %s" % ", ".join(names[:5]) if names else " (alle)"))
    threading.Thread(target=_pkg_worker,
                     args=(device_id, row, job, names),
                     daemon=True).start()
    PKG_RUNNING.add(device_id)
    return {"started": True, "job": job, "packages": n}


@app.get("/api/devices/{device_id}/packages/update/status")
def api_pkg_update_status(device_id: int, _u: dict = Depends(auth)):
    return {"running": device_id in PKG_RUNNING,
            "output": _PKG_OUT.get(device_id, "")}


# ------------------------------------------------------------- backups


@app.post("/api/devices/{device_id}/config/backup")
def api_config_backup(device_id: int, _u: dict = Depends(auth)):
    """Erstellt auf dem Router ein tar.gz von /etc/config und lädt es herunter."""
    row = _device_or_404(device_id)
    _ssh_only(row)
    dev = scheduler.make_device(row)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    remote = f"/tmp/owfb-{ts}.tar.gz"
    try:
        dev.run(f"tar -czf {remote} -C /etc config 2>/dev/null || "
                f"tar -czf {remote} /etc/config", timeout=60)
        blob = dev.read_file(remote)
        local = os.path.join(BACKUP_DIR, f"{row['name']}-{ts}-config.tar.gz")
        with open(local, "wb") as fh:
            fh.write(blob)
        size = os.path.getsize(local)
        dev.run(f"rm -f {remote}")
    except Exception as exc:
        raise HTTPException(502, f"backup failed: {exc}")
    did = db.add_backup(device_id, os.path.basename(local), size)
    _job(device_id, "backup", "ok", os.path.basename(local))
    return {"id": did, "filename": os.path.basename(local), "size": size}


@app.get("/api/devices/{device_id}/config/backups")
def api_config_backups(device_id: int, _u: dict = Depends(auth)):
    _device_or_404(device_id)
    return db.list_backups(device_id)


@app.get("/api/config/backups/{backup_id}/download")
def api_backup_download(backup_id: int, _u: dict = Depends(auth)):
    with db.get_db() as conn:
        row = conn.execute(
            "SELECT * FROM config_backups WHERE id=?", (backup_id,)).fetchone()
    if not row:
        raise HTTPException(404, "backup not found")
    path = os.path.join(BACKUP_DIR, row["filename"])
    if not os.path.exists(path):
        raise HTTPException(410, "backup file missing")
    return FileResponse(path, filename=row["filename"],
                        media_type="application/gzip")


@app.post("/api/devices/{device_id}/config/restore")
async def api_config_restore(device_id: int,
                               _adm: dict = Depends(require_admin),
                             file: UploadFile = File(...),
                             restart: bool = Form(False)):
    """Stellt ein vorheriges /etc/config tar.gz auf dem Router wieder her."""
    row = _device_or_404(device_id)
    _ssh_only(row)
    dev = scheduler.make_device(row)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    remote = f"/tmp/owfr-{ts}.tar.gz"
    data = await file.read()
    if len(data) < 10 or data[:2] != b"\x1f\x8b":
        raise HTTPException(400, "kein gültiges gzip")
    try:
        dev.write_file(remote, data)
        rc, out, err = dev.run(
            f"tar -xzf {remote} -C /etc && rm -f {remote}"
            + (" && /etc/init.d/network restart" if restart else ""))
        if rc != 0:
            raise HTTPException(500, f"restore failed: {err or out}")
        _job(device_id, "restore", "ok", file.filename)
        return {"ok": True, "restarted": restart}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"restore failed: {exc}")


# -------------------------------------------------------- central config


@app.post("/api/central/apply")
def api_central_apply(req: CentralApply, _adm: dict = Depends(require_admin)):
    """Wendet uci-Werte zentral auf eine Gruppe von Routern an."""
    if not req.device_ids:
        raise HTTPException(400, "no devices selected")
    if not req.assignments:
        raise HTTPException(400, "no assignments")
    results = []
    for did in req.device_ids:
        row = db.get_device(did)
        if not row:
            results.append({"device": did, "error": "not found"})
            continue
        if _is_hp(row):
            # Switch ohne SSH: uci gibt es hier nicht
            results.append({"device": did, "name": row["name"],
                            "error": "HP 1810: kein SSH/uci – Gerät übersprungen"})
            continue
        dev = scheduler.make_device(row)
        entry = {"device": did, "name": row["name"]}
        try:
            if not dev.is_online():
                entry["error"] = "unreachable"
                results.append(entry)
                continue
            if req.backup_before:
                remote = f"/tmp/owfc-{uuid.uuid4().hex[:8]}.tar.gz"
                dev.run(f"tar -czf {remote} -C /etc config 2>/dev/null", timeout=60)
                entry["backup"] = remote
            cmds = [f"uci set {shlex.quote(a.key)}={shlex.quote(a.value)}"
                    for a in req.assignments]
            if req.commit:
                cmds.append("uci commit")
            script = " && ".join(cmds)
            rc, out, err = dev.run(script, timeout=60)
            if rc != 0:
                entry["error"] = (err or out).strip()[:500]
            else:
                entry["ok"] = True
                entry["applied"] = [a.key for a in req.assignments]
        except Exception as exc:
            entry["error"] = str(exc)
        results.append(entry)
    db.add_central(device_id=req.device_ids[0],
                   payload_json=json.dumps(
                       {"assignments": [{"key": a.key, "value": a.value}
                                        for a in req.assignments],
                        "commit": req.commit,
                        "backup_before": req.backup_before,
                        "devices": req.device_ids}),
                   result_json=json.dumps(results))
    _job(req.device_ids[0], "central", "ok",
         f"{len(req.assignments)} keys -> {len(req.device_ids)} devices")
    return {"results": results}


@app.get("/api/central/history")
def api_central_history(limit: int = 50, _u: dict = Depends(auth)):
    return db.list_central(limit)


@app.get("/api/jobs")
def api_jobs(limit: int = 100, _u: dict = Depends(auth)):
    return db.list_jobs(limit)


@app.get("/api/update-jobs")
def api_update_jobs(limit: int = 100, _u: dict = Depends(auth)):
    return db.list_update_jobs(limit)


@app.post("/api/update-jobs/run")
def api_update_jobs_run(device_id: int = 0,
                        _adm: dict = Depends(require_admin)):
    """Update-Pruefung (und ggf. Auto-Update) sofort im Hintergrund starten."""
    ids = [device_id] if device_id else [d["id"] for d in db.list_devices()]
    if device_id:
        _ssh_only(_device_or_404(device_id))
    else:
        ids = [i for i in ids if not _is_hp(db.get_device(i) or {})]
    _job(None, "update-check", "running", "sofortiger Update-Check (%d Router)" % len(ids))
    threading.Thread(target=updater.run_checks, args=(ids,), daemon=True).start()
    return {"started": True, "devices": len(ids)}


# ------------------------------------------------------- survey & actions


@app.post("/api/devices/{device_id}/survey")
def api_device_survey(device_id: int, _u: dict = Depends(auth)):
    row = _device_or_404(device_id)
    if (row.get("kind") or "openwrt") == "hp1810":
        # Switch ohne SSH: kein Survey; LLDP/MAC-Tabelle laufen über poll_lldp
        scheduler.poll_lldp(device_id)
        return {"ok": True, "note": "HP Switch – Port-Belegung aktualisiert"}
    res = scheduler.survey_device(device_id)
    if res is None:
        raise HTTPException(502, "Router nicht erreichbar – bitte SSH-Daten prüfen")
    return res


@app.post("/api/devices/{device_id}/reboot")
def api_device_reboot(device_id: int, _adm: dict = Depends(require_admin)):
    row = _device_or_404(device_id)
    if (row.get("kind") or "openwrt") == "hp1810":
        raise HTTPException(400, "HP 1810: Reboot nicht über Web-Interface verfügbar")
    dev = scheduler.make_device(row)
    try:
        dev.reboot()
    except Exception as exc:
        raise HTTPException(502, f"reboot failed: {exc}")
    db.add_job(device_id, "reboot", "ok", "Reboot befohlen")
    return {"ok": True}


@app.post("/api/devices/{device_id}/rename")
def api_device_rename(device_id: int, name: str,
                      _u: dict = Depends(require_admin)):
    _device_or_404(device_id)
    name = name.strip()
    if not name or len(name) > 64:
        raise HTTPException(400, "Ungültiger Name")
    db.rename_device(device_id, name)
    info = db.get_device_info(device_id) or {}
    info["manual"] = True   # manual name: stop auto-rename
    db.upsert_device_info(device_id, json.dumps(info))
    return {"ok": True, "name": name}


# ------------------------------------------------------ dashboard & search


@app.get("/api/dashboard")
def api_dashboard(_u: dict = Depends(auth)):
    devices = db.list_devices()
    out = {"routers": [], "ssids": [], "channels": [],
           "totals": {"routers": len(devices), "online": 0,
                      "clients_lan": 0, "clients_wlan": 0}}
    for d in devices:
        st = db.last_check(d["id"])
        status = {"online": bool(st[0]), "checked_at": st[1]} if st \
            else {"online": False, "checked_at": None}
        info = db.get_device_info(d["id"]) or {}
        lan = db.list_clients(d["id"], "lan")
        wlan = db.list_clients(d["id"], "wlan")
        online = bool(status.get("online"))
        out["totals"]["online"] += online
        out["totals"]["clients_lan"] += len(lan)
        out["totals"]["clients_wlan"] += len(wlan)
        for c in wlan:
            ch = c.get("channel")
            band = c.get("band") or ""
            if ch:
                out["channels"].append({"router": d["name"], "ssid":
                                        c.get("ssid") or c.get("iface") or "",
                                        "channel": ch, "band": band})
        out["routers"].append({
            "id": d["id"], "name": d["name"], "ip": d["ip"],
            "online": online,
            "uptime_s": (info or {}).get("uptime_s"),
            "model": (info or {}).get("model"),
            "version": (info or {}).get("version"),
            "rx_bps": (info or {}).get("rx_bps"),
            "tx_bps": (info or {}).get("tx_bps"),
            "clients_lan": len(lan), "clients_wlan": len(wlan),
            "last_seen": status.get("checked_at"),
        })
    # SSIDs + channels from survey cache
    try:
        snaps = db.list_snapshots_all(since_hours=48)
    except Exception:
        snaps = []
    seen = {}
    for s in snaps:
        try:
            for ssid in json.loads(s.get("ssids_json") or "[]"):
                key = (s["device_name"], ssid.get("ssid"),
                       ssid.get("channel"), ssid.get("band"))
                seen[key] = {"router": s["device_name"],
                             "ssid": ssid.get("ssid"),
                             "channel": ssid.get("channel"),
                             "band": ssid.get("band"),
                             "clients": ssid.get("clients", 0)}
        except Exception:
            continue
    out["ssids"] = list(seen.values())
    # Pie: Clients pro WLAN-Kanal — über alle SSIDs eines (Band, Kanal) aufsummiert
    chan_usage = {}
    for v in seen.values():
        ch = v["channel"]
        if ch is None:
            continue
        key = (v["band"], ch)
        e = chan_usage.setdefault(key, {"band": v["band"], "channel": ch, "clients": 0})
        e["clients"] += v.get("clients") or 0
    out["channel_usage"] = sorted(chan_usage.values(), key=lambda x: -x["clients"])
    out["channels"] = [{"router": v["router"], "ssid": v["ssid"],
                        "channel": v["channel"], "band": v["band"],
                        "clients": v["clients"]} for v in seen.values()]
    # dedupe by (router, channel) for occupied-channel table
    occ = {}
    for c in out["channels"]:
        occ[(c["router"], c["channel"])] = c
    out["channels"] = sorted(occ.values(),
                             key=lambda x: (x["band"], int(x["channel"] or 0)))
    return out


@app.get("/api/history/{device_id}")
def api_history(device_id: int, hours: int = 24, _u: dict = Depends(auth)):
    _device_or_404(device_id)
    return db.list_snapshots(device_id, since_hours=hours)


@app.get("/api/search")
def api_search(q: str, _u: dict = Depends(auth)):
    q = (q or "").strip()
    if len(q) < 2:
        return []
    return db.search_clients(q)


@app.get("/api/clients")
def api_all_clients(_u: dict = Depends(auth)):
    """Alle Clients (LAN + WLAN) aller Geräte mit Gerätename, SSID und Kanal."""
    devices = db.list_devices()
    name_of = {d["id"]: d.get("name") or d.get("ip", "") for d in devices}
    # device_id -> {ssid: channel} (aus dem letzten Survey, device_info)
    chan_of = {}
    for d in devices:
        info = db.get_device_info(d["id"]) or {}
        m = {}
        for it in info.get("interfaces") or []:
            if it.get("ssid"):
                m[it["ssid"]] = it.get("channel", "")
        chan_of[d["id"]] = m
    out = []
    for d in devices:
        for kind in ("wlan", "lan"):
            for c in db.list_clients(d["id"], kind):
                if kind == "wlan":
                    ssid = c.get("iface", "")
                    chan = chan_of.get(d["id"], {}).get(ssid, "")
                else:
                    ssid, chan = "", ""
                out.append({
                    "device": d.get("name", ""),
                    "dev_ip": d.get("ip", ""),
                    "kind": kind,
                    "mac": c.get("mac", ""),
                    "hostname": c.get("hostname", ""),
                    "ssid": ssid,
                    "channel": chan,
                    "signal": c.get("signal") or "",
                })
    out.sort(key=lambda x: (x["device"], x["kind"], x["mac"]))
    return out


# ------------------------------------------------------------- LLDP / topology
def _lldp_node(device_id: int, row: dict) -> dict:
    """Lokales Chassis + Nachbarn eines Geräts für die Topologieansicht."""
    local = db.lldp_local(device_id) or {}
    neighbors = db.lldp_neighbors(device_id)
    # Nachbarn identifizieren: ist der Nachbar ein bekanntes Gerät
    # (Name aus LLDP oder MAC = lokales Chassis eines bekannten Geräts)?
    known = db.list_devices()
    by_name = {(d.get("name") or "").lower(): d for d in known}
    by_mac = {}
    for d in known:
        m = (db.lldp_local(d["id"]) or {}).get("mac") or ""
        if m:
            by_mac[m.lower()] = d
    for n in neighbors:
        n["local_port"] = n.get("iface") or ""
        n["neighbor_port"] = n.get("port_id") or n.get("port_descr") or ""
        peer = None
        label = (n.get("neighbor_name") or "").strip().lower()
        if label:
            peer = by_name.get(label)
        if not peer and n.get("mac"):
            peer = by_mac.get(n["mac"].lower())
        n["peer_device_id"] = peer["id"] if peer else None
        n["is_known"] = bool(peer)
        n["peer_name"] = peer["name"] if peer else (
            n.get("neighbor_name") or n.get("hostname") or n.get("mgmt_ip") or "unbekannt")
    return {
        "device_id": device_id,
        "name": row.get("name", ""),
        "ip": row.get("ip", ""),
        "state": row.get("state", "unknown"),
        "lldpd": local.get("lldpd") or "unknown",
        "version": local.get("version") or "",
        "error": local.get("error") or "",
        "local": {
            "chassis_id": local.get("chassis_id") or "",
            "mac": local.get("mac") or "",
            "name": local.get("name") or "",
            "descr": local.get("descr") or "",
            "mgmt_ip": local.get("mgmt_ip") or "",
            "updated_at": local.get("updated_at") or "",
        },
        "neighbors": neighbors,
        "fdb": _fdb_view(device_id),
    }


def _client_mac_map() -> dict:
    """MAC -> (hostname, ip) aus allen erfassten Clients (ARP/WLAN).

    Das ist die „MAC-Tabelle“: ARP-/DHCP-Einträge aller Router liefern pro
    MAC-Adresse den bekannten Rechnernamen — zuverlässiger als ein PTR-Name."""
    m = {}
    for d in db.list_devices():
        for kind in ("lan", "wlan"):
            for c in db.list_clients(d["id"], kind):
                mac = (c.get("mac") or "").lower()
                if not mac:
                    continue
                host = (c.get("hostname") or "").strip()
                ip = (c.get("ip") or "").strip()
                if mac not in m or (not m[mac][0] and host):
                    m[mac] = (host, ip)
    return m


def _client_label_map() -> dict:
    """MAC -> (hostname, ip, ssid) aus allen erfassten Clients (LAN + WLAN).

    Wie ``_client_mac_map``, nimmt zusätzlich die SSID mit — für die
    FDB-Belegung pro Port, damit WLAN-Stationen mit ihrem Netzwerk
    beschriftet werden.
    """
    m = {}
    for d in db.list_devices():
        for kind in ("lan", "wlan"):
            for c in db.list_clients(d["id"], kind):
                mac = (c.get("mac") or "").lower()
                if not mac:
                    continue
                host = (c.get("hostname") or "").strip()
                ip = (c.get("ip") or "").strip()
                ssid = (c.get("ssid") or "").strip()
                if mac not in m or (not m[mac][0] and host):
                    m[mac] = (host, ip, ssid)
    return m


def _fdb_view(device_id: int, label_map: dict | None = None) -> dict:
    """Bridge-FDB als Port-Belegung pro Gerät für die Topologieansicht.

    Gruppiert die gespeicherten FDB-Einträge nach Bridge und Port (Port-
    Nummer aus brctl + Port-Name aus sysfs) und beschriftet jede MAC über
    die Client-MAC-Tabelle (Hostname/IP/SSID) — so wird aus der nackten
    MAC-Adresse „wer hängt an welchem Port“."""
    rows = db.fdb(device_id)
    if not rows:
        return {"bridges": [], "updated_at": ""}
    if label_map is None:
        label_map = _client_label_map()
    bridges: dict = {}
    order: list = []
    updated = ""
    for r in rows:
        br = r.get("bridge") or "br-lan"
        if br not in bridges:
            bridges[br] = {}
            order.append(br)
        bports = bridges[br]
        key = (r.get("port"), r.get("port_name") or "")
        if key not in bports:
            bports[key] = []
        mac = (r.get("mac") or "").lower()
        hm = label_map.get(mac)
        host = hm[0] if hm else ""
        ip = hm[1] if hm else ""
        ssid = hm[2] if hm else ""
        bports[key].append({
            "mac": mac,
            "hostname": host,
            "ip": ip,
            "ssid": ssid,
            "named": bool(host),
        })
        sa = r.get("seen_at") or ""
        if sa > updated:
            updated = sa
    out_bridges = []
    for br in order:
        ports = []
        for (port, pname) in sorted(bridges[br], key=lambda k: k[0]):
            ports.append({"port": port, "port_name": pname,
                          "clients": bridges[br][(port, pname)]})
        out_bridges.append({"bridge": br, "ports": ports})
    return {"bridges": out_bridges, "updated_at": updated}


def _enrich_neighbors(nodes: list) -> list:
    """Unbekannte Nachbarn per MAC-Tabelle und Reverse-DNS anreichern.

    - MAC -> Rechnername aus den erfassten Clients (ARP/WLAN-MAC-Tabelle)
    - mgmt_ip ohne Namen -> Reverse-DNS (PTR-Lookup)
    Ergebnis landet in ``hostname`` + ``name_source``; peer_name folgt daraus."""
    mac_map = _client_mac_map()
    for node in nodes:
        for n in node["neighbors"]:
            name_source = n.get("name_source") or ""
            mac = (n.get("mac") or "").lower()
            # 1) MAC -> Hostname aus der MAC-Tabelle (Clients)
            if mac and mac in mac_map and mac_map[mac][0]:
                n["hostname"] = mac_map[mac][0]
                name_source = "clients"
            # 2) Reverse-DNS der Management-IP, falls sonst kein Name bekannt
            ip = (n.get("mgmt_ip") or "").strip()
            if ip and not (n.get("hostname") or (n.get("neighbor_name") or "")):
                try:
                    rdn = socket.gethostbyaddr(ip)[0]
                    if rdn:
                        n["hostname"] = rdn
                        name_source = "dns"
                except (socket.herror, socket.gaierror, OSError):
                    pass
            n["name_source"] = name_source
            # peer_name für unbekannte Geräte ggf. durch den aufgelösten Namen
            if not n["is_known"]:
                n["peer_name"] = (
                    n.get("hostname") or n.get("neighbor_name")
                    or n.get("mgmt_ip") or "unbekannt")
    return nodes


@app.get("/api/topology")
def api_topology(_u: dict = Depends(auth)):
    """Aggregierte Topologie (UniFi-artig) für die Graph-View.

    Jedes Gerät inkl. lokalem Chassis + Nachbarn (bereits identifiziert,
    ob der Nachbar ein bekanntes Gerät ist oder nicht; unbekannte Nachbarn
    sind per MAC-Tabelle / Reverse-DNS mit Hostnamen angereichert)."""
    nodes = []
    for d in db.list_devices():
        nodes.append(_lldp_node(d["id"], d))
    return {"devices": _enrich_neighbors(nodes)}


@app.get("/api/devices/{device_id}/lldp")
def api_lldp(device_id: int, _u: dict = Depends(auth)):
    """LLDP-Daten (lokal + Nachbarn) eines einzelnen Geräts, unbekannte
    Nachbarn per MAC-Tabelle / Reverse-DNS angereichert."""
    row = _device_or_404(device_id)
    return _enrich_neighbors([_lldp_node(device_id, row)])[0]


@app.post("/api/devices/{device_id}/lldp/scan")
def api_lldp_scan(device_id: int, _u: dict = Depends(auth)):
    """LLDP sofort neu pollen (ohne auf den 2-min-Timer zu warten)."""
    row = _device_or_404(device_id)
    scheduler.poll_lldp(device_id)
    return _lldp_node(device_id, row)


@app.post("/api/devices/{device_id}/lldp/activate")
def api_lldp_activate(device_id: int, _u: dict = Depends(auth)):
    """lldpd auf dem Router (ggf. nach apk add) starten — bleibt nach Reboot aktiv."""
    row = _device_or_404(device_id)
    if (row.get("kind") or "openwrt") == "hp1810":
        # Switch meldet LLDP nativ; kein lldpd nötig
        scheduler.poll_lldp(device_id)
        return {"ok": True, "output": "HP 1810 – LLDP nativ aktiv, neu gepollt"}
    dev = scheduler.make_device(row)
    if not dev.is_online():
        raise HTTPException(502, "Router nicht erreichbar")
    try:
        res = dev.activate_lldp()
    except Exception as exc:
        raise HTTPException(502, "lldpd-Aktivierung fehlgeschlagen: %s" % exc)
    db.add_job(device_id, "lldp", "ok" if res.get("ok") else "error",
               ("lldpd aktiviert" if res.get("ok") else "Aktivierung fehlerhaft")
               + ": " + (res.get("output") or "")[:120])
    # direkt nachpollen, damit die neue Topologie sichtbar ist
    scheduler.poll_lldp(device_id)
    return res


@app.get("/health")
def health():
    return {"ok": True, "devices": len(db.list_devices())}
