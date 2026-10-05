"""HP 1810-24G / ProCurve (Vitesse) Web-Interface collector.

Diese Switches haben kein SSH, nur ein Web-Interface mit Passwort (kein
Benutzername in der UI intern 'admin').  Das Login-Modell wird vom Browser-JS
berechnet, nicht vom Server gesetzt, deshalb muss der Collector die
Browser-Session nachbauen:

  - GET /config/login?deviceid=<base64("admin:"+password)>
  - Cookie  deviceid=<base64(...)>  und  seid=<zufall>
  - Header  CsrfToken=<gleiches wie seid>  und Query  sid=<seid>
  - ein ``sesslid``-Cookie ueber HTTP bricht den Login -> weglassen.

Alle Daten-Endpunkte antworten mit '|'-getrennten Records, deren Felder '/'-
getrennt sind.  Die Antworten koennen gzip-komprimiert sein.
"""
from __future__ import annotations

import base64
import gzip
import io
import random
import urllib.error
import urllib.request

EP_NEIGHBORS = "/config/lldp_neighbors"
EP_STATS = "/config/lldp_statistics"
EP_MAC = "/config/dynamic_mac_table"
EP_STP = "/stat/rstp_status_bridge"

MAC_FIELD_OFFSET = 3   # MAC/Flags/Flags + 26 Port-Felder  (Port = Index - 3)
MAC_PORT_COUNT = 26    # 24 GbE + 2 SFP


def _gunzip(raw: bytes) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except OSError:
            return raw
    return raw


def _fields(rec: str) -> list:
    """LLDP-Records trennen '/', MAC-Tabelle '/'. Rueckgabe wie original."""
    return [x.strip() for x in rec.split("/")]


def parse_lldp_neighbors(raw: str) -> list:
    """Port?chassis-id?sys-name?port-id?caps?caps-avail?mgmt-ip|..."""
    out = []
    for rec in (raw or "").split("|"):
        f = rec.split("?")
        if len(f) < 7 or not f[0].strip():
            continue
        # f[0]="Port 4" -> iface name
        iface = f[0].strip()
        port_no = "".join(ch for ch in iface if ch.isdigit())
        chassis = (f[1] or "").strip().upper()
        mgmt = (f[7] or "").split("¤")[0].strip()
        out.append({
            "iface": iface,
            "iface_short": ("lan%s" % port_no) if port_no else iface,
            "mac": (f[2] or "").strip().replace("-", ":").lower(),
            "chassis_id": (f[1] or "").strip(),
            "sys_name": (f[3] or "").strip(),
            "port_id": (f[4] or "").strip(),
            "sys_desc": (f[5] or "").strip(),
            "mgmt_ip": mgmt,
        })
    return out


def parse_mac_table(raw: str) -> list:
    """[{mac, ports:[...]}] - Spalten-Index minus 3 = Schalter-Port (1-basiert)."""
    rows = []
    recs = [r for r in (raw or "").split("|") if r.strip()]
    for rec in recs[1:]:                      # recs[0] = Header "anzahl/alter"
        f = rec.split("/")
        if len(f) < MAC_FIELD_OFFSET + 1:
            continue
        ports = [i - MAC_FIELD_OFFSET for i, x in enumerate(f)
                 if x.strip() == "1"]
        ports = [p for p in ports if 1 <= p <= MAC_PORT_COUNT]
        if ports:
            canon = "".join(ch for ch in f[0] if ch in "0123456789abcdefABCDEF")
            if len(canon) == 12:
                canon = ":".join(canon[i:i+2] for i in range(0, 12, 2)).lower()
            else:
                canon = f[0].strip().lower()
            rows.append({"mac": canon, "ports": ports})
    return rows


def parse_lldp_stats(raw: str) -> list:
    """port/TX/RX/Errors/Discarded/...  (JS-Label: pval[1]=TX pval[2]=RX pval[3]=Errors pval[4]=Discarded)."""
    out = []
    for rec in (raw or "").split("|"):
        f = _fields(rec)
        if len(f) < 5 or not f[0].isdigit():
            continue
        def _i(v):
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0
        out.append({
            "port": int(f[0]),
            "frames_tx": _i(f[1]),
            "frames_rx": _i(f[2]),
            "errors": _i(f[3]),
            "discarded": _i(f[4]),
            "extra": f[5:],
        })
    return out


def parse_stp(raw: str) -> dict:
    """rstp_status_bridge -> {bridge: {...}, ports: [...]}."""
    recs = (raw or "").split("|")
    bridge = {}
    ports = []
    if recs and recs[0].strip():
        f = _fields(recs[0])
        bridge = {
            "enabled": f[0] if len(f) > 0 else "",
            "protocol": f[1] if len(f) > 1 else "",
            "bridge_id": f[2] if len(f) > 2 else "",
            "priority": f[3] if len(f) > 3 else "",
            "hello_time": f[4] if len(f) > 4 else "",
            "max_age": f[5] if len(f) > 5 else "",
            "fwd_delay": f[6] if len(f) > 6 else "",
            "raw": f,
        }
    for rec in recs[1:]:
        f = _fields(rec)
        if len(f) < 6 or not f[0].isdigit():
            continue
        ports.append({
            "switch_id": int(f[0]),
            "port": int(f[1]) if f[1].isdigit() else None,
            "port_id": f[2],
            "role": f[3],
            "state": f[4],
            "cost": f[5],
            "raw": f,
        })
    return {"bridge": bridge, "ports": ports}


class HpSwitch:
    """Ein HP 1810 / ProCurve Switch ueber das Web-Interface."""

    def __init__(self, name: str, ip: str, password: str, port: int = 80) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self._pw = password or ""
        self._deviceid = base64.b64encode(("admin:" + self._pw).encode()).decode()
        self._seid = ""

    # --- session -----------------------------------------------------------
    def _headers(self) -> dict:
        return {
            "Cookie": "deviceid=%s; seid=%s" % (self._deviceid, self._seid),
            "CsrfToken": self._seid,
            "If-Modified-Since": "0",
            "Referer": "http://%s/index.htm" % self.ip,
            "User-Agent": "openwrt-fleet/1.0",
        }

    def _get(self, path: str) -> str:
        sep = "&" if "?" in path else "?"
        url = "http://%s:%d%s%s%s=%s" % (self.ip, self.port, path, sep,
                                         "sid", self._seid)
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = _gunzip(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("login expired (HTTP 401)") from e
            raise RuntimeError("HTTP %s on %s" % (e.code, path)) from e
        except Exception as e:
            raise RuntimeError("%s: %s" % (type(e).__name__, str(e)[:160])) from e
        return raw.decode("utf-8", "replace").replace("\ufffd", "\xa4")

    def login(self) -> None:
        self._seid = str(random.randint(100000000, 999999999))
        text = self._get("/config/login?deviceid=" + self._deviceid)
        if self._deviceid not in text:
            raise RuntimeError("login rejected (no deviceid echo)")

    def is_online(self) -> bool:
        try:
            self.login()
            return True
        except Exception:
            return False

    # --- polling -----------------------------------------------------------
    def poll(self) -> dict:
        """Holt Nachbarn, MAC-Tabelle, LLDP-Stats und RSTP.  Fehler pro
        Endpunkt werden gesammelt, aber ein Login-Fehler kuerzt ab."""
        out = {"lldp_neighbors": [], "mac_table": [], "lldp_stats": [],
               "stp": {}, "errors": []}
        try:
            self.login()
        except Exception as e:
            out["errors"].append("login: %s" % str(e)[:160])
            return out
        for key, path in (("lldp_neighbors", EP_NEIGHBORS),
                          ("mac_table", EP_MAC),
                          ("lldp_stats", EP_STATS),
                          ("stp", EP_STP)):
            try:
                txt = self._get(path)
                if key == "stp":
                    out[key] = parse_stp(txt)
                elif key == "lldp_neighbors":
                    out[key] = parse_lldp_neighbors(txt)
                elif key == "mac_table":
                    out[key] = parse_mac_table(txt)
                else:
                    out[key] = parse_lldp_stats(txt)
            except Exception as e:
                out["errors"].append("%s: %s" % (key, str(e)[:160]))
        return out