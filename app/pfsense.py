# -*- coding: utf-8 -*-
"""pfSense firewall collector via the webConfigurator (HTTPS, no SSH).

pfSense-Geraete werden hier ausschliesslich ueber das Web-Interface
(webConfigurator, Standard 443) angesprochen — es gibt keinen SSH-Zugang.
Der Collector baut eine Browser-Session mit urllib nach:

  - GET  /index.php      -> Login-Page, CSRF-Token aus dem Hidden-Input
                            ``__csrf_magic`` (``sid:...:time:...:hash:...``)
  - POST /index.php      -> username, password, __csrf_magic, loginAttempts
                            -> Redirect in die Session (Cookie ``pfSession``)

pfSense nutzt in LANs typischerweise selbstsignierte Zertifikate, daher
werden TLS-Zertifikate NICHT verifiziert (ssl._create_unverified_context).

Alle Methoden, die der Scheduler (scheduler.py / updater.py / main.py)
vom sshx-Layer kennt, liefern die gleichen Namen und Return-Formen:

  is_online()        -> bool
  model_name()       -> str
  full_info()        -> dict   (version, kind='pfsense', no_ssh, ...)
  survey()           -> dict   (full_info + hostname, clients, interfaces)
  check_update()     -> dict   (pfSense hat keinen maschinenlesbaren Feed)
  package_check()    -> dict   (kein opkg — immer leer)
  poll_lldp()        -> dict   (Base-Form, per Web nur ARP/Besteffort)
  poll_fdb()         -> dict   (Base-Form, per Web nicht verfuegbar)

Alles ist defensiv geparsed (Regex + try/except): unerwartete Ausgabe
liefert Besteffort-Strukturen mit ``error``, nie eine Exception.
Nur Python-Standardbibliothek (urllib, ssl, http.cookiejar, re, html.parser).
"""
from __future__ import annotations

import http.cookiejar
import html.parser
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------------------------------------------ parser
# Version auf der Dashboard-Page: pfSense zeigt z.B.
#   "pfSense 2.7.2", "<b>Version 2.7.2</b>", "pfSense 2.7.2-RELEASE"
_VERSION_RES = (
    re.compile(r"pfSense[\s\-_v]*(\d+\.\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"\bVersion[\s:_]+(\d+\.\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\s*(?:-RELEASE\b|-RELEASE\s)"),
)
_HOSTNAME_RES = (
    re.compile(r"<title[^>]*>\s*([^<]{1,80}?)\s*[:|–\-]\s*pfSense[^<]*</title>", re.I),
    re.compile(r"System\s+Hostname[^\n<]*[:>]\s*([A-Za-z0-9._\-]{1,64})", re.I),
)
_CSRF_RE = re.compile(
    r"<input[^>]+name=[\"']__csrf_magic[\"'][^>]+value=[\"']([^\"']+)[\"']", re.I)


class _CSRFParser(html.parser.HTMLParser):
    """Robuster Fallback-Parser: holt value aus <input name=__csrf_magic>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.value = ""

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        d = dict(attrs)
        if d.get("name") == "__csrf_magic" and d.get("value"):
            self.value = d["value"]


def _extract_csrf(html_text: str) -> str:
    """CSRF-Token aus der Login-Page (Regex, Fallback html.parser)."""
    m = _CSRF_RE.search(html_text)
    if m:
        return m.group(1)
    try:
        p = _CSRFParser()
        p.feed(html_text)
        return p.value
    except Exception:
        return ""


# ------------------------------------------------------------------- class
class PfSense:
    """Ein pfSense-Firewall ueber das webConfigurator (HTTPS).

    Gleiche Konstruktor-Argumente wie sshx.OpenWRT (ip, port, user,
    password, firmware_dir, timeout, ssh_key, auth_mode,
    ssh_key_passphrase) — die SSH-spezifischen werden bewusst ignoriert.
    Port 22 (SSH-Default aus der Geraetetabelle) wird automatisch auf den
    Web-Port 443 umgebogen.
    """

    def __init__(self, ip: str, port: int = 22, user: str = "root",
                 password: str = "", firmware_dir: str = "",
                 timeout: int = 15, ssh_key: str = "",
                 auth_mode: str = "password",
                 ssh_key_passphrase: str = "") -> None:
        self.ip = ip
        # SSH-Default 22 ist fuer das Web-Interface sinnlos -> 443
        self.port = int(port or 443)
        if self.port == 22:
            self.port = 443
        self.user = user
        self.password = password
        self.firmware_dir = firmware_dir or ""
        self.timeout = timeout
        # Toleranter Port-Aufbau: "192.168.1.1:4444" in der IP-Spalte.
        if ip.count(":") == 1:
            h, p = ip.split(":", 1)
            if p.isdigit() and h:
                self.ip = h.strip()
                if (port in (None, 0, 22) or p != str(port)):
                    port = int(p)
                ip = self.ip
        self.ip = ip
        self.port = int(port or 443)
        # SSH-Felder bewusst aufbewahrt, aber NICHT genutzt (Web-basiert):
        self.ssh_key = ssh_key or ""
        self.auth_mode = auth_mode or "password"
        self.ssh_key_passphrase = ssh_key_passphrase or ""

        self._ctx = ssl._create_unverified_context()
        self._opener = self._make_opener()
        self._logged_in = False
        self._last_version = ""

    # ------------------------------------------------------------- session
    def _make_opener(self) -> urllib.request.OpenerDirector:
        """Opener mit Cookie-Jar + unverified TLS + Browser-User-Agent."""
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=self._ctx),
        )
        self._jar = jar
        return opener

    def _url(self, path: str) -> str:
        return "https://%s:%d%s" % (self.ip, self.port, path)

    def _request(self, path: str, data: dict | None = None,
                 timeout: int | None = None) -> tuple[int, str, str]:
        """GET/POST gegen das webConfigurator.

        Liefert (status, body, error). status=-1 bei Verbindungs-/Zeit-
        fehlern; HTTP 4xx/5xx als status (body darf gefuellt sein).
        Redirects werden automatisch gefolgt (Cookie-Session).
        """
        url = self._url(path)
        body = None
        headers = {"User-Agent": "Mozilla/5.0 (openwrt-fleet) pfSense/1.0",
                   "Accept": "text/html,application/xhtml+xml"}
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with self._opener.open(req,
                                   timeout=timeout or self.timeout) as r:
                raw = r.read()
                return r.status, raw.decode("utf-8", "replace"), ""
        except urllib.error.HTTPError as e:
            # Redirects koennen je Build 302/303 sein; die liefert urllib
            # in der Regel selbst, HTTPError heisst hier also echtes Fehler.
            try:
                raw = e.read()
            except Exception:
                raw = b""
            return e.code, raw.decode("utf-8", "replace"), ""
        except Exception as e:
            return -1, "", "%s: %s" % (type(e).__name__, str(e)[:160])

    def _login(self) -> tuple[bool, str]:
        """Login absetzen; True bei Session (pfSession-Cookie / Dashboard)."""
        status, html_text, err = self._request("/index.php")
        if status not in (200, 302, 303) or not html_text:
            # bereits eingeloggt (Session-Cookies ueberlebt)?
            if self._jar and any(c.name == "pfSession"
                                 for c in self._jar):
                return True, ""
            return False, err or ("HTTP %s beim Login-GET" % status)
        csrf = _extract_csrf(html_text)
        if not csrf:
            # ev. schon authentifizierte Seite (Session von frueher)
            if "pfSession" in " ".join(c.name for c in self._jar):
                return True, ""
            return False, "kein CSRF-Token in der Login-Page gefunden"
        data = {
            "login_attempts": "1",
            "usernamefld": self.user,
            "passwordfld": self.password,
            "login": "Anmelden",
            "__csrf_magic": csrf,
        }
        status2, html2, err2 = self._request("/index.php", data=data,
                                             timeout=max(self.timeout, 30))
        probe = (html2 or "").lower()
        # Echte Erfolgs-/Miss marker: Login-Seite hat keinen Logout/Dashboard;
        # abgelehnte Zugangsdaten zeigen 'auth_failure'/'wrong password'.
        if any("auth_fail" in probe or "wrong password" in probe
               for _ in [1]):
            return False, "Login abgelehnt (falsche Zugangsdaten?)"
        ok = ("logout" in probe) or ("dashboard" in probe) \
            or ("system_information" in probe) or ("pfcontrol" in probe)
        try:
            ok = ok or any(c.name == "pfSession" for c in self._jar)
        except Exception:
            pass
        if not ok:
            return False, ("Login abgelehnt (falsche Zugangsdaten?)"
                           + (((" | " + err2) if err2 else ""))
                           + ((" | Titel: " + (re.search(r"<title>(.*?)</title>", html2, re.I) or ["?"])[1]) if html2 else ""))
        return True, ""

    def _get(self, path: str) -> tuple[bool, str]:
        """Seiten-GET innerhalb der Session; (ok, body)."""
        status, body, err = self._request(path)
        if status == 200 and body:
            return True, body
        # ev. Session abgelaufen -> ein neuer Login-Versuch
        self._logged_in = False
        ok, _e = self._login()
        if ok:
            status, body, err = self._request(path)
            if status == 200 and body:
                return True, body
        return False, err or ("HTTP %s auf %s" % (status, path))

    # ------------------------------------------------------------ metadata
    def is_online(self) -> bool:
        """Erreichbarkeit des Web-Interfaces (kurzes Timeout, ~10 s)."""
        try:
            status, _body, _err = self._request("/index.php", timeout=10)
            return status in (200, 301, 302, 303, 307, 308)
        except Exception:
            return False

    def model_name(self) -> str:
        """Human-readable Modellname — fuer pfSense immer 'pfSense'."""
        return "pfSense"

    def _version(self, html_text: str = "") -> str:
        """Versionsnummer aus einer beliebigen UI-Seite (best effort)."""
        for rx in _VERSION_RES:
            m = rx.search(html_text)
            if m:
                return m.group(1)
        return self._last_version

    def _hostname(self, html_text: str = "") -> str:
        """System-Hostname aus Title/System-Panel (best effort)."""
        for rx in _HOSTNAME_RES:
            m = rx.search(html_text)
            if m:
                return m.group(1).strip()
        return ""

    def full_info(self) -> dict:
        """System-Info per Web (best effort), gleiche Art wie unifi.py:

        {kind:'pfsense', model, version, uptime_s, mem_available_kb,
        load1, no_ssh, ...} — unbekannte Felder bleiben 0/'';
        wirft nie.
        """
        info = {
            "kind": "pfsense",
            "model": "pfSense",
            "version": "",
            "hostname": "",
            "uptime_s": 0,
            "mem_available_kb": 0,
            "load1": 0.0,
            "no_ssh": True,
            "error": "",
        }
        try:
            ok, body = self._get("/index.php")
            if not ok:
                info["error"] = body[:200] or "web nicht erreichbar"
                return info
            ver = self._version(body)
            if ver:
                self._last_version = ver
                info["version"] = ver
            # Hostname aus Title/Panel, sonst aus URL-Context
            info["hostname"] = self._hostname(body)
            # pfSense zeigt auf dem Dashboard z.T. "System Information"
            # inkl. uptime/cpu/mem — defensive parsen, falls vorhanden
            m = re.search(r"Uptime[:\s]+(\d+)\s*(?:days?\s*)?(\d*)\s*(?:hours?\s*)?",
                          body, re.I)
            if m:
                try:
                    d = int(m.group(1))
                    h = int(m.group(2) or 0)
                    info["uptime_s"] = d * 86400 + h * 3600
                except (TypeError, ValueError):
                    pass
            m = re.search(r"Load\s*Average[^\d\n]*([\d.]+)", body, re.I)
            if m:
                try:
                    info["load1"] = float(m.group(1))
                except ValueError:
                    pass
            m = re.search(r"Memory\s*Available[^\d\n]*([\d]+)\s*(?:kB|KB|MiB)?",
                          body, re.I)
            if m:
                try:
                    kb = int(m.group(1))
                    info["mem_available_kb"] = kb * 1024 if kb < 1024 else kb
                except ValueError:
                    pass
        except Exception as exc:
            info["error"] = str(exc)[:200]
        return info

    # ----------------------------------------------------------------- survey
    def survey(self) -> dict:
        """One-shot Survey (Web-Edition): full_info + clients=[], interfaces=[],
        hostname. Niemals raised; bei Offline leeres Besteffort-Dict."""
        base = {
            "kind": "pfsense", "model": "pfSense", "version": "",
            "hostname": "", "uptime_s": 0, "clients": [], "interfaces": [],
            "leases": {}, "no_ssh": True, "error": "",
        }
        try:
            info = self.full_info()
        except Exception as exc:
            base["error"] = str(exc)[:200]
            return base
        for k in ("version", "hostname", "uptime_s", "mem_available_kb",
                  "load1", "no_ssh", "model", "kind"):
            if k in info:
                base[k] = info[k]
        if info.get("error"):
            base["error"] = info["error"]
        base.setdefault("clients", [])
        base.setdefault("interfaces", [])
        base.setdefault("leases", {})
        return base

    # ------------------------------------------------------------------ LLDP
    def poll_lldp(self) -> dict:
        """LLDP-Form des sshx-Layers.

        ueber das Web-Interface ist LLDP auf pfSense nur sehr begrenzt
        auswertbar (GUI zeigt keine Nachbarn als strukturierbare Daten an),
        daher wohlgeformte leere Struktur mit Hinweis — der Scheduler
        persistiert die Topologie nicht ueberschreibend bei Fehler.
        """
        result = {
            "lldpd": "n/a (web)",
            "version": None,
            "error": ("LLDP nicht ueber das pfSense-Web-Interface "
                      "verfuegbar (kein SSH/lldpctl)"),
            "neighbors": [],
            "local": {},
            "local_chassis": None,
        }
        return result

    # ------------------------------------------------------------------- FDB
    def poll_fdb(self) -> dict:
        """Bridge-FDB-Form des sshx-Layers — per Web nicht verfuegbar."""
        return {"rows": [], "error": "FDB nicht ueber das Web-Interface verfuegbar"}

    # ------------------------------------------------------------- packages
    def package_check(self, refresh: bool = True) -> dict:
        """pfSense hat keinen opkg/apk — immer leer, nie ein Fehler."""
        return {"pkgman": "", "count": 0, "packages": [],
                "error": "kein Paketmanager (pfSense)"}

    # ------------------------------------------------------------ firmware
    def check_update(self) -> dict:
        """Firmware-Check: aktuelle Version aus der UI.

        pfSense-Freigaben kommen ueber das Web-Update-Modul (interaktive
        Signatur-Pruefung, kein maschinenlesbarer Feed), daher latest=''
        und has_update=False. Niemals raised.
        """
        current = self._last_version
        err = ""
        try:
            info = self.full_info()
            if info.get("version"):
                current = info["version"]
            elif info.get("error"):
                err = info["error"][:200]
        except Exception as exc:
            err = str(exc)[:200]
        return {
            "kind": "pfsense",
            "model": "pfSense",
            "current": current,
            "latest": "",
            "has_update": False,
            "image_exists": False,
            "url": "",
            "no_ssh": True,
            "error": err,
        }

    # --------------------------------------------------- (nicht SSH) no-ops
    def lan_clients(self) -> list:
        """Kein SSH-ARP-Zugriff — Web-Edition liefert keine LAN-Clients."""
        return []

    def wlan_clients(self) -> list:
        """Kein SSH-wifi-Zugriff — Web-Edition liefert keine WLAN-Clients."""
        return []

    def uptime_seconds(self) -> int:
        """Uptime in Sekunden (0 wenn nicht aus der UI ableitbar)."""
        try:
            return int(self.full_info().get("uptime_s") or 0)
        except Exception:
            return 0

    def reboot(self) -> None:
        """Kein SSH -> Reboot nicht ausfuehrbar (still no-op)."""
        return None

    def installed_packages(self) -> dict:
        """Kein Paketmanager — leeres Besteffort-Snapshot (kein Fehler-Throw)."""
        return {"pkgman": "", "names": [], "error": "kein Paketmanager (pfSense)"}
