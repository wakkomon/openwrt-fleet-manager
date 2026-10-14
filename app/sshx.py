# -*- coding: utf-8 -*-
"""SSH operations for OpenWRT routers (paramiko)."""
import io
import json
import os
import re
import shlex
import time

import paramiko

OPENWRT_RELEASE = "/etc/openwrt_release"
DOWNLOAD_BASE = "https://downloads.openwrt.org/releases"


class OpenWRT:
    """One OpenWRT device reachable via SSH."""

    def __init__(self, ip: str, port: int = 22, user: str = "root",
                 password: str = "", firmware_dir: str = "", timeout: int = 15,
                 ssh_key: str = "", auth_mode: str = "password",
                 ssh_key_passphrase: str = ""):
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.firmware_dir = firmware_dir or DOWNLOAD_BASE
        self.timeout = timeout
        self.ssh_key = ssh_key or ""
        self.auth_mode = auth_mode or "password"
        self.ssh_key_passphrase = ssh_key_passphrase or ""

    # ------------------------------------------------------------------ SSH
    def _pkey(self):
        """Parse private key text (OpenSSH/PEM) into a paramiko key object.

        Handles password-protected (encrypted) keys: if the key is encrypted
        and a passphrase is stored, it is passed to paramiko; if the key is
        encrypted but no passphrase is set, a clear, actionable error is raised
        instead of a generic "key not readable" message.
        """
        last_exc = None
        names = ["Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey", "DSKey"]
        passphrase = self.ssh_key_passphrase or None
        for name in names:
            cls = getattr(paramiko, name, None)
            if cls is None:
                continue
            try:
                return cls.from_private_key(
                    io.StringIO(self.ssh_key),
                    password=passphrase,
                )
            except Exception as exc:
                last_exc = exc
        msg = "privater SSH-Key nicht lesbar: %s" % last_exc
        if isinstance(last_exc, paramiko.PasswordRequiredException):
            if passphrase:
                msg = "privater SSH-Key verschluesselt: Passphrase nicht korrekt"
            else:
                msg = ("privater SSH-Key ist verschluesselt (passwortgeschuetzt) – "
                       "Bitte im Geraet-Dialog die Key-Passphrase eintragen")
        raise ValueError(msg)

    def _client(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {}
        if self.auth_mode == "key" and self.ssh_key:
            kwargs["pkey"] = self._pkey()
        else:
            kwargs["password"] = self.password
        client.connect(
            self.ip, port=self.port, username=self.user,
            timeout=self.timeout, allow_agent=False, look_for_keys=False,
            banner_timeout=self.timeout, auth_timeout=self.timeout, **kwargs
        )
        return client

    def run(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run a command; return (exit_code, stdout, stderr)."""
        client = self._client()
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        finally:
            client.close()

    def is_online(self) -> bool:
        try:
            rc, _, _ = self.run("echo ok", timeout=10)
            return rc == 0
        except Exception:
            return False

    # ------------------------------------------------------ package updates
    def package_check(self, refresh: bool = True) -> dict:
        """Upgradable packages via opkg/apk/rpm (whichever the device has).

        Returns {"pkgman", "count", "packages": ["name [cur -> new]", ...],
        "error": str|None}. Refreshes indexes first unless refresh=False."""
        rc, out, _ = self.run("which opkg apk rpm 2>/dev/null", timeout=15)
        managers = [os.path.basename(w.strip()) for w in out.split() if w.strip()]
        if not managers:
            return {"pkgman": "", "count": 0, "packages": [],
                    "error": "kein Paketmanager gefunden"}
        pm = managers[0]
        err = None
        if pm == "opkg":
            if refresh:
                rc2, _, e2 = self.run("opkg update 2>&1 | tail -1", timeout=180)
                if rc2 != 0:
                    err = f"opkg update: {(e2 or '')}"[:160]
            rc3, out3, e3 = self.run(
                "opkg list-upgradable 2>/dev/null | "
                "awk '{print $1\" [\"$3\" -> \"$5\"]\"}' | head -40", timeout=120)
        elif pm == "apk":
            if refresh:
                rc2, _, e2 = self.run("apk update 2>&1 | tail -1", timeout=180)
                if rc2 != 0:
                    err = f"apk update: {(e2 or '')}"[:160]
            # apk-tools v3 (OpenWrt >= 24): "apk version -l '<'" lists upgradable.
            rc3, out3, e3 = self.run("apk version -l '<' 2>/dev/null", timeout=120)
            pkgs = []
            for line in out3.splitlines():
                m = re.match(r"(.+?)-(\d[^ ]*)\s*<\s*(\S+)", line.strip())
                if m:
                    pkgs.append(f"{m.group(1)} [{m.group(2)} -> {m.group(3)}]")
            return {"pkgman": "apk", "count": len(pkgs), "packages": pkgs[:12],
                    "error": err}
        else:
            rc3, out3, e3 = self.run(
                "rpm -q -a --queryformat "
                "'%{NAME} [%{VERSION} -> %{UPPERVERSION}]\\n' "
                "2>/dev/null | grep '\\[.*-> .*\\]' | grep -v '-> \\]' | head -40",
                timeout=180)
        if rc3 != 0 and not out3.strip():
            err = err or f"{pm} list-upgradable: {(e3 or '')}"[:160]
        pkgs = [l.strip() for l in out3.splitlines() if l.strip()]
        return {"pkgman": pm, "count": len(pkgs), "packages": pkgs[:12],
                "error": err}

    def update_packages(self, names: list | None = None,
                        timeout: int = 900, on_output=None) -> dict:
        """Alle upgradbaren Pakete aktualisieren (apk upgrade / opkg upgrade).

        Blockiert bis Ende (in einem Worker-Thread laufen lassen!).
        `names` limitiert den Lauf auf ausgewählte Pakete (None = alles).
        `on_output(chunk)` wird bei jedem empfangenen Stück gerufen, damit
        die UI live mitlesen kann. Returns {"pkgman", "rc", "output",
        "error"} — output ist der letzten Zeilen des Paketaustauschs.
        """
        rc, out, _ = self.run("which opkg apk 2>/dev/null", timeout=15)
        managers = [w.strip().rsplit("/", 1)[-1] for w in out.split()
                    if w.strip()]
        pm = "apk" if "apk" in managers else (
            "opkg" if "opkg" in managers else "")
        if not pm:
            return {"pkgman": "", "rc": 1, "output": "",
                    "error": "kein Paketmanager gefunden"}
        if pm == "apk":
            target = " ".join(shlex.quote(n) for n in names) if names else ""
            cmd = ("apk update >/dev/null 2>&1; "
                   "apk upgrade" + (f" {target}" if target else "") +
                   " 2>&1 | tail -40")
        else:
            if names:
                quoted = " ".join(shlex.quote(n) for n in names)
                cmd = ("opkg update 2>&1 | tail -1; "
                       f"opkg upgrade {quoted} 2>&1 | tail -40")
            else:
                cmd = "opkg update 2>&1 | tail -1; opkg upgrade 2>&1 | tail -40"
        client = self._client()
        out_buf: list = []
        try:
            _, stdout, stderr = client.exec_command(cmd)
            chan = stdout.channel
            import time as _t
            deadline = _t.time() + timeout
            rc_code = 0
            while True:
                if stdout.channel.recv_ready():
                    chunk = stdout.read(4096)
                    out_buf.append(chunk)
                    if on_output:
                        try:
                            on_output(chunk.decode("utf-8", "replace"))
                        except Exception:
                            pass
                rc_code = chan.recv_exit_status()
                if rc_code != -1:
                    for data in (stdout.read(), stderr.read()):
                        if data:
                            out_buf.append(data)
                            if on_output:
                                try:
                                    on_output(data.decode("utf-8", "replace"))
                                except Exception:
                                    pass
                    break
                if _t.time() > deadline:
                    try:
                        chan.close()
                    except Exception:
                        pass
                    return {"pkgman": pm, "rc": 124,
                            "output": "".join(out_buf)[:4000],
                            "error": "Timeout nach %d s" % int(timeout)}
                _t.sleep(1.5)
            return {"pkgman": pm, "rc": rc_code,
                    "output": "".join(out_buf)[:4000],
                    "error": None if rc_code == 0 else "rc=%s" % rc_code}
        finally:
            client.close()

    # --------------------------------------- package set (sysupgrade backup)
    _WORLD_CMD = {
        "apk": "cat /etc/apk/world 2>/dev/null",
        "opkg": "opkg list-installed 2>/dev/null | awk '{print $1}'",
    }

    def installed_packages(self) -> dict:
        """Installierte Paketnamen des Routers (Basis für Re-Install nach
        sysupgrade). apk: /etc/apk/world, opkg: list-installed.
        Returns {"pkgman", "names": [...], "error"}."""
        rc, out, _ = self.run("which opkg apk 2>/dev/null", timeout=15)
        managers = [w.strip().rsplit("/", 1)[-1] for w in out.split()
                    if w.strip()]
        pm = "apk" if "apk" in managers else ("opkg" if "opkg" in managers
                                              else "")
        if not pm:
            return {"pkgman": "", "names": [],
                    "error": "kein Paketmanager gefunden"}
        rc2, out2, e2 = self.run(self._WORLD_CMD[pm], timeout=60)
        # Versions-Pins ("base-files=1711~x") abschneiden -> nur Paketnamen
        names = sorted({line.strip().split("=")[0].strip()
                        for line in out2.splitlines() if line.strip()})
        err = None if rc2 == 0 else (e2 or out2 or "rc=%s" % rc2)[:160]
        return {"pkgman": pm, "names": names, "error": err}

    def reinstall_packages(self, names: list,
                           timeout: int = 300) -> dict:
        """Fehlende Pakete nach sysupgrade nachinstallieren (apk add /
        opkg install). Batchweise (20); fehlt das Index-Cache-Problem, wird
        einmal `apk update` nachgeschoben. Returns
        {"pkgman", "installed": [...], "failed": [...], "error"}."""
        snap = self.installed_packages()
        pm = snap.get("pkgman", "")
        have = set(snap.get("names", []))
        todo = [n for n in names if n and n not in have]
        res = {"pkgman": pm, "installed": [], "failed": list(todo),
               "error": None}
        if not todo:
            res["failed"] = []
            return res
        if not pm:
            res["error"] = snap.get("error") or "kein Paketmanager"
            return res
        cmd = "apk add" if pm == "apk" else "opkg install"

        def _try(batch: list) -> bool:
            q = " ".join(shlex.quote(n) for n in batch)
            rc, out, err = self.run(f"{cmd} {q} 2>&1 | tail -4",
                                    timeout=timeout)
            if rc != 0 and pm == "apk":
                # Index evtl. leer (fresh flash) -> einmal nachziehen
                self.run("apk update >/dev/null 2>&1", timeout=timeout)
                rc, out, err = self.run(f"{cmd} {q} 2>&1 | tail -4",
                                        timeout=timeout)
            if rc != 0:
                res["error"] = res["error"] or \
                    f"rc={rc}: {(out or err or '')}"[:200]
            return rc == 0

        for i in range(0, len(todo), 20):
            batch = todo[i:i + 20]
            if _try(batch):
                res["installed"].extend(batch)
            else:
                # Batch fehlgeschlagen (ein unpublishbares Paket blockiert
                # alles) -> einzeln weiter, damit der Rest nicht verliert
                for n in batch:
                    if _try([n]):
                        res["installed"].append(n)
                    else:
                        pass
        res["failed"] = [n for n in todo if n not in res["installed"]]
        return res

    # ---------------------------------------------------- file transfer
    # Minimal images (e.g. without LuCI) often lack SFTP, base64 and busybox,
    # so transfers go through exec_command: `hexdump` for reads, `cat >` for
    # writes (stdin pipe).
    def read_file(self, remote_path: str) -> bytes:
        """Fetch a remote file as bytes via hexdump over exec (no sftp)."""
        rc, out, err = self.run(
            f"hexdump -v -e '8/1 \"%02x\"' {shlex.quote(remote_path)}",
            timeout=120)
        if rc != 0:
            raise RuntimeError(f"read failed ({rc}): {err.strip()[:200]}")
        hexd = re.sub(r"\s+", "", out)
        if len(hexd) % 2:
            hexd = hexd[:-1]
        return bytes.fromhex(hexd)

    def write_file(self, remote_path: str, data: bytes) -> None:
        """Write bytes to a remote file via stdin pipe (no sftp)."""
        client = self._client()
        try:
            chan = client.get_transport().open_session(timeout=self.timeout)
            chan.exec_command(f"cat > {shlex.quote(remote_path)}")
            chan.settimeout(120)
            offset = 0
            while offset < len(data):
                sent = chan.send(data[offset:offset + 65536])
                offset += sent
            chan.shutdown_write()
            rc = chan.recv_exit_status()
            if rc != 0:
                raise RuntimeError(f"write failed on router (rc={rc})")
        finally:
            client.close()

    # ------------------------------------------------------------ metadata
    def openwrt_release(self) -> dict:
        """Parse /etc/openwrt_release into a dict."""
        rc, content, err = self.run(f"cat {OPENWRT_RELEASE}")
        if rc != 0:
            raise RuntimeError(f"not an OpenWRT device: {err.strip()[:200]}")
        info = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, val = line.partition("=")
            info[key.strip()] = val.strip().strip("'\"")
        return info

    def device_info(self) -> dict:
        client = self._client()
        try:
            _, out, _ = client.exec_command(
                "tr '\\0' ' ' </sys/firmware/devicetree/base/compatible 2>/dev/null"
            )
            compat = out.read().decode("utf-8", "replace").strip()
        finally:
            client.close()
        return {"compatible": compat}

    def full_info(self) -> dict:
        release = self.openwrt_release()
        dev = self.device_info()
        rc, out, _ = self.run("uptime 2>/dev/null")
        rc2, mem, _ = self.run(
            "free 2>/dev/null | awk '/^Mem:/{print $2\" kB total\"; exit}'")
        return {
            "version": release.get("DISTRIB_RELEASE", ""),
            "revision": release.get("DISTRIB_REVISION", ""),
            "target": release.get("DISTRIB_TARGET", ""),
            "arch": release.get("DISTRIB_ARCH", ""),
            "description": release.get("DISTRIB_DESCRIPTION", ""),
            "taints": release.get("DISTRIB_TAINTS", ""),
            "model": self.model_name(),
            "board": self.board_slug(),
            "compatible": dev.get("compatible", ""),
            "hostname": self._hostname(),
            "uptime": out.strip(),
            "memory": mem.strip(),
        }

    def _hostname(self) -> str:
        rc, out, _ = self.run("uci get system.@system[0].hostname 2>/dev/null")
        return out.strip()

    # ------------------------------------------------------------- clients
    def poll_lldp(self) -> dict:
        """LLDP-Daten über lldpctl -f json (Schema: lldpd 1.0.x, display.c).

        Liefert Status (lldpd läuft / installiert / fehlt), das lokale
        Chassis (Name, MAC) und alle gesehenen Nachbarn. Fehler bei
        „lldpd läuft nicht“ werden als sauberer Status zurückgegeben.
        """
        import socket
        import ipaddress
        try:
            _, ver, _ = self.run(
                "opkg -info lldpd 2>/dev/null | awk -F': ' "
                "'/Version:/{print $2; exit}'", timeout=15)
            ver = (ver or "").strip()
            # `timeout` fehlt teils auf BusyBox-ash — portable Fallback:
            # Prozess im Hintergrund starten, nach 12 s killen.
            rc, out, err = self.run(
                'if command -v timeout >/dev/null 2>&1; then '
                'timeout 12 lldpctl -f json 2>&1; '
                'else (lldpctl -f json 2>&1 & P=$!; '
                '(sleep 12; kill -9 $P 2>/dev/null) & K=$!; '
                'wait $P; RC=$?; kill $K 2>/dev/null; exit $RC); fi',
                timeout=25)
            ok = (rc == 0)
            if ok and not out.strip():
                ok = False
        except Exception as exc:
            return {"error": str(exc), "lldpd": "error",
                    "installed": None, "version": None, "neighbors": []}
        lldpd = "running" if ok else ("installed" if ver else "missing")
        result = {"lldpd": lldpd, "version": ver or None,
                  "error": None, "neighbors": [], "local": [],
                  "local_chassis": None}
        if not ok:
            result["error"] = ((out or err) or "lldpd läuft nicht").strip()[:300]
            return result
        try:
            data = json.loads(out)
        except Exception as exc:
            result["error"] = "lldpctl-JSON nicht parsebar: %s" % exc
            return result
        result["local_chassis"] = data.get("local-chassis")
        result["local"] = data.get("local", []) or []
        result["neighbors"] = self._parse_lldp_neighbors(data)
        return result

    def _parse_lldp_neighbors(self, data: dict) -> list:
        """lldpctl-JSON → flache Neighbor-Liste.
        Werte kommen je nach lldpd-Version als Objekt oder String daher
        (json_writer.c: Einzelwert-Objekte kollabieren zu Plain-Values)."""
        import socket
        import ipaddress

        def v(x, key):
            if isinstance(x, dict):
                val = x.get(key)
                if isinstance(val, list):
                    val = val[0] if val else None
                if isinstance(val, dict):
                    val = val.get("value", "")
                return val or ""
            return x if isinstance(x, str) else ("" if x is None else str(x))

        def ip_of(lst):
            for e in lst or []:
                val = (e.get("value") or "") if isinstance(e, dict) else (e or "")
                if val:
                    try:
                        ipaddress.ip_address(val)
                        return val
                    except ValueError:
                        pass
            return None

        out = []
        for e in data.get("lldp", []) or []:
            via = e.get("via")
            if not isinstance(via, dict):
                continue
            iface = v(e, "interface")
            if not iface:
                continue
            ch = via.get("chassis") or {}
            name = v(ch, "name") or ""
            mips = ch.get("mgmt-ip") or []
            mgmt = ip_of(mips)
            host = None
            if mgmt:
                try:
                    host = socket.gethostbyaddr(mgmt)[0]
                except Exception:
                    host = None
            port = via.get("port") or {}
            out.append({
                "interface": iface,
                "mac": v(via, "mac") or "",
                "neighbor_name": name,
                "neighbor_descr": v(ch, "descr") or "",
                "chassis_id": v(ch, "id"),
                "port_id": v(port, "id"),
                "port_descr": v(port, "descr") or "",
                "mgmt_ip": mgmt,
                "hostname": host,
                "status": v(e, "status"),
            })
        return out

    # ------------------------------------------------------- bridge FDB
    def poll_fdb(self) -> dict:
        """Bridge-FDB over all local bridges via `brctl showmacs`.

        Independent of LLDP: fills the L2 adjacency gap ("wer hängt wo an")
        even when lldpd is off and no neighbors are advertised. Returns
        {"rows": [(bridge, port, port_name, mac), ...], "error": ...}.

        Port numbering is brctl's (decimal); the port name is resolved on
        the host side from /sys/class/net/<br>/brif/<name>/port_no (hex).
        The shell below uses only parameter expansion (no `basename`, which
        is unreliable on these BusyBox OpenWrt boxes) and no \\t regex.
        """
        import re
        CMD = (
            'for d in /sys/class/net/*; do '
            '  [ -d "$d/brif" ] || continue; '
            '  br="${d##*/}"; '
            '  echo "===BR $br"; '
            '  for p in "$d"/brif/*; do [ -e "$p" ] || continue; '
            '    n="${p##*/}"; echo "PORT $n $(cat $p/port_no 2>/dev/null)"; '
            '  done; '
            '  echo "===MACS $br"; brctl showmacs "$br" 2>/dev/null | head -400; '
            'done; echo "===DONE==="'
        )
        try:
            rc, out, err = self.run(CMD, timeout=40)
        except Exception as exc:
            return {"rows": [], "error": str(exc)}
        if rc != 0:
            return {"rows": [], "error": ((out or err) or "").strip()[:300]}

        rows = []
        cur_bridge = None
        port_map = {}      # per bridge: brctl port (int) -> port name
        macs_mode = False
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("===BR "):
                cur_bridge = s[6:].strip()
                port_map = {}
                macs_mode = False
                continue
            if s.startswith("PORT ") and cur_bridge:
                parts = s.split()
                if len(parts) >= 3:
                    m = re.match(r"0[xX]([0-9a-fA-F]+)", parts[2])
                    if m:
                        port_map[int(m.group(1), 16)] = parts[1]
                continue
            if s.startswith("===MACS "):
                macs_mode = True
                continue
            if s.startswith("==="):      # ===DONE=== / any other marker
                macs_mode = False
                continue
            if not macs_mode or not cur_bridge:
                continue
            f = line.split("\t")
            if len(f) < 2:
                continue
            try:
                port = int(f[0].strip())
            except ValueError:
                continue
            mac = f[1].strip().lower()
            if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                continue
            is_local = f[2].strip().lower() if len(f) > 2 else ""
            if is_local == "yes":
                continue                # own AP MAC, not a client
            rows.append((cur_bridge, port, port_map.get(port, ""), mac))
        # brctl showmacs meldet dieselbe (bridge,port,mac) je Eintrag nochmal;
        # deduplizieren, sonst stoesst save_fdb auf den UNIQUE-Key (device_id,
        # bridge, port, mac). Reihenfolge beibehalten.
        seen = set()
        dedup = []
        for r in rows:
            k = (r[0], r[1], r[3])
            if k in seen:
                continue
            seen.add(k)
            dedup.append(r)
        return {"rows": dedup, "error": None}

    def activate_lldp(self) -> dict:
        """lldpd (ggf. nach Installation via apk add) starten.
        Bleibt nach Reboot aktiv (initscript wird registriert)."""
        _rc, out, _err = self.run(
            'if ! command -v lldpctl >/dev/null 2>&1; then '
            '  echo "INSTALLING"; apk add lldpd 2>&1 | tail -2; '
            'else echo "PRESENT"; fi; '
            'echo "---START---"; '
            'lldpd 2>/dev/null && echo "lldpd started" || '
            '{ echo "retry"; pkill lldpd 2>/dev/null; sleep 1; '
            '  lldpd 2>/dev/null && echo "retry ok"; }; '
            'enable lldpd 2>/dev/null; '
            'sleep 1; command -v lldpctl >/dev/null 2>&1 '
            '&& lldpctl -f json 2>&1 | head -c 400',
            timeout=180)
        ok = "lldpd started" in out or "retry ok" in out
        return {"ok": ok, "output": (out or _err or "").strip()[:800]}

    def lan_clients(self) -> list:
        """Connected LAN devices from the ARP table (ip neigh), enriched
        with hostnames from the dnsmasq lease file when available."""
        import re
        rc, out, _ = self.run(
            "ip -4 neigh 2>/dev/null; echo ---LEASES---; cat /tmp/dhcp.leases 2>/dev/null")
        neigh, leases = (out.split("---LEASES---", 1)
                         if "---LEASES---" in out else (out, ""))
        lease_mac = {}
        for line in leases.splitlines():
            p = line.split()
            if len(p) >= 3:
                lease_mac[p[2].lower()] = (p[3] if len(p) > 3 else "",
                                           p[4] if len(p) > 4 else "")
        clients = []
        seen = set()
        for m in re.finditer(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]{17})",
                neigh, re.M):
            ip, iface, mac = m.group(1), m.group(2), m.group(3).lower()
            if mac in seen:
                continue
            seen.add(mac)
            host, _, _h, _ = lease_mac.get(mac, ("", "", "", ""))
            clients.append({"ip": ip, "mac": mac, "hostname": host,
                            "iface": iface})
        return clients

    def wlan_clients(self) -> list:
        """Associated WLAN stations per SSID via `iw station dump` per radio
        interface, with the SSID taken from `wifi status` config."""
        import json
        import re
        # 1) map AP ifname -> ssid from wifi status (config only, no stations)
        ssid_of = {}
        rc, out, _ = self.run("wifi status 2>/dev/null", timeout=30)
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        for _radio, rdata in data.items():
            if not isinstance(rdata, dict):
                continue
            for iface in rdata.get("interfaces", []) or []:
                if (iface.get("config") or {}).get("mode") != "ap":
                    continue
                cfg = iface.get("config") or {}
                ssid = cfg.get("ssid") or ""
                if isinstance(ssid, list):
                    ssid = ssid[0] if ssid else ""
                ifname = iface.get("ifname") or ""
                if ifname:
                    ssid_of[ifname] = ssid
        # 2) stations via iw per interface
        rc, out, _ = self.run(
            "iw dev 2>/dev/null | awk '{print $2}'", timeout=30)
        clients = []
        seen = set()
        for ifname in (x.strip() for x in out.splitlines()):
            # only interfaces `wifi status` reported as AP mode
            # (ssid_of keys) — no name-based filter, so plain
            # `wlan0`/`wlan1` radios are included as well
            if not ifname or ifname not in ssid_of:
                continue
            rc, out, _ = self.run(
                f"iw dev {shlex.quote(ifname)} station dump 2>/dev/null",
                timeout=30)
            if rc != 0:
                continue
            ssid = ssid_of.get(ifname, "")
            for m in re.finditer(
                    r"^Station\s+([0-9a-fA-F:]{17})\s*\(on\s+([^)]+)\)(.*?)(?=\n\s*Station\s|\Z)",
                    out, re.M | re.S):
                mac = m.group(1).lower()
                if mac in seen:
                    continue
                seen.add(mac)
                sm = re.search(
                    r"signal[=:]\s*(-?\d+(?:\.\d+)?)", m.group(3) or "")
                signal = str(int(float(sm.group(1)))) if sm else ""
                clients.append({"ip": "", "mac": mac,
                                "hostname": "", "ssid": ssid,
                                "signal": signal})
        return clients

    # ------------------------------------------------------------- firmware
    def board_slug(self) -> str:
        """Board slug (e.g. tplink_archer-c7-v2) as used in image filenames."""
        # Primary: the device-tree model id from /etc/board.json (jsonfilter)
        rc, out, _ = self.run(
            "jsonfilter -i /etc/board.json -e '@.model.id' 2>/dev/null")
        if rc == 0 and out.strip():
            return out.strip()
        release = self.openwrt_release()
        for key in ("DISTRIB_BOARD_SLUG", "DISTRIB_BOARD"):
            if release.get(key):
                return release[key].replace(".", "_")
        # Last resort: device-tree compatible from the DTB
        compat = self.device_info().get("compatible", "").split(" ")[0]
        return (compat.replace(" ", "-").replace(".", "_").lstrip("_")
                if compat else "unknown")

    def model_name(self) -> str:
        """Human-readable model name, e.g. 'TP-Link Archer C7 v2'."""
        rc, out, _ = self.run(
            "jsonfilter -i /etc/board.json -e '@.model.name' 2>/dev/null")
        if rc == 0 and out.strip():
            return out.strip()
        rc, out, _ = self.run("cat /proc/cpuinfo 2>/dev/null |"
                              " sed -n 's/^machine.*: //p' | head -1")
        return out.strip()

    def _board_for_filename(self, board: str) -> str:
        """Board slug as it appears in image filenames (',' -> '_')."""
        return board.replace(",", "_")

    def target_files(self, version: str, target: str) -> list:
        """List the filenames available for a version+target (incl. subtarget)."""
        import re
        import urllib.request

        base = self.firmware_dir.rstrip("/")
        # target may be 'ath79/generic' or just 'ath79'; resolve the subtarget
        # by walking the directory listing.
        parts = [p for p in target.split("/") if p]
        for base_path in (f"targets/{'/'.join(parts)}", f"targets/{parts[0]}"):
            url = f"{base}/{version}/{base_path}/"
            try:
                with urllib.request.urlopen(url, timeout=20) as resp:
                    html = resp.read().decode("utf-8", "replace")
            except Exception:
                continue
            files = re.findall(r'href="([^"/]+)"', html)
            subdirs = re.findall(r'href="([^"]+)/(?=")', html)
            if subdirs and "files" not in files:
                # descend one level into the subtarget dir
                sub = subdirs[0]
                try:
                    with urllib.request.urlopen(
                            f"{base}/{version}/targets/{'/'.join(parts)}/{sub}/",
                            timeout=20) as resp:
                        html = resp.read().decode("utf-8", "replace")
                    return re.findall(r'href="([^"/]+)"', html)
                except Exception:
                    continue
            return files
        return []

    def find_sysupgrade(self, version: str, target: str, board: str) -> str:
        """Return the full URL of the sysupgrade image, or '' if not found."""
        import urllib.parse
        board_f = self._board_for_filename(board)
        files = self.target_files(version, target)
        for fname in files:
            if fname.endswith("-squashfs-sysupgrade.bin") and board_f in fname:
                parts = [p for p in target.split("/") if p]
                url = (f"{self.firmware_dir.rstrip('/')}/{version}/targets/"
                       f"{'/'.join(parts)}/")
                # files may live one level deeper (subtarget dir) – verify
                candidates = [url + urllib.parse.quote(fname),
                               url + "files/" + urllib.parse.quote(fname)]
                for cand in candidates:
                    try:
                        import urllib.request
                        with urllib.request.urlopen(cand, timeout=20) as resp:
                            resp.read(0)
                        return cand
                    except Exception:
                        continue
        # Fallback: guess the conventional name
        return self.firmware_url(version, target, board)

    def firmware_url(self, version: str, target: str, board: str) -> str:
        """Conventional sysupgrade .bin URL for a version (best effort)."""
        import urllib.parse
        parts = [p for p in target.split("/") if p]
        board_f = self._board_for_filename(board)
        return (
            f"{self.firmware_dir.rstrip('/')}/{version}/targets/"
            f"{'/'.join(parts)}/"
            f"openwrt-{version}-{parts[0]}-{parts[-1] if len(parts) > 1 else 'generic'}"
            f"-{urllib.parse.quote(board_f)}-squashfs-sysupgrade.bin"
        )

    def check_update(self) -> dict:
        """Find the newest release in the same series as the installed one."""
        import re
        import urllib.request

        release = self.openwrt_release()
        current = release.get("DISTRIB_RELEASE", "")
        target = release.get("DISTRIB_TARGET", "")
        board = self.board_slug()

        try:
            with urllib.request.urlopen(f"{self.firmware_dir}/", timeout=20) as resp:
                html = resp.read().decode("utf-8", "replace")
        except Exception as exc:
            return {"error": f"download dir not reachable: {exc}",
                    "current": current, "latest": current, "has_update": False}

        # Collect version directories like 25.12.5 (relative or absolute links)
        versions = set(re.findall(
            r'href="(?:/releases/)?(\d+\.\d+\.\d+)/?["\s]', html))
        if not versions:
            return {"error": "no versions found in directory listing",
                    "current": current, "latest": current, "has_update": False}

        # Only offer updates within the same series (major.minor) as installed,
        # because sysupgrade across major series is not always supported.
        series = ".".join(current.split(".")[:2]) if current else None
        candidates = [v for v in versions
                      if not series or v.startswith(series + ".")]
        if not candidates:
            candidates = list(versions)
        latest = max(candidates, key=lambda v: [int(p) for p in v.split(".")])

        # Only an update if newer AND a sysupgrade image exists for this board
        url = (self.find_sysupgrade(latest, target, board)
               if latest != current else "")
        exists = bool(url)
        has_update = latest != current and exists
        return {
            "current": current,
            "latest": latest,
            "has_update": has_update,
            "image_exists": exists,
            "target": target,
            "board": board,
            "url": url,
        }

    # --------------------------------------------------------- sysupgrade
    def download_image(self, url: str, dest: str = "/tmp/firmware.bin",
                       timeout: int = 600) -> tuple[int, str, str]:
        """Download the firmware image onto the router into /tmp.

        Tries the router's own fetchers (wget / uclient-fetch / curl) so
        the image lands in /tmp before sysupgrade is started. Busybox
        wget often lacks TLS support, so callers should fall back to a
        server-side download (see main._stage_image_on_device) when this
        fails or the file looks truncated.
        """
        url_q, dest_q = shlex.quote(url), shlex.quote(dest)
        cmd = (
            f"rm -f {dest_q}; "
            f"(command -v wget >/dev/null 2>&1 && wget -O {dest_q} {url_q} "
            f"|| command -v uclient-fetch >/dev/null 2>&1 && uclient-fetch -o {dest_q} {url_q} "
            f"|| command -v curl >/dev/null 2>&1 && curl -fsSL -o {dest_q} {url_q}) "
            f"2>&1; echo DLRC=$?"
        )
        return self.run(cmd, timeout=timeout)

    def sysupgrade(self, url: str, preserve_config: bool = True,
                   test_only: bool = False) -> tuple[int, str, str]:
        """Run sysupgrade on the device.

        `url` may be an http(s) URL or a local path (e.g. an image that
        was pre-downloaded into /tmp via download_image()).
        The command is started via `setsid` in a new session so closing
        the SSH session does not kill it while the router reboots.
        (BusyBox has no `nohup`; setsid is present on OpenWrt.)
        """
        preserve = " -c" if preserve_config else ""
        test = " -T" if test_only else ""
        cmd = (
            "setsid sh -c '"
            f"echo openwrtfleet-sysupgrade-gestartet-$(date) > /tmp/openwrtfleet.log; "
            f"sysupgrade{preserve}{test} {shlex.quote(url)} "
            f">>/tmp/openwrtfleet.log 2>&1; "
            f"echo openwrtfleet-sysupgrade-beendet-rc=$?-$(date) "
            f">>/tmp/openwrtfleet.log' </dev/null >/dev/null 2>&1 "
            "& echo started"
        )
        return self.run(cmd, timeout=30)

    def upgrade_log(self) -> str:
        rc, out, _ = self.run("cat /tmp/openwrtfleet.log 2>/dev/null")
        return out


    # ------------------------------------------------- cached survey data
    def reboot(self) -> None:
        """Reboot the router (fire-and-forget over a detached session)."""
        try:
            client = self._client()
            try:
                client.exec_command("(sleep 1; reboot) >/dev/null 2>&1 &",
                                    timeout=5)
            finally:
                client.close()
        except Exception:
            pass

    def uptime_seconds(self) -> int:
        rc, out, _ = self.run("cat /proc/uptime 2>/dev/null | cut -d. -f1")
        try:
            return int(out.strip())
        except ValueError:
            return 0

    def survey(self) -> dict:
        """Collect everything the cache needs in ONE SSH session: uptime,
        hostname/model, traffic rate over ~8 s, per-interface WLAN info
        (ssid/channel/ht), associated stations and dhcp leases (hostnames).

        Returns {} if the device is unreachable; partial results otherwise."""
        script = (
            "echo @UPTIME@; cat /proc/uptime 2>/dev/null;"
            " echo @HOST@; uci -q get system.@system[0].hostname 2>/dev/null;"
            " jsonfilter -i /etc/board.json -e '@.model.name' 2>/dev/null;"
            " echo @REL@; grep DISTRIB_RELEASE /etc/openwrt_release 2>/dev/null;"
            " echo @DEV@; cat /proc/net/dev; sleep 8; cat /proc/net/dev;"
            " echo @WIFI@; for d in $(iw dev 2>/dev/null |"
            " awk '/^[[:space:]]*Interface /{print $2}'); do"
            " echo \"##IF:$d\"; iw dev $d info 2>/dev/null;"
            " iw dev $d station dump 2>/dev/null; done;"
            " echo @ARP@; ip -o neigh 2>/dev/null;"
            " echo @LEASES@; cat /tmp/dhcp.leases 2>/dev/null"
        )
        try:
            rc, out, _ = self.run(script, timeout=90)
        except Exception:
            return {}
        if "@UPTIME@" not in out:
            return {}
        sec, cur = {}, None
        for line in out.splitlines():
            key = line.strip()
            if key.startswith("@") and key.endswith("@") and 3 < len(key) < 12:
                cur = key.strip("@")
                sec[cur] = []
            elif cur is not None:
                sec[cur].append(line)
        res = {"uptime_s": 0, "hostname": "", "model": "", "version": "",
               "interfaces": [], "clients": [], "leases": {}}
        try:
            res["uptime_s"] = int(float((sec.get("UPTIME") or ["0"])[0].split()[0]))
        except (ValueError, IndexError):
            pass
        host = sec.get("HOST") or []
        if host:
            res["hostname"] = host[0].strip()
            if len(host) > 1:
                res["model"] = host[1].strip()
        for line in sec.get("REL") or []:
            m = re.search(r"DISTRIB_RELEASE='([^']*)'", line)
            if m:
                res["version"] = m.group(1)
        # traffic: two /proc/net/dev dumps -> byte deltas over ~8 s
        dumps = []
        for line in sec.get("DEV") or []:
            s = line.strip()
            if s.startswith("Inter-") or s.startswith("face") or "|" in s:
                if not dumps or dumps[-1]:
                    dumps.append([])
                continue
            parts = line.split(":")
            if len(parts) != 2:
                continue
            f = parts[1].split()
            if len(f) >= 9:
                try:
                    dumps[-1].append((parts[0].strip(), int(f[0]), int(f[8])))
                except ValueError:
                    pass
        if len(dumps) >= 2 and dumps[0] and dumps[-1]:
            first = {n: (r, t) for n, r, t in dumps[0]}
            last = {n: (r, t) for n, r, t in dumps[-1]}
            iface = next((n for n in ("br-lan", "br-wan", "eth0") if n in first), None) \
                or next((n for n, _ in first.items() if n != "lo"), None)
            if iface:
                res["rx_bps"] = max(0, last[iface][0] - first[iface][0]) // 8
                res["tx_bps"] = max(0, last[iface][1] - first[iface][1]) // 8
                res["rx_total"] = last[iface][0]
                res["tx_total"] = last[iface][1]
                res["traffic_iface"] = iface
        # wifi blocks: ##IF:<ifname> + `iw dev info` + `iw dev station dump`
        blocks = {}
        cur_if = None
        for line in sec.get("WIFI") or []:
            if line.startswith("##IF:"):
                cur_if = line[5:].strip()
                blocks[cur_if] = []
            elif cur_if:
                blocks[cur_if].append(line)
        stations = []
        for ifname, lines in blocks.items():
            info = {"iface": ifname, "ssid": "", "channel": "", "ht": "",
                    "band": "", "mode": ""}
            st = None
            for line in lines:
                s = line.strip()
                m = re.match(r"Station ([0-9a-fA-F:]{17})( \(on [^)]+\))?", s)
                if m:
                    st = {"mac": m.group(1).lower(), "iface": ifname,
                          "ip": "", "hostname": "", "signal": "",
                          "tx_bytes": 0, "rx_bytes": 0, "connected_s": 0}
                    stations.append(st)
                    continue
                if st is not None:
                    if s.startswith("signal:") and not st["signal"]:
                        m2 = re.match(r"signal:\s*(-?\d+)", s)
                        if m2:
                            st["signal"] = m2.group(1) + " dBm"
                    elif s.startswith("tx bytes:"):
                        try:
                            st["tx_bytes"] = int(s.split(":")[1].split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif s.startswith("rx bytes:"):
                        try:
                            st["rx_bytes"] = int(s.split(":")[1].split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif s.startswith("connected time:"):
                        try:
                            st["connected_s"] = int(s.split(":")[1])
                        except (ValueError, IndexError):
                            pass
                    continue
                # device info keys
                m = re.match(r"ssid (.+)$", s)
                if m:
                    info["ssid"] = m.group(1).strip()
                elif s.startswith("mode "):
                    info["mode"] = s.split()[-1]
                elif s.startswith("channel "):
                    mch = re.match(r"channel\s+(\d+)\s*\((\d+)\s*MHz\)", s)
                    if mch:
                        info["channel"] = mch.group(1)
                        freq = int(mch.group(2))
                        info["band"] = ("2.4" if freq < 3000
                                        else "5" if freq < 7000 else "6")
                    else:
                        parts = s.split()
                        if len(parts) > 1:
                            info["channel"] = parts[1]
                elif s.startswith("type AP"):
                    info["mode"] = info["mode"] or "AP"
            if info["mode"].lower() == "ap" or info["ssid"]:
                res["interfaces"].append(info)
        # leases: ip -> hostname
        by_mac, by_ip = {}, {}
        for line in sec.get("LEASES") or []:
            p = line.split()
            if len(p) >= 4:
                ip, mac, hostn = p[2], p[1].lower(), \
                    ("" if p[3] == "*" else p[3])
                if hostn:
                    by_mac[mac] = hostn
                    by_ip[ip] = hostn
        # arp: mac -> ip
        mac2ip = {}
        for line in sec.get("ARP") or []:
            p = line.split()
            # ip dev [scope] ... lladdr MAC [REACHABLE]
            if "lladdr" in p:
                i = p.index("lladdr")
                if i and i > 0 and len(p) >= i + 2:
                    ip = p[0]
                    if ip.count(".") == 3 or ":" in ip:
                        mac2ip[p[i + 1].lower()] = ip
        # enrich stations with hostname from leases and ip from arp
        for st in stations:
            st["hostname"] = by_mac.get(st["mac"], "")
            st["ip"] = mac2ip.get(st["mac"], "")
        res["clients"] = stations
        res["leases"] = by_ip
        return res


def wait_for_reboot(dev: OpenWRT, wait_s: int = 60, poll: int = 10,
                    timeout: int = 300) -> bool:
    """Poll until the device is reachable again after a reboot."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        if dev.is_online():
            return True
    return False
