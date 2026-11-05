# -*- coding: utf-8 -*-
"""Background jobs: status checks, client scans, full surveys, firmware checks.

All device data lands in the local SQLite cache (device_info, clients,
survey_snapshots) so the UI and search work without live SSH round-trips.
"""
import json

from apscheduler.schedulers.background import BackgroundScheduler

from . import db
from .hp import HpSwitch
from .sshx import OpenWRT


def _kind(row: dict) -> str:
    return row.get("kind") or "openwrt"


def make_device(row: dict):
    """Collector passend zur Geraete-Art bauen.

    openwrt -> OpenWRT (SSH)
    unifi   -> UniFiSwitch (SSH, Ubiquiti swctrl; Subklasse von OpenWRT)
    pfsense -> PfSense (Web-Interface HTTPS, kein SSH)
    hp1810  -> nicht hier (make_hp)
    """
    kind = _kind(row)
    if kind == "pfsense":
        from .pfsense import PfSense
        port = row["port"] or 443
        if port == 22:  # SSH-Default ist fuer pfSense sinnlos -> Web-Port
            port = 443
        return PfSense(
            ip=row["ip"], port=port, user=row["user"],
            password=row["password"],
        )
    if kind == "unifi":
        from .unifi import UniFiSwitch
        return UniFiSwitch(
            ip=row["ip"], port=row["port"], user=row["user"],
            password=row["password"], firmware_dir=row.get("firmware_dir") or "",
            ssh_key=row.get("ssh_key") or "",
            auth_mode=row.get("auth_mode") or "password",
            ssh_key_passphrase=row.get("ssh_key_passphrase") or "",
        )
    return OpenWRT(
        ip=row["ip"], port=row["port"], user=row["user"],
        password=row["password"], firmware_dir=row.get("firmware_dir") or "",
        ssh_key=row.get("ssh_key") or "",
        auth_mode=row.get("auth_mode") or "password",
        ssh_key_passphrase=row.get("ssh_key_passphrase") or "",
    )


def make_hp(row: dict) -> HpSwitch:
    """HP-1810/ProCurve-Switch (Web-Interface, kein SSH) bauen."""
    port = row["port"] or 80
    if port == 22:  # SSH-Default ist fuer HP sinnlos -> Web-Port
        port = 80
    return HpSwitch(row["name"], row["ip"], row["password"], port)


def _is_hp(row: dict) -> bool:
    return (row.get("kind") or "openwrt") == "hp1810"


def _is_pfsense(row: dict) -> bool:
    return (row.get("kind") or "openwrt") == "pfsense"


def _is_web(row: dict) -> bool:
    """Web-verwaltete Geraete ohne SSH: HP-Switch und pfSense."""
    return _is_hp(row) or _is_pfsense(row)


def check_status(device_id: int) -> None:
    row = db.get_device(device_id)
    if not row:
        return
    if _is_hp(row):
        db.upsert_online(device_id, make_hp(row).is_online())
        return
    dev = make_device(row)
    if _is_pfsense(row):
        # pfSense: volle Web-Info holen; Login-/Erreichbarkeitsfehler als
        # Grund im device_info hinterlegen (UI zeigt ihn in den Details).
        try:
            info = dev.full_info()
        except Exception as exc:  # pragma: no cover
            db.upsert_online(device_id, False)
            db.upsert_device_info(device_id,
                                  json.dumps({"error": str(exc)[:300]}))
            db.add_job(device_id, "status", "error", str(exc)[:300])
            return
        err = (info.get("error") or "")
        online = not err
        db.upsert_online(device_id, online)
        db.upsert_device_info(device_id, json.dumps(info))
        if err:
            db.add_job(device_id, "status", "error", err[:300])
        return
    online = dev.is_online()
    db.upsert_online(device_id, online)


def scan_clients(device_id: int) -> None:
    row = db.get_device(device_id)
    if not row:
        return
    if _is_pfsense(row):
        # pfSense: keine SSH-ARP/WLAN-Clients
        return
    if (row.get("kind") or "") == "unifi":
        # UniFi-Switch: MAC-Tabelle (FDB) als LAN-Clients ablegen.
        dev = make_device(row)
        if not dev.is_online():
            db.upsert_online(device_id, False)
            return
        db.upsert_online(device_id, True)
        try:
            fdb_res = dev.poll_fdb()
            fdb = fdb_res.get("rows", []) if isinstance(fdb_res, dict) else fdb_res
            db.save_fdb(device_id, fdb)
            # rows: (bridge, port, port_name, mac) — port-Label aus port_name
            db.replace_clients(device_id, "lan",
                               [("", r[3], "",
                                 r[2] or ("Port %s" % r[1]))
                                for r in fdb])
            db.replace_clients(device_id, "wlan", [])
        except Exception as exc:  # pragma: no cover
            db.add_job(device_id, "scan", "error", str(exc))
        return
    dev = make_device(row)
    if not dev.is_online():
        db.upsert_online(device_id, False)
        return
    db.upsert_online(device_id, True)
    try:
        lan = dev.lan_clients()
        wlan = dev.wlan_clients()
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
                           [(w.get("ip") or "", w["mac"],
                             w.get("hostname") or "",
                             w.get("ssid") or "", w.get("signal") or "")
                            for w in wlan])
    except Exception as exc:  # pragma: no cover
        db.add_job(device_id, "scan", "error", str(exc))


def _poll_hp(device_id: int, row: dict) -> None:
    """HP-Switch ueber Web-Interface pollen: LLDP-Nachbarn + MAC-Tabelle
    in die Topologie-/FDB-Struktur persistieren (kein SSH, kein lldpd)."""
    sw = make_hp(row)
    try:
        data = sw.poll()
    except Exception as exc:  # pragma: no cover
        db.upsert_online(device_id, False)
        db.add_job(device_id, "lldp", "error", str(exc))
        return
    errs = data.get("errors") or []
    login_err = [e for e in errs if e.startswith("login:")]
    db.upsert_online(device_id, not login_err)
    fdb_rows, fdb_msg = [], "fdb: n/a"
    if not any(e.startswith("mac_table:") for e in errs):
        for m in data.get("mac_table") or []:
            for p in m.get("ports") or []:
                fdb_rows.append(("br0", p, "Port %d" % p, m.get("mac")))
        db.save_fdb(device_id, fdb_rows)
        fdb_msg = "%d MACs" % len(fdb_rows)
        if fdb_rows:
            # MAC-Liste (Clients) automatisch aktuell halten.
            db.replace_clients(device_id, "lan",
                               [("", r[3] or "", "", r[2] or "")
                                for r in fdb_rows])
            db.replace_clients(device_id, "wlan", [])
    nb = [{
        "interface": n.get("iface") or "",
        "mac": n.get("mac") or "",
        "chassis_id": n.get("chassis_id") or "",
        "port_id": n.get("port_id") or "",
        "neighbor_name": n.get("sys_name") or "",
        "neighbor_descr": n.get("sys_desc") or "",
        "port_descr": n.get("port_id") or "",
        "mgmt_ip": n.get("mgmt_ip") or "",
        "hostname": "",
    } for n in (data.get("lldp_neighbors") or [])]
    local = {
        "local_chassis": {"id": row["name"], "name": row["name"], "mac": "",
                          "descr": "HP 1810/ProCurve", "mgmt-ip": row["ip"]},
        "lldpd": "hp-web", "version": "", "error": "; ".join(errs)[:300],
    }
    db.save_lldp(device_id, local, nb)
    prefix = ("; ".join(login_err)[:160] + " | ") if login_err else ""
    db.add_job(device_id, "lldp", "ok" if not login_err else "error",
               "%s%d Nachbarn | %s" % (prefix, len(nb), fdb_msg))


def poll_lldp(device_id: int) -> None:
    """LLDP-Poll: lldpctl -f json auf dem Router, Nachbarn + lokales Chassis
    in SQLite persistieren. Reverse-DNS (Hostname) erfolgt bereits in
    `poll_lldp` des sshx-Layers. Fehler werden als Job + Status vermerkt,
    die gespeicherte Topologie bleibt dabei erhalten.

    Zusätzlich wird in derselben SSH-Verbindung die Bridge-FDB
    (`brctl showmacs`) erfasst — sie liefert die L2-Adjazenz
    ("wer hängt an welchem Port") und ist unabhängig von lldpd, daher auch
    dann nützlich, wenn kein LLDP-Daemon läuft und 0 Nachbarn gemeldet
    werden.
    """
    row = db.get_device(device_id)
    if not row:
        return
    if _is_pfsense(row):
        # pfSense wird per Web-Interface verwaltet; LLDP/FDB gibt es dort nicht.
        db.upsert_online(device_id, make_device(row).is_online())
        return
    if _is_hp(row):
        _poll_hp(device_id, row)
        return
    dev = make_device(row)
    # Bridge-FDB zuerst (eigene, robuste Abfrage) — funktioniert auch,
    # wenn lldpd fehlt; eigener Try, damit ein FDB-Fehler das LLDP nicht
    # stört und umgekehrt.
    try:
        fdb_res = dev.poll_fdb()
        fdb_rows = fdb_res.get("rows", [])
        db.save_fdb(device_id, fdb_rows)
        fdb_msg = "%d MACs" % len(fdb_rows)
        if (row.get("kind") or "") == "unifi" and fdb_rows:
            # MAC-Liste (Clients) automatisch aktuell halten: FDB = Clients.
            # rows: (bridge, port, port_name, mac)
            db.replace_clients(device_id, "lan",
                               [("", r[3] or "", "",
                                 r[2] or ("Port %s" % r[1]))
                                for r in fdb_rows])
            db.replace_clients(device_id, "wlan", [])
    except Exception as exc:  # pragma: no cover
        fdb_msg = "fdb: %s" % exc

    try:
        res = dev.poll_lldp()
    except Exception as exc:  # pragma: no cover
        db.upsert_online(device_id, False)
        db.add_job(device_id, "lldp", "error",
                   "%s | %s" % (str(exc), fdb_msg))
        return
    if res.get("error") and not res.get("neighbors"):
        # lldpd fehlt/laeuft nicht — Status merken, nichts loeschen
        db.save_lldp(device_id, res, [])
        db.add_job(device_id, "lldp", "ok",
                   "lldpd %s (%s) | %s"
                   % (res.get("lldpd"), res["error"][:60], fdb_msg))
        return
    db.upsert_online(device_id, True)
    db.save_lldp(device_id, res, res.get("neighbors", []))
    db.add_job(device_id, "lldp", "ok",
               "%d Nachbarn | %s"
               % (len(res.get("neighbors", [])), fdb_msg))


def survey_device(device_id: int) -> None:
    """One SSH round-trip -> everything into the cache:
    uptime, hostname (auto-rename), model/version, WLAN SSIDs+channels,
    clients with signal, traffic rates (snapshot for history)."""
    row = db.get_device(device_id)
    if not row:
        return
    if _is_hp(row):
        return  # Switch ohne SSH: Status/LLDP/FDB laufen ueber poll_lldp
    if (row.get("kind") or "") == "unifi":
        # UniFi-Switch: SSH-Survey bringt nur System-Info; die MAC-Tabelle
        # (FDB) als LAN-Clients holen, sonst bleibt die Liste leer.
        scan_clients(device_id)
        return
    dev = make_device(row)
    try:
        res = dev.survey()
    except Exception as exc:
        db.upsert_online(device_id, False)
        db.add_job(device_id, "survey", "error", str(exc))
        return None
    if not res:
        db.upsert_online(device_id, False)
        return
    db.upsert_online(device_id, True)

    # auto hostname update: use router's own hostname until the user
    # renamed the entry manually (manual name kept in devices.name once it
    # differs from the previous auto value)
    host = res.get("hostname") or ""
    current = row["name"]
    prev_info = db.get_device_info(device_id) or {}
    manual = bool(prev_info.get("manual"))
    # auto-rename only while the name is still the auto-managed one;
    # a manual rename sets the "manual" flag (device_info) and wins.
    # Kollisionsschutz: nicht auf einen Namen umbenennen, den bereits ein
    # anderes Geraet fuehrt (sonst taucht z.B. "AP-OG4" doppelt auf).
    taken = any((d["name"] or "").strip() == host.strip()
                for d in db.list_devices() if d["id"] != device_id)
    if host and current != host and not manual and not taken:
        db.rename_device(device_id, host)

    leases = res.get("leases") or {}          # ip -> hostname
    clients = res.get("clients") or []        # station dump entries
    ifaces = res.get("interfaces") or []
    iface_ssid = {i["iface"]: i.get("ssid", "") for i in ifaces}
    # reverse lease lookup by hostname is not possible without ARP;
    # clients keep IP empty unless a later ARP scan fills it in
    db.replace_clients(device_id, "wlan",
                       [(c.get("ip") or "", c["mac"],
                         c.get("hostname") or "",
                         iface_ssid.get(c.get("iface", ""), ""),
                         c.get("signal") or "")
                        for c in clients])
    db.replace_clients(device_id, "lan",
                       [(ip, "", host, "")
                        for ip, host in leases.items() if ip])

    per_iface = {}
    for c in clients:
        k = c.get("iface") or ""
        per_iface[k] = per_iface.get(k, 0) + 1
    ssids = [{"iface": i["iface"], "ssid": i["ssid"],
              "channel": i["channel"], "band": i["band"],
              "clients": per_iface.get(i["iface"], 0)}
             for i in ifaces]
    info = {k: v for k, v in res.items() if k != "leases"}
    info["leases"] = leases
    info["ssids"] = ssids
    info["manual"] = manual
    info["auto_name"] = host or current
    info["refreshed_at"] = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat(timespec="seconds")
    # Keys, die der Firmware/Paket-Check (alle 3 h) in device_info schreibt,
    # muessen ueberleben: upsert_device_info ersetzt das komplette JSON,
    # sonst verschwinden packages/pkg_restore bei jedem 5-min-Survey-Tick.
    for keep in ("packages", "pkg_restore"):
        if keep in prev_info:
            info[keep] = prev_info[keep]
    db.upsert_device_info(device_id, json.dumps(info))

    db.add_snapshot(device_id, res.get("uptime_s", 0),
                    res.get("rx_bps", 0), res.get("tx_bps", 0),
                    res.get("rx_total", 0), res.get("tx_total", 0),
                    len(clients), len(leases), ssids)
    db.add_job(device_id, "survey", "ok",
               f"{len(clients)} WLAN-Clients, {len(leases)} Lease")
    return res


def check_firmware(device_id: int) -> None:
    from . import updater
    updater.check_one(device_id)


def _all_ids():
    return [d["id"] for d in db.list_devices()]


def _status_all():
    for did in _all_ids():
        check_status(did)


def _lldp_all():
    for did in _all_ids():
        try:
            poll_lldp(did)
        except Exception as exc:  # pragma: no cover
            db.add_job(did, "lldp", "error", str(exc))


def _survey_all():
    for did in _all_ids():
        try:
            survey_device(did)
        except Exception as exc:  # pragma: no cover
            db.add_job(did, "survey", "error", str(exc))


def _firmware_all():
    for did in _all_ids():
        check_firmware(did)


def _initial_surveys():
    """Right after startup, survey every device once so the dashboard has data."""
    import threading

    def run():
        import time
        time.sleep(3)
        _survey_all()
        time.sleep(1)
        _lldp_all()
    threading.Thread(target=run, daemon=True).start()


_scheduler = None
SURVEY_MINUTES = 5
UPDATE_CHECK_HOURS = 3
LLDP_MINUTES = 2


def start():
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(_status_all, "interval", seconds=60,
                       id="status", max_instances=1, coalesce=True)
    _scheduler.add_job(_lldp_all, "interval", minutes=LLDP_MINUTES,
                       id="lldp", max_instances=1, coalesce=True)
    _scheduler.add_job(_survey_all, "interval", minutes=SURVEY_MINUTES,
                       id="survey", max_instances=1, coalesce=True)
    _scheduler.add_job(_firmware_all, "interval", hours=UPDATE_CHECK_HOURS,
                       id="firmware", max_instances=1, coalesce=True)
    _scheduler.start()
    _initial_surveys()
    return _scheduler


def shutdown():
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass
