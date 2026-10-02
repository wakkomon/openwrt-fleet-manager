# -*- coding: utf-8 -*-
"""Background jobs: status checks, client scans, full surveys, firmware checks.

All device data lands in the local SQLite cache (device_info, clients,
survey_snapshots) so the UI and search work without live SSH round-trips.
"""
import json

from apscheduler.schedulers.background import BackgroundScheduler

from . import db
from .sshx import OpenWRT


def make_device(row: dict) -> OpenWRT:
    return OpenWRT(
        ip=row["ip"], port=row["port"], user=row["user"],
        password=row["password"], firmware_dir=row.get("firmware_dir") or "",
        ssh_key=row.get("ssh_key") or "",
        auth_mode=row.get("auth_mode") or "password",
    )


def check_status(device_id: int) -> None:
    row = db.get_device(device_id)
    if not row:
        return
    dev = make_device(row)
    online = dev.is_online()
    db.upsert_online(device_id, online)


def scan_clients(device_id: int) -> None:
    row = db.get_device(device_id)
    if not row:
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


def survey_device(device_id: int) -> None:
    """One SSH round-trip -> everything into the cache:
    uptime, hostname (auto-rename), model/version, WLAN SSIDs+channels,
    clients with signal, traffic rates (snapshot for history)."""
    row = db.get_device(device_id)
    if not row:
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
    if host and current != host and not manual:
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
    threading.Thread(target=run, daemon=True).start()


_scheduler = None
SURVEY_MINUTES = 5
UPDATE_CHECK_HOURS = 3


def start():
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(_status_all, "interval", seconds=60,
                       id="status", max_instances=1, coalesce=True)
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
