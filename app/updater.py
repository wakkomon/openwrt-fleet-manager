# -*- coding: utf-8 -*-
"""Firmware-Update-Check + Auto-Update + Update-Jobs (Liste im UI).

Der Scheduler ruft check_one() alle 3 Stunden pro Router auf. Jedes Ergebnis
landet in der Tabelle update_jobs (UI-Tab "Update-Jobs"). Router mit
auto_update=1 werden automatisch geflasht (sysupgrade, Konfiguration bleibt
erhalten); manuelle Upgrades werden via db.add_update_job(..., source="manual")
in main.py geloggt und nach dem Reboot mit finalize_manual() abgeschlossen.
"""
import json
import threading

from . import db


def _now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


def _dev(row: dict):
    from . import scheduler
    return scheduler.make_device(row)


def _store_pkg_state(device_id: int, pkg: dict) -> None:
    """Paket-Update-Ergebnis in device_info (JSON) ablegen -> UI-Details."""
    try:
        info = db.get_device_info(device_id) or {}
        if not isinstance(info, dict):
            info = {}
        info["packages"] = {
            "pkgman": pkg.get("pkgman", ""),
            "count": pkg.get("count", 0),
            "packages": pkg.get("packages", [])[:12],
            "error": pkg.get("error") or "",
            "checked_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(timespec="seconds"),
        }
        db.upsert_device_info(device_id, json.dumps(info))
    except Exception:  # pragma: no cover
        pass


def _record(device_id: int, row: dict, status: str, version: str,
            message: str, source: str = "auto"):
    """Job anlegen; gleichartige Ruhezustands-Jobs nur bei Statuswechsel."""
    last = db.last_update_job(device_id)
    quiet = ("up-to-date", "update-available", "pkg-update", "offline")
    if last and last.get("status") == status and status in quiet:
        return None
    return db.add_update_job(device_id, row.get("name", ""), status, source,
                             version or "", message)


# ------------------------------------------------- package set (sysupgrade)
# Vor einem Flash wird die Liste der installierten Pakete (/etc/apk/world bzw.
# opkg list-installed) in device_info["pkg_restore"] gesichert. Nach dem
# Reboot diffen wir gegen den Ist-Zustand und installieren fehlende Pakete
# nach. pending bleibt True bis der Restore abgeschlossen ist: stirbt der
# Thread/Prozess dazwischen, holt der naechste check_one() (Scheduler-Tick
# oder "Jetzt prüfen") den Restore automatisch nach. Der prozessinterne
# Inflight-Set verhindert parallel laufende Restores desselben Routers.

_restore_inflight: set = set()


def _info_get(device_id: int) -> dict:
    info = db.get_device_info(device_id)
    return info if isinstance(info, dict) else {}


def snapshot_packages(device_id: int, dev) -> dict:
    """Paketstand vor einem Upgrade sichern (Basis für Re-Install)."""
    snap = dev.installed_packages()
    if snap.get("error") or not snap.get("names"):
        return snap
    info = _info_get(device_id)
    info["pkg_restore"] = {
        "pending": True,
        "names": snap["names"],
        "pkgman": snap.get("pkgman", ""),
        "saved_at": _now(),
    }
    db.upsert_device_info(device_id, json.dumps(info))
    return snap


def _claim_restore(device_id: int) -> list:
    """Pending-Restore beanspruchen -> Paketnamen ([] wenn keiner/aktiv)."""
    if device_id in _restore_inflight:
        return []
    info = _info_get(device_id)
    pr = info.get("pkg_restore")
    if not isinstance(pr, dict) or not pr.get("pending"):
        return []
    names = [n for n in (pr.get("names") or []) if n]
    if not names:
        pr["pending"] = False
        info["pkg_restore"] = pr
        db.upsert_device_info(device_id, json.dumps(info))
        return []
    _restore_inflight.add(device_id)
    return names


def _finish_restore(device_id: int, status: str, message: str) -> None:
    """Restore abschliessen: pending loeschen, Ergebnis protokollieren."""
    try:
        info = _info_get(device_id)
        pr = info.get("pkg_restore")
        if isinstance(pr, dict):
            pr["pending"] = False
            pr["status"] = status
            pr["finished_at"] = _now()
            pr["result"] = message[:300]
            info["pkg_restore"] = pr
            db.upsert_device_info(device_id, json.dumps(info))
    except Exception:  # pragma: no cover
        pass
    _restore_inflight.discard(device_id)


def run_restore(device_id: int) -> None:
    """Fehlende Pakete nach sysupgrade nachinstallieren (blockierend)."""
    names = _claim_restore(device_id)
    if not names:
        return
    row = db.get_device(device_id)
    if not row:
        _restore_inflight.discard(device_id)
        return
    dev = _dev(row)
    job = db.add_update_job(device_id, row.get("name", ""), "running",
                            "auto", "", "Paket-Restore: Diff gegen Snapshot")
    try:
        now = dev.installed_packages()
        have = set(now.get("names") or [])
        missing = [n for n in names if n not in have]
        if not missing:
            _finish_restore(device_id, "done",
                            "alle %d Pakete vorhanden" % len(names))
            db.finish_update_job(job, "done",
                                 "Paket-Restore: nichts zu tun (%d Pakete ok)"
                                 % len(names))
            return
        res = dev.reinstall_packages(missing)
        inst, failed = res.get("installed", []), res.get("failed", [])
        msg = ("%d Pakete installiert, %d fehlgeschlagen%s"
               % (len(inst), len(failed),
                  (": " + " ".join(failed[:6])) if failed else ""))
        if res.get("error"):
            msg += " | " + str(res["error"])[:200]
        status = "done" if not failed else "error"
        _finish_restore(device_id, status, msg)
        db.finish_update_job(job, status, "Paket-Restore: " + msg)
        db.add_job(device_id, "pkg-restore",
                   "ok" if status == "done" else "error", msg)
    except Exception as exc:  # pragma: no cover
        _finish_restore(device_id, "error", str(exc)[:200])
        db.finish_update_job(job, "error",
                             "Paket-Restore fehlgeschlagen: %s" % str(exc)[:200])
    finally:
        _restore_inflight.discard(device_id)


def _restore_thread(device_id: int) -> None:
    threading.Thread(target=run_restore, args=(device_id,),
                     daemon=True).start()


def ensure_restore(device_id: int) -> None:
    """Pending-Paket-Restore anstossen (nach Flash/Reboot). Doppel-Laeufe
    verhindert _claim_restore ueber den Inflight-Set."""
    if device_id in _restore_inflight:
        return
    info = _info_get(device_id)
    pr = info.get("pkg_restore")
    if isinstance(pr, dict) and pr.get("pending") and (pr.get("names") or []):
        _restore_thread(device_id)


def check_one(device_id: int):
    """Ein Router: erreichbar? Update-Check, Status in DB + Jobliste,
    Auto-Update wenn freigeschaltet. Gibt check_update()-Ergebnis zurück."""
    row = db.get_device(device_id)
    if not row:
        return None
    dev = _dev(row)
    if not dev.is_online():
        db.upsert_online(device_id, False)
        _record(device_id, row, "offline", "", "Router nicht erreichbar")
        return None
    db.upsert_online(device_id, True)
    # Nach einem Flash (Restore-Thread koennte abgestuerzt sein): pendingen
    # Paket-Restore hier nachholen, bevor der neue Check startet.
    ensure_restore(device_id)
    try:
        res = dev.check_update()
    except Exception as exc:  # pragma: no cover
        db.add_job(device_id, "firmware", "error", str(exc))
        _record(device_id, row, "error", "", "Check fehlgeschlagen: %s" % exc)
        return None
    db.set_firmware_state(device_id, res.get("current", ""),
                          res.get("latest", ""), bool(res.get("has_update")))
    db.add_job(device_id, "firmware",
               "update" if res.get("has_update") else "ok", json.dumps(res))
    # Paket-Updates (opkg/apk/rpm) — zusaetzlich zum Firmware-Check
    pkg = {}
    try:
        pkg = dev.package_check()
    except Exception as exc:  # pragma: no cover
        pkg = {"pkgman": "", "count": 0, "packages": [], "error": str(exc)[:160]}
    _store_pkg_state(device_id, pkg)
    if pkg.get("count"):
        names = " ".join(p.split()[0] for p in pkg.get("packages", [])[:2])
        db.add_job(device_id, "packages", "update", json.dumps(pkg))
        _record(device_id, row, "pkg-update", "",
                "%d Paket(s) aktualisierbar (%s, %s): %s%s" % (
                    pkg["count"], pkg.get("pkgman", "?"),
                    res.get("current", ""), names,
                    " …" if pkg["count"] > 2 else ""))
    elif pkg.get("error"):
        db.add_job(device_id, "packages", "error", pkg["error"])
    else:
        db.add_job(device_id, "packages", "ok", json.dumps(pkg))
    if res.get("error"):
        _record(device_id, row, "error", "", res["error"])
        return res
    if not res.get("has_update"):
        _record(device_id, row, "up-to-date", res.get("latest", ""),
                "%s ist aktuell" % res.get("current", ""))
        return res
    if not row.get("auto_update"):
        _record(device_id, row, "update-available", res.get("latest", ""),
                "Update %s verfügbar (Auto-Update aus)" % res.get("latest", ""))
        return res
    _auto_upgrade(device_id, row, res)
    return res


def _auto_upgrade(device_id: int, row: dict, res: dict) -> None:
    job = db.add_update_job(device_id, row.get("name", ""), "running", "auto",
                            res.get("latest", ""), "Auto-Update: Image wird geladen")
    db.add_job(device_id, "auto-update", "running",
               "flash %s" % res.get("latest", ""))
    dev = _dev(row)
    try:
        url = res.get("url") or ""
        if not url:
            raise RuntimeError("keine Image-URL im Check-Ergebnis")
        if url.startswith("http"):
            from .main import _stage_image_on_device
            staged = _stage_image_on_device(dev, url)
            image = staged["image"]
        else:
            image = url
        snapshot_packages(device_id, dev)
        rc, out, err = dev.sysupgrade(image, True, False)
        if rc != 0 and "started" not in out:
            raise RuntimeError("sysupgrade: %s" % (err or out or "rc=%s" % rc))
        db.finish_update_job(job, "running",
                             "sysupgrade gestartet, warte auf Reboot")
        from .sshx import wait_for_reboot
        ok = wait_for_reboot(dev, wait_s=20, poll=10, timeout=420)
        if not ok:
            db.finish_update_job(job, "error",
                                 "Router nach 420 s nicht erreichbar")
            db.add_job(device_id, "auto-update", "error",
                       "nicht wieder erreichbar")
            return
        try:
            res2 = dev.check_update()
        except Exception:
            res2 = {}
        newv = res2.get("current", "")
        latest = res.get("latest", "")
        db.set_firmware_state(device_id, newv or res.get("current", ""),
                              res2.get("latest", latest),
                              bool(res2.get("has_update")))
        if newv and latest and newv == latest:
            db.finish_update_job(job, "done", "geflasht auf %s" % newv)
            db.add_job(device_id, "auto-update", "ok",
                       "auf %s aktualisiert" % newv)
        else:
            db.finish_update_job(job, "done",
                                 "Reboot ok, Version jetzt: %s" % (newv or "?"))
            db.add_job(device_id, "auto-update", "ok",
                       "Reboot ok (%s)" % (newv or "?"))
        # fehlende Pakete aus dem Vor-Flash-Snapshot nachinstallieren
        _restore_thread(device_id)
    except Exception as exc:  # pragma: no cover
        db.finish_update_job(job, "error", "Auto-Update fehlgeschlagen: %s" % exc)
        db.add_job(device_id, "auto-update", "error", str(exc))


def finalize_manual(device_id: int, ok: bool) -> None:
    """Manuellen Upgrade-Job nach /firmware/wait abschliessen."""
    last = db.last_update_job(device_id)
    if last and last.get("source") == "manual" and last.get("status") == "running":
        db.finish_update_job(last["id"], "done" if ok else "error",
                             "Router wieder erreichbar ✓" if ok
                             else "Router nach Wartezeit nicht erreichbar")
    if ok:
        # Router ist nach dem Flash wieder da -> Paketsnapshot abarbeiten
        _restore_thread(device_id)


def run_checks(device_ids: list) -> None:
    """Update-Check über mehrere Router (Sofort-Lauf aus dem UI)."""
    for did in device_ids:
        try:
            check_one(did)
        except Exception as exc:  # pragma: no cover
            db.add_update_job(did, "", "error", "auto", "", str(exc))
