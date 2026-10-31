# OpenWRT Fleet Manager

> **Hinweis:** Dieses Projekt wurde KI-generiert — Quellcode, UI und Deployment
> wurden von einem KI-Agenten (Hermes Agent, Nous Research) in enger Zusammenarbeit
> mit dem Betreiber erstellt und getestet.

Deutsche FastAPI-Web-App zur Ueberwachung und Verwaltung einer OpenWRT-AP-Flotte
(SSH-Zugriff via paramiko, Live-Dashboard, WLAN-Client-Sicht, UCI-Edits, Backups).

## Stack

| Komponente | Beschreibung |
|---|---|
| Backend | FastAPI + uvicorn (`app/main.py`, `app/main:app`) |
| Scheduler | APScheduler – regelmaessig Survey der APs (WLAN-Clients, SSIDs, Interfaces) |
| SSH | paramiko (`app/sshx.py`) |
| Persistenz | SQLite (`/data/openwrtfleet.db`), Backups unter `/data/backups` |
| Frontend | Einzelne HTML-Seite (`static/index.html`), Polling alle 30 s |

## Struktur

```
├── app/
│   ├── main.py        # FastAPI-App, Endpoints, Auth, Bootstrap
│   ├── db.py          # SQLite-Wrapper (Geräte, Clients, User, Tokens)
│   ├── scheduler.py   # APScheduler-Jobs (Survey, Uptime, Load)
│   └── sshx.py        # SSH-Operationen (UCI, wifi status, ip neigh, …)
├── static/index.html  # Frontend
├── Dockerfile
├── requirements.txt
└── docker-compose.yml
```

## Docker-Deployment

```bash
git clone <repo-url>
cd openwrt-fleet-manager
OWF_ADMIN_PASSWORD='geheimes-passwort' docker compose up -d --build
```

- Port **8789** (Host → Container), Volume `./data:/data` für DB und Backups.
- **Erster Start:** Der Standard-Admin wird genau einmal angelegt.
  - Mit `OWF_ADMIN_PASSWORD` im Environment/`.env`: dieses Passwort gilt.
  - Ohne: wird ein Zufallspasswort generiert und per
    `docker logs openwrtfleet` ausgegeben (einmalig! danach im Web-UI unter
    „User“ ändern).
- Weitere Benutzer: Web-UI → „User“ (App-Benutzer, separat von den SSH-Credentials).
- AP-Credentials (root + Passwort) werden im Web-UI pro Gerät gepflegt, liegen
  in der DB – nie im Code/Repo.

### Ohne Compose (nackter docker run)

```bash
docker build -t openwrtfleet:latest .
docker run -d --name openwrtfleet --restart unless-stopped \
  -p 8789:8789 -v /pfad/zu/data:/data \
  -e OWF_ADMIN_USER=admin -e OWF_ADMIN_PASSWORD='geheimes-passwort' \
  openwrtfleet:latest
```

### Update / Rebuild

```bash
docker compose build --pull
# Container neu ERSTELLEN – `docker restart` genuegt NICHT,
# der existierende Container ist an die alte Image-ID gebunden:
docker compose down
docker compose up -d
```

### Backups

SQLite-DB wird bei Bedarf nach `/data/backups` gesichert (siehe `BACKUP_DIR`).
Das Verzeichnis `./data` ist der einzige persistenzierte Ort – bei Migration
einfach mitschleppen.

## Konfiguration (Environment)

| Variable | Default | Beschreibung |
|---|---|---|
| `OWF_ADMIN_USER` | `admin` | Username des Bootstraps-Admins (nur 1. Start) |
| `OWF_ADMIN_PASSWORD` | (generiert) | Passwort des Bootstraps-Admins (nur 1. Start) |
| `OPENWRT_FLEET_DB` | `/data/openwrtfleet.db` | Pfad der SQLite-DB |
| `OPENWRT_FLEET_BACKUPS` | `/data/backups` | Verzeichnis fuer Backups |
|| `OPENWRT_FLEET_DATA` | `/data` | Basis-Verzeichnis (Session-Secret u. a.) |

## Features

### Geräte-Überwachung
- **Live-Dashboard**: Status, Uptime, Load, LLDP-Nachbarn, FDB-Portbelegung (MAC-Tabelle)
- **WLAN-Clients**: Live-View mit SSID, Kanal, Signalstärke, IP, Hostname
- **SSID-Übersicht**: Alle SSIDs pro Radio, Kanalbelegung, Nutzung pro Kanal/AP (Canvas-Pie-Charts)
- **LLDP-Topologie**: Nachbarn speichern + grafische Graph-Ansicht (2-Min-Auto-Poll)
- **Bridge-FDB**: L2-Adjazenz pro Port (MAC-Tabelle), unabhängig von LLDP
- **Geräte-Filter**: Suche, Status-Anzeige (grün/gelb/grau), LLDP/Paket-Fehler

### Firmware-Updates
- **Firmware-Check**: Automatischer Check alle 3 h (`UPDATE_CHECK_HOURS=3`), Image-Download auf Router, Validierung (Magic-Bytes, squashfs-Header)
- **Sysupgrade**: Manuell und Auto-Flash (`auto_update=1`), preserve-Konfiguration, Warteschlange
- **Paket-Restore**: Vor Flash Snapshot aller Pakete → post-Flash Diff + automatischer Wiederaufbau (`apk add` No-Op wenn installiert)
- **Firmware-Wait**: `wait_for_reboot` 420 s, Status-Meldung nach Reboot, Fehlererkennung

### Update-Jobs (Pakete)
- **Paket-Update-Check**: Opkg/Apk/Rpm-Erkennung (busybox-kompatibel), Upgradable: `apk version -l`
- **Batch-Paket-Update**: Alle oder ausgewählte Pakete pro Gerät, Live-Log
- **SSH-Key-Auth**: Geräte können per SSH-Key oder Passwort authentifiziert werden (`auth_mode`/`ssh_key`)
- **Auto-Update**: Pro Gerät einstellbar (`auto_update=1`) → Firmware und Paket-Updates automatisch

### Gerätetypen
- **OpenWrt-Router/APs**: Standard-Firmware, sysupgrade, LLDP, FDB, WLAN-Survey
- **HP 1810-Switches**: Web-Interface (`kind='hp1810'`), kein SSH, virtuelle Info (Modell/Version/Uptime), LLDP/FDB über Bridge-FDB, UI blendet SSH-Funktionen aus
- **TP-Link TL-WPA4220**: Ausgesetzt (keine SSH, Web-Protokoll-RE existiert, Passwort-Login blockiert)

### UCI-Konfiguration
- UCI-Edits über SSH (`uci set/commit`), Konfigurations-Backup/Restore

## Versionshistorie

| Version | Datum | Beschreibung |
|---|---|---|
| — | 05.10.2026 | HP 1810-Switch (`hp1810`): Web-Only-Geräte, SSH-Guards, virtuelle Info, UI-Anpassungen |
| — | 04.10.2026 | Bridge-FDB/Port-Belegung: L2-Adjazenz pro Port, FDB-Dedup, Topologie-Integration |
| — | 03.10.2026 | LLDP-Topologie: LLDP-Poll, Graph-Ansicht, lldpd-Management (activate, missing/error), BusyBox-Pitfalls (timeout-Wrapper, rc-Propagation, json-Import) |
| — | 01.10.2026 | Paket-Restore nach sysupgrade (Snapshot → Diff → Reinstall); Update-Jobs (Batch/SSH-Key/Auto-Update/Paket-Check 3 h); Intervalle (Status 60 s, Survey 5 min, FW 3 h) |
| — | 30.09.2026 | Firmware-Update-Pfad: Image-Download+Validierung, sysupgrade preserve, wait_for_reboot, staging |
| — | 28.09.2026 | Dashboard: Canvas-Pie-Charts (Kanal/Nutzung), sortierbare Auslastungsspalte, `/api/clients`-Endpoint |
