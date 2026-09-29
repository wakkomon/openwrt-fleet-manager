# OpenWRT Fleet Manager

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
| `OPENWRT_FLEET_DATA` | `/data` | Basis-Verzeichnis (Session-Secret u. a.) |
