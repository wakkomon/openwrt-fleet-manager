FROM python:3.12-slim

WORKDIR /app
ENV OPENWRT_FLEET_DB=/data/openwrtfleet.db \
    OPENWRT_FLEET_BACKUPS=/data/backups \
    OPENWRT_FLEET_DATA=/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/
COPY entrypoint.py ./entrypoint.py

EXPOSE 8789
# entrypoint.py stellt das TLS-Zert sicher (bestehendes /certs wird bevorzugt,
# sonst selbstsigniert nach /data/tls) und führt uvicorn mit HTTPS aus.
ENTRYPOINT ["python", "/app/entrypoint.py"]
