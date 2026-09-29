FROM python:3.12-slim

WORKDIR /app
ENV OPENWRT_FLEET_DB=/data/openwrtfleet.db \
    OPENWRT_FLEET_BACKUPS=/data/backups

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/

EXPOSE 8789
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8789"]
