#!/usr/bin/env python3
"""Container entrypoint: stellt das TLS-Zert fuers Web-UI (HTTPS) sicher.

Reihenfolge:
  1. Liegt cert.pem + key.pem unter /certs (read-only Mount eines bestehenden
     Zerts), werden diese unveraendert verwendet.
  2. Sonst wird unter dem Daten-Volume (/data/tls, persistent) genau einmal ein
     selbstsigniertes Zert erzeugt und wiederverwendet. Der Container startet
     damit auch bei leerem /certs zuverlässig über HTTPS; die Browser-Warnung
     bleibt über Neustarts stabil, weil das Zert im Daten-Volume persistiert.

TLS_SAN (optional, kommagetrennt): z.B. "IP:192.168.82.24,DNS:dev,DNS:openwrtfleet".
Default: IP:127.0.0.1,DNS:localhost,DNS:openwrtfleet
"""
import datetime
import ipaddress
import os
import pathlib

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"
DEFAULT_SAN = ["IP:127.0.0.1", "DNS:localhost", "DNS:openwrtfleet"]


def parse_san(raw):
    tokens = [t.strip() for t in (raw or "").split(",") if t.strip()]
    return tokens or DEFAULT_SAN


def build_san_extension(tokens):
    entries = []
    for tok in tokens:
        kind, _, value = tok.partition(":")
        if not value:
            continue
        if kind.upper() == "IP":
            entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        else:
            entries.append(x509.DNSName(value))
    return x509.SubjectAlternativeName(entries)


def ensure_selfsigned(out_dir, san_tokens):
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / CERT_NAME
    key_path = out_dir / KEY_NAME
    marker = out_dir / ".san"
    stored = marker.read_text().strip() if marker.exists() else ""
    used = ",".join(san_tokens)
    if cert_path.exists() and key_path.exists() and (not stored or stored == used):
        return out_dir
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openwrtfleet")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(build_san_extension(san_tokens), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    marker.write_text(used)
    print(f"[entrypoint] generated self-signed TLS cert in {out_dir} (SAN: {used})", flush=True)
    return out_dir


def main():
    san_tokens = parse_san(os.environ.get("TLS_SAN"))
    port = os.environ.get("OPENWRT_FLEET_PORT", "8789")

    mount = pathlib.Path("/certs")
    if (mount / CERT_NAME).exists() and (mount / KEY_NAME).exists():
        cert, key = mount / CERT_NAME, mount / KEY_NAME
        src = "mount"
    else:
        data_dir = os.environ.get("OPENWRT_FLEET_DATA", "/data")
        d = ensure_selfsigned(os.path.join(data_dir, "tls"), san_tokens)
        cert, key = d / CERT_NAME, d / KEY_NAME
        src = "auto-generated"

    print(f"[entrypoint] TLS: using {src} cert={cert} key={key}", flush=True)
    args = [
        "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", port,
        "--ssl-certfile", str(cert), "--ssl-keyfile", str(key),
    ]
    os.execvp("uvicorn", args)


if __name__ == "__main__":
    main()
