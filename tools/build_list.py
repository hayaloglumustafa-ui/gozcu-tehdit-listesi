#!/usr/bin/env python3
"""
Gözcü — tehdit listesi hazırlama ve imzalama aracı.

Ne yapar:
  1) Echap'ın açık stalkerware listesini (ioc.yaml, CC BY 4.0) indirir.
  2) Gözcü biçimine çevirir: paket adları + SHA-1 imza parmak izleri.
  3) Liste değişmediyse hiçbir şey yazmaz (gereksiz güncelleme olmaz).
  4) Değiştiyse yeni sürüm numarası verir ve ECDSA P-256 ile imzalar.

Çıktılar (--out-dir klasörüne):
  threat_list.signed.json  -> uygulamanın internetten indirdiği imzalı dosya
  threat_list.json         -> APK içine gömülecek düz liste (assets)

Güvenlik:
  - Özel anahtar yalnızca GOZCU_SIGNING_KEY ortam değişkeninden okunur, dosyaya yazılmaz.
  - Kaynak listede kayıt sayısı birden çok düşerse (ör. kaynak ele geçirilip boşaltıldıysa)
    yayın durdurulur.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.request

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SOURCE_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
SOURCE_NAME = "Echap stalkerware-indicators"
SOURCE_LICENSE = "CC BY 4.0"
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MIN_ENTRIES = 100            # bundan az kayıt varsa kaynak bozuk sayılır
MAX_DROP_RATIO = 0.30        # önceki listeye göre %30'dan fazla azalma yayınlanmaz

PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$")
SHA1_RE = re.compile(r"^[0-9A-F]{40}$")
SHA256_RE = re.compile(r"^[0-9A-F]{64}$")


def fetch_source(path_or_url: str) -> bytes:
    if os.path.exists(path_or_url):
        with open(path_or_url, "rb") as f:
            data = f.read(MAX_SOURCE_BYTES + 1)
    else:
        req = urllib.request.Request(path_or_url, headers={"User-Agent": "gozcu-list-builder"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        sys.exit("HATA: kaynak dosya beklenenden büyük")
    return data


def convert(raw: bytes) -> list:
    doc = yaml.safe_load(raw)
    if not isinstance(doc, list):
        sys.exit("HATA: kaynak biçimi değişmiş (liste bekleniyordu)")

    seen = set()
    entries = []

    def add(kind, value, name):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        entries.append({
            "type": kind,
            "value": value,
            "name": name[:100],
            "category": "stalkerware",
            "severity": "critical",
        })

    for item in doc:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        for pkg in item.get("packages") or []:
            pkg = str(pkg).strip()
            if PACKAGE_RE.match(pkg):
                add("package", pkg, name)
        for cert in item.get("certificates") or []:
            cert = str(cert).replace(":", "").replace(" ", "").strip().upper()
            if SHA1_RE.match(cert):
                add("cert_sha1", cert, name)
            elif SHA256_RE.match(cert):
                add("cert_sha256", cert, name)

    entries.sort(key=lambda e: (e["type"], e["value"]))
    return entries


def entries_hash(entries: list) -> str:
    blob = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def load_previous(path: str):
    """Önceki imzalı listeyi okur (imzayı burada doğrulamaya gerek yok; kendi dosyamız)."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        env = json.load(f)
    return json.loads(base64.b64decode(env["payload"]))


def load_key():
    pem = os.environ.get("GOZCU_SIGNING_KEY", "").strip()
    if not pem:
        sys.exit("HATA: GOZCU_SIGNING_KEY ortam değişkeni (özel anahtar) bulunamadı")
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        sys.exit("HATA: anahtar ECDSA P-256 olmalı")
    return key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=SOURCE_URL, help="ioc.yaml dosyası veya adresi")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--force", action="store_true", help="liste değişmese de yeniden imzala")
    args = ap.parse_args()

    signed_path = os.path.join(args.out_dir, "threat_list.signed.json")
    plain_path = os.path.join(args.out_dir, "threat_list.json")

    # Güvenlik: gizli anahtar, depodaki açık anahtarla (uygulamaya gömülü olanla) eşleşmeli.
    # Eşleşmezse her çalıştırmada hata verilir; uygulamanın reddedeceği bir liste asla yayınlanmaz.
    key = load_key()
    pub_path = os.path.join(args.out_dir, "public_key.pem")
    if os.path.exists(pub_path):
        with open(pub_path, "rb") as f:
            expected = serialization.load_pem_public_key(f.read())
        fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if key.public_key().public_bytes(*fmt) != expected.public_bytes(*fmt):
            sys.exit("HATA: GOZCU_SIGNING_KEY, public_key.pem ile eşleşmiyor; doğru anahtarı ekleyin")
    print("İmza anahtarı doğru.")

    entries = convert(fetch_source(args.source))
    if len(entries) < MIN_ENTRIES:
        sys.exit(f"HATA: yalnızca {len(entries)} kayıt bulundu; kaynak bozuk olabilir, yayınlanmadı")

    new_hash = entries_hash(entries)
    prev = load_previous(signed_path)
    if prev:
        if prev.get("entries_sha256") == new_hash and not args.force:
            print("Liste değişmedi; yeni sürüm yayınlanmadı.")
            return
        old_count = len(prev.get("entries", []))
        if old_count and len(entries) < old_count * (1 - MAX_DROP_RATIO):
            sys.exit(f"HATA: kayıt sayısı {old_count} -> {len(entries)} düştü; güvenlik için yayınlanmadı")

    version = int(dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H"))
    if prev and version <= int(prev.get("version", 0)):
        version = int(prev["version"]) + 1

    payload = {
        "schema": 1,
        "version": version,
        "updated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
        "source": SOURCE_NAME,
        "license": SOURCE_LICENSE,
        "entries_sha256": new_hash,
        "entries": entries,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    signature = key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))  # DER biçimi (Java ile uyumlu)
    key.public_key().verify(signature, payload_bytes, ec.ECDSA(hashes.SHA256()))  # kendi kendini sına

    envelope = {
        "format": "gozcu-signed-1",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    os.makedirs(args.out_dir, exist_ok=True)
    with open(signed_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, separators=(",", ":"))
        f.write("\n")
    with open(plain_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
        f.write("\n")

    kinds = {}
    for e in entries:
        kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    print(f"Yeni liste: sürüm {version}, {len(entries)} kayıt {kinds}")


if __name__ == "__main__":
    main()
