#!/usr/bin/env python3
"""Compile les listes de menaces publiques en 4 fichiers normalisés pour l'application.

Sortie (dossier passé en argument, par défaut ./public/feeds) :
  domains.txt  urls.txt  ips.txt  sha256.txt  manifest.json
Normalisation identique à lib/engine/local_threat_db.dart (parseFeed).
Code de sortie 1 si TOUTES les sources échouent (le déploiement de la veille reste alors en ligne).
Bibliothèque standard uniquement.
"""
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CFG = json.loads((HERE / "sources.json").read_text(encoding="utf-8"))
OFFICIAL = set(CFG["official_domains_never_listed"])
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "public/feeds")
MAX_BYTES = 25 * 1024 * 1024

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SHA_RE = re.compile(r"\b([a-f0-9]{64})\b")


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    return ".".join(parts[-3:]) if last2 in ("gouv.fr", "co.uk") else last2


def is_official(host: str) -> bool:
    return registrable(host) in OFFICIAL or host in OFFICIAL or any(host.endswith("." + o) for o in OFFICIAL)


def norm_host(line: str):
    s = line.lower()
    s = re.sub(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+", "", s)
    s = re.sub(r"^\|\|", "", s)
    s = re.sub(r"^[a-z]+://", "", s)
    s = re.split(r"[\^/$\s:#]", s)[0]
    if s.startswith("www."):
        s = s[4:]
    if not HOST_RE.match(s) or is_official(s):
        return None
    return s


def norm_url(line: str) -> str:
    s = re.sub(r"^[a-z]+://", "", line.strip().lower())
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip("/")


def parse(kind: str, body: str) -> set:
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] in "#![":
            continue
        if kind == "domains":
            h = norm_host(line)
            if h:
                out.add(h)
        elif kind == "urls":
            u = norm_url(line)
            if u:
                out.add(u)
        elif kind == "ips":
            m = IP_RE.search(line)
            if m:
                out.add(m.group(1))
        elif kind == "hashes":
            m = SHA_RE.search(line.lower())
            if m:
                out.add(m.group(1))
    return out


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "safebank-feeds-builder/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("taille au-delà de la limite")
    return data.decode("utf-8", errors="replace")


def main() -> int:
    buckets = {"domains": set(), "urls": set(), "ips": set(), "hashes": set()}
    status = {}
    for src in CFG["sources"]:
        if not src.get("commercial_use"):
            status[src["id"]] = f"ignorée ({src.get('enabled_note', 'licence')})"
            continue
        try:
            entries = parse(src["kind"], fetch(src["url"]))
            buckets[src["kind"]] |= entries
            status[src["id"]] = f"ok ({len(entries)} entrées)"
        except Exception as e:  # noqa: BLE001 - on veut continuer avec les autres sources
            status[src["id"]] = f"erreur {type(e).__name__}"
    ok = [k for k, v in status.items() if v.startswith("ok")]
    print(json.dumps(status, ensure_ascii=False, indent=1))
    if not ok:
        print("Toutes les sources ont échoué : rien n'est publié.", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    files = {"domains": "domains.txt", "urls": "urls.txt", "ips": "ips.txt", "hashes": "sha256.txt"}
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "sources": status, "files": {}}
    for kind, name in files.items():
        content = "\n".join(sorted(buckets[kind]))
        (OUT / name).write_text(content, encoding="utf-8")
        manifest["files"][name] = {"entries": len(buckets[kind]), "sha256": hashlib.sha256(content.encode()).hexdigest()}
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
