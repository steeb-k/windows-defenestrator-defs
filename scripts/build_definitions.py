#!/usr/bin/env python3
"""
Build a Windows Defenestrator definition pack.

Steps:
  1. Download MalwareBazaar full hash export → hashes.db (SQLite)
  2. Clone/pull YARA rule sources → rules/
  3. Pack everything into definitions.zip
  4. Write manifest.json with SHA-256, counts, etc.

Run:
  python scripts/build_definitions.py --out dist/
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
import zipfile as zf
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/full/"

YARA_SOURCES = [
    {
        "name": "signature-base",
        "url": "https://github.com/Neo23x0/signature-base.git",
        "subdirs": ["yara"],
        "exclude_patterns": [
            r"_TESTING",
            r"_experimental",
            r"apt_",
        ],
    },
    {
        "name": "yara-rules",
        "url": "https://github.com/Yara-Rules/rules.git",
        "subdirs": ["malware", "exploit_kits", "packers"],
        "exclude_patterns": [
            r"_index\.yar",
            r"TESTING",
        ],
    },
]

APP_VERSION = "0.1.0"
BATCH_SIZE = 10_000

# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    print(f"  + {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


# ── Step 1: MalwareBazaar hashes ──────────────────────────────────────────────

def build_hash_db(out_dir: Path) -> int:
    """Download MalwareBazaar full CSV export, import into SQLite. Returns hash count."""
    db_path = out_dir / "hashes.db"

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            sha256   TEXT NOT NULL PRIMARY KEY,
            md5      TEXT,
            name     TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'high',
            source   TEXT DEFAULT 'malwarebazaar'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_md5 ON hashes(md5)")

    print(f"Downloading MalwareBazaar hash export from {MALWAREBAZAAR_URL} …", flush=True)

    req = urllib.request.Request(
        MALWAREBAZAAR_URL,
        headers={
            "User-Agent": "windows-defenestrator/0.1 (https://github.com/steeb-k/windows-defenestrator)",
            "Accept": "application/zip, application/octet-stream, */*",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            content_type = resp.headers.get("Content-Type", "")
            content_len  = resp.headers.get("Content-Length", "unknown")
            print(f"  Response: {resp.status}, Content-Type: {content_type}, Length: {content_len}", flush=True)
            data = resp.read()
    except Exception as e:
        print(f"  ERROR downloading: {e}", flush=True)
        return 0

    print(f"  Downloaded {len(data):,} bytes", flush=True)

    if len(data) < 1000:
        print(f"  WARNING: Response too small, content: {data[:200]!r}", flush=True)
        return 0

    # Unzip
    try:
        archive = zf.ZipFile(io.BytesIO(data))
    except zf.BadZipFile as e:
        print(f"  ERROR: Not a zip file: {e}. First 200 bytes: {data[:200]!r}", flush=True)
        return 0

    names = archive.namelist()
    print(f"  Zip contents: {names}", flush=True)

    csv_name = next((n for n in names if n.lower().endswith(".csv")), None)
    if not csv_name:
        print(f"  ERROR: No CSV file found in zip. Contents: {names}", flush=True)
        return 0

    print(f"  Parsing {csv_name} …", flush=True)
    csv_bytes = archive.read(csv_name)
    csv_text = csv_bytes.decode("utf-8", errors="replace")

    # Show first few non-comment lines for debugging
    sample_lines = [l for l in csv_text.splitlines()[:20] if not l.startswith("#")]
    print(f"  First non-comment lines: {sample_lines[:3]}", flush=True)

    reader = csv.reader(io.StringIO(csv_text))

    # Detect column indices from header
    sha256_col = md5_col = name_col = None
    rows = []
    row_count = 0

    for row in reader:
        if not row:
            continue

        # Skip comment lines
        if row[0].strip().startswith("#"):
            continue

        # Detect header row (contains column names, not hex hashes)
        if sha256_col is None:
            header = [c.strip().strip('"').lower() for c in row]
            print(f"  CSV header: {header}", flush=True)
            try:
                sha256_col = header.index("sha256_hash")
            except ValueError:
                # Some exports use different names
                for i, h in enumerate(header):
                    if "sha256" in h:
                        sha256_col = i
                        break
            try:
                md5_col = header.index("md5_hash")
            except ValueError:
                for i, h in enumerate(header):
                    if "md5" in h:
                        md5_col = i
                        break
            # Name: prefer "signature", fall back to "file_name"
            for candidate in ("signature", "file_name", "name"):
                try:
                    name_col = header.index(candidate)
                    break
                except ValueError:
                    pass

            if sha256_col is None:
                print(f"  ERROR: Could not find sha256 column in header: {header}", flush=True)
                return 0
            if md5_col is None:
                md5_col = 0  # fallback
            if name_col is None:
                name_col = sha256_col  # last resort

            print(f"  Column mapping: sha256={sha256_col}, md5={md5_col}, name={name_col}", flush=True)
            continue

        row_count += 1

        try:
            sha256 = row[sha256_col].strip().lower()
            md5    = row[md5_col].strip().lower() if md5_col < len(row) else ""
            raw_name = row[name_col].strip() if name_col < len(row) else ""
            name = (raw_name or "Unknown")[:200]
        except IndexError:
            continue

        if len(sha256) != 64:
            continue

        rows.append((
            sha256,
            md5 if len(md5) == 32 else None,
            name,
            "high",
            "malwarebazaar",
        ))

        if len(rows) >= BATCH_SIZE:
            conn.executemany("INSERT OR IGNORE INTO hashes VALUES (?,?,?,?,?)", rows)
            conn.commit()
            rows.clear()

        if row_count % 500_000 == 0:
            print(f"  … {row_count:,} rows processed", flush=True)

    if rows:
        conn.executemany("INSERT OR IGNORE INTO hashes VALUES (?,?,?,?,?)", rows)
        conn.commit()

    count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
    conn.close()

    print(f"  Processed {row_count:,} CSV rows, imported {count:,} hashes into {db_path}", flush=True)
    return count


# ── Step 2: YARA rules ────────────────────────────────────────────────────────

def collect_yara_rules(work_dir: Path, rules_out_dir: Path) -> int:
    """Clone/update YARA sources and copy rules. Returns rule file count."""
    rules_out_dir.mkdir(parents=True, exist_ok=True)
    rule_count = 0

    for source in YARA_SOURCES:
        repo_dir = work_dir / source["name"]
        if repo_dir.exists():
            print(f"Updating {source['name']} …", flush=True)
            try:
                run(["git", "-C", str(repo_dir), "pull", "--ff-only", "--quiet"])
            except subprocess.CalledProcessError:
                print(f"  Warning: pull failed for {source['name']}, using cached")
        else:
            print(f"Cloning {source['name']} …", flush=True)
            run(["git", "clone", "--depth=1", source["url"], str(repo_dir)])

        dest_dir = rules_out_dir / source["name"]
        dest_dir.mkdir(exist_ok=True)

        excl = [re.compile(p, re.IGNORECASE) for p in source.get("exclude_patterns", [])]

        for subdir in source["subdirs"]:
            src_path = repo_dir / subdir
            if not src_path.exists():
                print(f"  Subdir {subdir} not found in {source['name']}, skipping", flush=True)
                continue

            for ext in ("*.yar", "*.yara"):
                for yar in src_path.rglob(ext):
                    rel = yar.relative_to(src_path)
                    if any(p.search(str(rel)) for p in excl):
                        continue
                    dest = dest_dir / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(yar, dest)
                    rule_count += 1

    print(f"  Collected {rule_count} YARA rule files", flush=True)
    return rule_count


# ── Step 3: Pack & manifest ────────────────────────────────────────────────────

def pack(out_dir: Path, rules_dir: Path) -> tuple:
    """Create definitions.zip. Returns (path, sha256)."""
    zip_path = out_dir / "definitions.zip"

    with zf.ZipFile(zip_path, "w", zf.ZIP_DEFLATED, compresslevel=6) as z:
        db_path = out_dir / "hashes.db"
        z.write(db_path, "hashes.db")
        for f in sorted(rules_dir.rglob("*")):
            if f.is_file():
                z.write(f, f"rules/{f.relative_to(rules_dir)}")

    size_mb = zip_path.stat().st_size // 1024 // 1024
    digest = sha256_file(zip_path)
    print(f"  Packed {zip_path} ({size_mb} MB), sha256={digest[:16]}…", flush=True)
    return zip_path, digest


def write_manifest(out_dir, version, pack_url, pack_sha256, hash_count, rule_count):
    manifest = {
        "version": version,
        "released_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hash_count": hash_count,
        "rule_count": rule_count,
        "pack_url": pack_url,
        "pack_sha256": pack_sha256,
        "min_app_version": APP_VERSION,
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2))
    print(f"  Wrote manifest: version={version}, hashes={hash_count:,}, rules={rule_count}", flush=True)
    return path


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out",  default="dist")
    parser.add_argument("--work", default="work")
    parser.add_argument("--repo", default="steeb-k/windows-defenestrator-defs")
    args = parser.parse_args()

    out_dir  = Path(args.out)
    work_dir = Path(args.work)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    version   = datetime.now(timezone.utc).strftime("%Y%m%d")
    rules_dir = work_dir / "rules"

    print(f"\n=== Building definitions pack v{version} ===\n", flush=True)

    hash_count = build_hash_db(out_dir)
    rule_count = collect_yara_rules(work_dir, rules_dir)

    zip_path, sha256 = pack(out_dir, rules_dir)

    pack_url = (
        f"https://github.com/{args.repo}/releases/download/{version}/definitions.zip"
    )
    write_manifest(out_dir, version, pack_url, sha256, hash_count, rule_count)

    print(f"\n=== Done. Output in {out_dir}/ ===\n", flush=True)


if __name__ == "__main__":
    main()
