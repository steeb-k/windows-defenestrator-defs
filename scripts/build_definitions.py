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
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/full/"

YARA_SOURCES = [
    {
        "name": "signature-base",
        "url": "https://github.com/Neo23x0/signature-base.git",
        "subdirs": ["yara"],
        # Skip rules known to have high false-positive rates or require context
        "exclude_patterns": [
            r"_TESTING",
            r"_experimental",
            r"apt_",          # APT rules often FP on benign tools
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

# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"  + {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


# ── Step 1: MalwareBazaar hashes ──────────────────────────────────────────────

def build_hash_db(out_dir: Path) -> int:
    """Download MalwareBazaar full CSV export, import into SQLite. Returns hash count."""
    import urllib.request
    import zipfile as zf

    print("Downloading MalwareBazaar hash export…")
    db_path = out_dir / "hashes.db"

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
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

    with urllib.request.urlopen(MALWAREBAZAAR_URL, timeout=120) as resp:
        data = resp.read()

    # The export is a zip containing full.csv
    with zf.ZipFile(io.BytesIO(data)) as z:
        csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
        csv_data = z.read(csv_name).decode("utf-8", errors="replace")

    reader = csv.reader(io.StringIO(csv_data))
    rows = []
    for row in reader:
        # Skip comment lines
        if not row or row[0].startswith("#"):
            continue
        # Columns: first_seen, sha256_hash, md5_hash, sha1_hash, reporter,
        #          file_name, file_type_guess, mime_type, signature, clamav,
        #          vtpercent, imphash, tlsh, characteristic_tags
        if len(row) < 8:
            continue
        sha256 = row[1].strip().lower()
        md5    = row[2].strip().lower()
        name   = (row[8].strip() or row[5].strip() or "Unknown")[:200]
        if len(sha256) != 64:
            continue
        rows.append((sha256, md5 if len(md5) == 32 else None, name, "high", "malwarebazaar"))
        if len(rows) >= 5000:
            conn.executemany(
                "INSERT OR IGNORE INTO hashes VALUES (?,?,?,?,?)", rows
            )
            rows.clear()

    if rows:
        conn.executemany("INSERT OR IGNORE INTO hashes VALUES (?,?,?,?,?)", rows)

    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
    conn.close()

    print(f"  Imported {count:,} hashes into {db_path}")
    return count


# ── Step 2: YARA rules ────────────────────────────────────────────────────────

def collect_yara_rules(work_dir: Path, rules_out_dir: Path) -> int:
    """Clone/update YARA sources and copy rules. Returns rule file count."""
    rules_out_dir.mkdir(parents=True, exist_ok=True)
    rule_count = 0

    for source in YARA_SOURCES:
        repo_dir = work_dir / source["name"]
        if repo_dir.exists():
            print(f"Updating {source['name']}…")
            try:
                run(["git", "-C", str(repo_dir), "pull", "--ff-only", "--quiet"])
            except subprocess.CalledProcessError:
                print(f"  Warning: pull failed for {source['name']}, using cached")
        else:
            print(f"Cloning {source['name']}…")
            run(["git", "clone", "--depth=1", source["url"], str(repo_dir)])

        dest_dir = rules_out_dir / source["name"]
        dest_dir.mkdir(exist_ok=True)

        excl = [re.compile(p, re.IGNORECASE) for p in source.get("exclude_patterns", [])]

        for subdir in source["subdirs"]:
            src_path = repo_dir / subdir
            if not src_path.exists():
                print(f"  Subdir {subdir} not found, skipping")
                continue

            for yar in src_path.rglob("*.yar"):
                rel = yar.relative_to(src_path)
                rel_str = str(rel)

                if any(p.search(rel_str) for p in excl):
                    continue

                dest = dest_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(yar, dest)
                rule_count += 1

            for yar in src_path.rglob("*.yara"):
                rel = yar.relative_to(src_path)
                dest = dest_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(yar, dest)
                rule_count += 1

    print(f"  Collected {rule_count} YARA rule files")
    return rule_count


# ── Step 3: Pack & manifest ────────────────────────────────────────────────────

def pack(out_dir: Path, rules_dir: Path) -> tuple[Path, str]:
    """Create definitions.zip from hashes.db + rules/. Returns (path, sha256)."""
    zip_path = out_dir / "definitions.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        db_path = out_dir / "hashes.db"
        z.write(db_path, "hashes.db")

        for f in sorted(rules_dir.rglob("*")):
            if f.is_file():
                z.write(f, f"rules/{f.relative_to(rules_dir)}")

    digest = sha256_file(zip_path)
    print(f"  Packed {zip_path} ({zip_path.stat().st_size // 1024 // 1024} MB), sha256={digest[:16]}…")
    return zip_path, digest


def write_manifest(
    out_dir: Path,
    version: str,
    pack_url: str,
    pack_sha256: str,
    hash_count: int,
    rule_count: int,
) -> Path:
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
    print(f"  Wrote manifest: version={version}, hashes={hash_count:,}, rules={rule_count}")
    return path


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist", help="Output directory")
    parser.add_argument("--work", default="work", help="Working directory (cloned repos)")
    parser.add_argument("--repo", default="steeb-k/windows-defenestrator-defs",
                        help="GitHub repo slug for release URL construction")
    args = parser.parse_args()

    out_dir = Path(args.out)
    work_dir = Path(args.work)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    version = datetime.now(timezone.utc).strftime("%Y%m%d")
    rules_dir = work_dir / "rules"

    print(f"\n=== Building definitions pack v{version} ===\n")

    hash_count = build_hash_db(out_dir)
    rule_count = collect_yara_rules(work_dir, rules_dir)

    zip_path, sha256 = pack(out_dir, rules_dir)

    pack_url = (
        f"https://github.com/{args.repo}/releases/download/{version}/definitions.zip"
    )

    write_manifest(out_dir, version, pack_url, sha256, hash_count, rule_count)

    print(f"\n=== Done. Output in {out_dir}/ ===\n")


if __name__ == "__main__":
    main()
