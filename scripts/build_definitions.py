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

# Primary: our own GitHub Release asset — fast, reliable, updated quarterly.
# Fallback: NIST's S3 bucket directly (used during bootstrap or if the release
# asset is missing).
NSRL_URL_PRIMARY  = "https://github.com/steeb-k/windows-defenestrator-defs/releases/download/nsrl-stable/rds_modernm.zip"
NSRL_URL_FALLBACK = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip"
# Windows PE/installer/driver extensions to allowlist from NSRL
NSRL_EXTS = {".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".msi", ".cab"}

YARA_SOURCES = [
    {
        "name": "signature-base",
        "url": "https://github.com/Neo23x0/signature-base.git",
        "subdirs": ["yara"],
        "exclude_patterns": [
            r"_TESTING",
            r"_experimental",
            r"apt_",
            r"gen_",        # generic infrastructure rules (IsPE64, IsPE32, etc.) — match every PE binary
        ],
    },
    {
        "name": "yara-rules",
        "url": "https://github.com/Yara-Rules/rules.git",
        "subdirs": ["malware", "exploit_kits", "packers"],
        "exclude_patterns": [
            r"_index\.yar",
            r"TESTING",
            r"packer_compiler_signatures",   # IsPE32/IsPE64 — match every PE binary
            r"Javascript_exploit_and_obfuscation",  # possible_includes_base64_packed_functions — too broad
        ],
    },
    {
        "name": "reversinglabs-yara-rules",
        "url": "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
        "subdirs": ["yara/ransomware", "yara/backdoor", "yara/trojan",
                    "yara/infostealer", "yara/virus", "yara/exploit",
                    "yara/downloader", "yara/rootkit"],
        "exclude_patterns": [],
    },
    {
        "name": "elastic-protections",
        "url": "https://github.com/elastic/protections-artifacts.git",
        "subdirs": ["yara/rules"],
        "exclude_patterns": [],
    },
]

APP_VERSION = "0.1.0"
BATCH_SIZE = 10_000

# ── YARA global exclusions ────────────────────────────────────────────────────
# Applied to ALL sources during post-copy cleanup, regardless of which source
# the file came from. Patterns are matched case-insensitively against filenames.
GLOBAL_EXCLUDE_PATTERNS = [
    r"_[Tt]est\b",    # *_Test, *_test suffix -- unit/integration test rules
    r"_[Tt]esting\b", # belt-and-suspenders alongside per-source _TESTING
]

# ── Hash quality filters ──────────────────────────────────────────────────────

# Minimum VirusTotal detection percentage required to import a hash.
# Dual-use tools (AutoIt, PsExec, 7-Zip, NirSoft, Sysinternals) typically
# score 0–15 %. Real malware with multi-engine consensus starts at ~50 %.
# Lower = broader coverage, higher = fewer false positives.
VTPERCENT_MIN = 50

# When vtpercent is "n/a" (no VT submission), also require ClamAV detection.
# Two independent signals required before importing an unverified hash.
# Set False to skip all n/a-vtpercent entries entirely instead.
REQUIRE_CLAMAV_FOR_NA_VT = True

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

    # MalwareBazaar full.csv has NO header row — data starts after # comment lines.
    # Fixed column layout (as of 2025):
    #   0: first_seen_utc  1: sha256_hash  2: md5_hash  3: sha1_hash
    #   4: reporter        5: file_name    6: file_type  7: mime_type
    #   8: signature (name) …
    SHA256_COL, MD5_COL, NAME_COL = 1, 2, 8
    CLAMAV_COL, VTPERCENT_COL     = 9, 10

    # MalwareBazaar uses "value", "value" format (space after comma),
    # so skipinitialspace=True is required for correct quoted-field parsing.
    reader = csv.reader(io.StringIO(csv_text), skipinitialspace=True)
    rows = []
    row_count = 0
    skipped_no_name = 0
    skipped_vt_low  = 0
    skipped_vt_na   = 0

    for row in reader:
        if not row:
            continue
        # Skip comment lines
        if row[0].strip().startswith("#"):
            continue
        if len(row) <= SHA256_COL:
            continue

        row_count += 1

        sha256 = row[SHA256_COL].strip().lower()
        md5    = row[MD5_COL].strip().lower()    if len(row) > MD5_COL       else ""
        name   = row[NAME_COL].strip()           if len(row) > NAME_COL      else ""
        clamav = row[CLAMAV_COL].strip()         if len(row) > CLAMAV_COL    else ""
        vt_raw = row[VTPERCENT_COL].strip()      if len(row) > VTPERCENT_COL else "n/a"

        # Filter 1: must have a malware classification name
        if not name or name.lower() == "n/a":
            skipped_no_name += 1
            continue

        name = name[:200]

        if len(sha256) != 64:
            continue

        # Filter 2: vtpercent quality gate
        if vt_raw.lower() == "n/a":
            if REQUIRE_CLAMAV_FOR_NA_VT:
                if not clamav or clamav.lower() == "n/a":
                    skipped_vt_na += 1
                    continue
                severity = "medium"   # ClamAV-only confirmation = medium confidence
            else:
                skipped_vt_na += 1
                continue
        else:
            try:
                vt_pct = float(vt_raw)
            except ValueError:
                skipped_vt_low += 1
                continue
            if vt_pct < VTPERCENT_MIN:
                skipped_vt_low += 1
                continue
            severity = "high" if vt_pct >= 75.0 else "medium"

        rows.append((
            sha256,
            md5 if len(md5) == 32 else None,
            name,
            severity,
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

    print(
        f"  Processed {row_count:,} CSV rows → imported {count:,} hashes "
        f"(skipped: {skipped_no_name:,} no-name, "
        f"{skipped_vt_low:,} low-VT <{VTPERCENT_MIN}%, "
        f"{skipped_vt_na:,} unverified no-VT)",
        flush=True,
    )
    return count


# ── Step 2: NSRL allowlist ────────────────────────────────────────────────────

def build_allowlist(out_dir: Path) -> int:
    """Download NSRL Modern Minimal RDS, import Windows executable SHA-256s as allowlist.
    Returns the number of allowlisted hashes inserted."""
    db_path = out_dir / "hashes.db"

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS allowlist (
            sha256 TEXT NOT NULL PRIMARY KEY
        )
    """)

    data = None
    for url in (NSRL_URL_PRIMARY, NSRL_URL_FALLBACK):
        print(f"Downloading NSRL from {url} …", flush=True)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "windows-defenestrator/0.1 (https://github.com/steeb-k/windows-defenestrator)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                content_len = resp.headers.get("Content-Length", "unknown")
                print(f"  Downloading ({content_len} bytes) …", flush=True)
                data = resp.read()
            print(f"  Downloaded {len(data):,} bytes", flush=True)
            break
        except Exception as e:
            print(f"  WARNING: download failed from {url}: {e}", flush=True)

    if not data:
        print("  ERROR: all NSRL download sources failed", flush=True)
        conn.close()
        return 0

    try:
        archive = zf.ZipFile(io.BytesIO(data))
    except zf.BadZipFile as e:
        print(f"  ERROR: Not a zip file: {e}", flush=True)
        conn.close()
        return 0

    names = archive.namelist()
    print(f"  NSRL zip contents: {names[:10]}", flush=True)

    # The flat file is called NSRLFile.txt (despite the extension, it's CSV)
    csv_name = next((n for n in names if "NSRLFile" in n), None)
    if not csv_name:
        print(f"  ERROR: NSRLFile not found in zip. Contents: {names}", flush=True)
        conn.close()
        return 0

    # NSRL RDS modern format header:
    # "SHA-1","MD5","SHA-256","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
    SHA256_COL = 2
    FILENAME_COL = 3

    print(f"  Parsing {csv_name} …", flush=True)
    rows = []
    row_count = 0

    with archive.open(csv_name) as f:
        reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
        next(reader, None)  # skip header row

        for row in reader:
            if len(row) <= FILENAME_COL:
                continue

            sha256 = row[SHA256_COL].strip().lower()
            filename = row[FILENAME_COL].strip()

            if len(sha256) != 64:
                continue

            ext = os.path.splitext(filename)[1].lower()
            if ext not in NSRL_EXTS:
                continue

            rows.append((sha256,))
            row_count += 1

            if len(rows) >= BATCH_SIZE:
                conn.executemany("INSERT OR IGNORE INTO allowlist VALUES (?)", rows)
                conn.commit()
                rows.clear()

            if row_count % 500_000 == 0:
                print(f"  … {row_count:,} NSRL executable entries processed", flush=True)

    if rows:
        conn.executemany("INSERT OR IGNORE INTO allowlist VALUES (?)", rows)
        conn.commit()

    count = conn.execute("SELECT COUNT(*) FROM allowlist").fetchone()[0]
    conn.close()

    print(f"  NSRL: processed {row_count:,} executable entries, {count:,} unique hashes in allowlist", flush=True)
    return count


# ── Step 3: YARA rules ────────────────────────────────────────────────────────

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

    # Post-copy cleanup: remove any rule file that matches ANY source's exclude
    # patterns. This catches files that slipped through (e.g. from a different
    # source or subdir than expected) and prevents AV from flagging the pack.
    all_excl = [
        re.compile(p, re.IGNORECASE)
        for source in YARA_SOURCES
        for p in source.get("exclude_patterns", [])
    ] + [
        re.compile(p, re.IGNORECASE)
        for p in GLOBAL_EXCLUDE_PATTERNS
    ]
    removed = 0
    for yar in rules_out_dir.rglob("*.yar"):
        if any(p.search(yar.name) for p in all_excl):
            yar.unlink()
            removed += 1
    for yar in rules_out_dir.rglob("*.yara"):
        if any(p.search(yar.name) for p in all_excl):
            yar.unlink()
            removed += 1
    if removed:
        rule_count -= removed
        print(f"  Removed {removed} excluded rule files in post-copy cleanup", flush=True)

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


def write_manifest(out_dir, version, pack_url, pack_sha256, hash_count, rule_count, allowlist_count):
    manifest = {
        "version": version,
        "released_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hash_count": hash_count,
        "rule_count": rule_count,
        "allowlist_count": allowlist_count,
        "pack_url": pack_url,
        "pack_sha256": pack_sha256,
        "min_app_version": APP_VERSION,
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2))
    print(f"  Wrote manifest: version={version}, hashes={hash_count:,}, rules={rule_count}, allowlist={allowlist_count:,}", flush=True)
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
    allowlist_count = build_allowlist(out_dir)
    rule_count = collect_yara_rules(work_dir, rules_dir)

    zip_path, sha256 = pack(out_dir, rules_dir)

    pack_url = (
        f"https://github.com/{args.repo}/releases/download/{version}/definitions.zip"
    )
    write_manifest(out_dir, version, pack_url, sha256, hash_count, rule_count, allowlist_count)

    print(f"\n=== Done. Output in {out_dir}/ ===\n", flush=True)


if __name__ == "__main__":
    main()
