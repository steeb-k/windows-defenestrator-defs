# windows-defenestrator-defs

Threat definition packs for [Windows Defenestrator](https://github.com/steeb-k/windows-defenestrator).

Updated daily via GitHub Actions. Each release contains:

- `hashes.db` — SQLite database of known-malicious SHA-256 and MD5 hashes sourced from [MalwareBazaar](https://bazaar.abuse.ch/)
- `rules/` — Curated YARA rules from [neo23x0/signature-base](https://github.com/Neo23x0/signature-base) and [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
- `manifest.json` — Version metadata consumed by the app

## Release format

```json
{
  "version": "20260317",
  "released_at": "2026-03-17T02:00:00Z",
  "hash_count": 1234567,
  "rule_count": 842,
  "pack_url": "https://github.com/steeb-k/windows-defenestrator-defs/releases/download/20260317/definitions.zip",
  "pack_sha256": "abc123...",
  "min_app_version": "0.1.0"
}
```

## Sources

| Source | License | Notes |
|--------|---------|-------|
| [MalwareBazaar](https://bazaar.abuse.ch/) | CC0 | Daily malware hash exports |
| [neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | CC BY-NC 4.0 | High-quality, low-FP YARA rules |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | Various (see repo) | Community YARA rules |
