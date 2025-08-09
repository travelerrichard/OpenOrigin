# Originals ETL — Minimum-ETL for Sharing Original Media

Create an **Original File Package** (`*_package.zip`) for analysis:
- Lossless rewrap to `.mp4` where possible
- Metadata JSON (full or redacted)
- SHA-256 hashes
- `manifest.json` with actions taken
- **Profiles** now include optional security layers (signing, logging)

## Quick start
```bash
cd originals-etl/cli
python originals_etl.py /path/to/video.mov --profile redact
```
