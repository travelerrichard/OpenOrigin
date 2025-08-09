# OpenOrigin: High-Priority Hardening PR

This PR updates `originals_etl.py` and CI to ensure local-only processing, deterministic packaging, manifest rigor, and optional signing.

## Highlights
- Offline guard (default) with `--allow-network` escape hatch.
- Deterministic ZIP + atomic JSON writes.
- Package `.zip.sha256` sidecar + self-verify routine.
- Profile SHA, tool versions in `manifest.json`.
- Optional GPG signing (official/user) and optional transparency log POST.
- CI validates manifests & redaction-rule JSONs (when present), plus ruff/mypy (non-fatal).

## Layout
```
helpers/profiles/         # profile JSONs (preserve/redact variants)
schemas/                  # manifest & redaction_profile schemas
.github/workflows/ci.yml  # schema validation + ruff/mypy
samples/                  # auto-written last_run_manifest.json after ETL run
tests/test_schema.py      # minimal schema test
```
