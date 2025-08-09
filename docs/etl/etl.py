#!/usr/bin/env python3
"""
OpenOrigin CLI (local-only)
- Processes a media file entirely on the user's machine.
- Produces: manifest.json, metadata_released.json, and a *_package.zip
- Optional: signature (.sig) generated locally if user enables signing.
"""

import os, sys, json, hashlib, zipfile, time, subprocess
from pathlib import Path
import click

# ---------- Offline Guard (blocks accidental network use) ----------
def enforce_offline_mode():
    """Prevents any outbound sockets: hard stop if code tries to connect."""
    import socket
    real_socket = socket.socket
    class NoNetSocket(real_socket):
        def connect(self, *args, **kwargs):
            raise RuntimeError("Network use blocked: OpenOrigin runs local-only.")
    socket.socket = NoNetSocket
    os.environ["NO_PROXY"] = "*"
    os.environ["HTTPS_PROXY"] = ""
    os.environ["HTTP_PROXY"] = ""
    print("[offline] Network access blocked for this process.")

# ---------- Helpers ----------
def sha256_of_file(path: Path) -> str:
    """Stream SHA-256 for large files without loading into RAM"""
    print(f"[hash] Computing SHA-256 for: {path}")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    print(f"[hash] Done: {digest}")
    return digest

def run_exiftool(path: Path) -> dict:
    """Try to extract metadata using exiftool; fallback to empty dict if missing."""
    try:
        print("[meta] Running exiftool locally...")
        out = subprocess.check_output(["exiftool", "-json", str(path)], text=True)
        data = json.loads(out)[0] if out.strip().startswith("[") else {}
        print("[meta] exiftool completed.")
        return data
    except Exception as e:
        print(f"[meta] exiftool not available or failed: {e}")
        return {}

def apply_redactions(src_meta: dict, profile: dict) -> dict:
    """
    Redact fields according to profile rules.
    Example: profile["redact_fields"] = ["GPSLatitude", "GPSLongitude", "SerialNumber"]
    """
    print("[meta] Applying redactions per profile...")
    released = dict(src_meta)  # shallow copy
    for key in profile.get("redact_fields", []):
        if key in released:
            print(f"[meta] Redacting field: {key}")
            released.pop(key, None)
    return released

def write_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"[fs] Wrote JSON: {path}")

def make_deterministic_zip(zip_path: Path, files: dict):
    """
    Create a deterministic zip: fixed timestamps, sorted entries.
    files: { "name-in-zip": Path }
    """
    print(f"[zip] Creating package: {zip_path}")
    ts = (1980, 1, 1, 0, 0, 0)  # DOS earliest allowed timestamp for reproducibility
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files.keys()):
            fp = files[name]
            zi = zipfile.ZipInfo(name)
            zi.date_time = ts
            zi.compress_type = zipfile.ZIP_DEFLATED
            with fp.open("rb") as f:
                zf.writestr(zi, f.read())
    print("[zip] Package complete.")

# ---------- CLI ----------
@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--profile", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Path to a JSON profile defining redactions & options.")
@click.option("--outdir", type=click.Path(file_okay=False, path_type=Path), default=Path("./openorigin_out"))
@click.option("--sign", is_flag=True, help="Sign final ZIP with local private key (optional).")
def main(input_file: Path, profile: Path | None, outdir: Path, sign: bool):
    """
    Process INPUT_FILE locally; produce an OpenOrigin package ZIP plus manifest.
    """
    enforce_offline_mode()
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"[cli] Input: {input_file}")
    print(f"[cli] Outdir: {outdir}")

    # Load profile or use default
    prof = {"redact_fields": ["GPSLatitude", "GPSLongitude", "GPSPosition", "SerialNumber"]}
    if profile:
        print(f"[cli] Using profile: {profile}")
        prof = json.loads(Path(profile).read_text())

    # Hash media & extract metadata (local)
    delivered_sha = sha256_of_file(input_file)
    meta_original = run_exiftool(input_file)
    meta_released = apply_redactions(meta_original, prof)

    # Write metadata files
    meta_orig_path = outdir / "metadata_original.json"
    meta_rel_path  = outdir / "metadata_released.json"
    write_json(meta_orig_path, meta_original)           # include/exclude later per profile
    write_json(meta_rel_path,  meta_released)

    # Build manifest
    manifest = {
        "tool": "OpenOrigin",
        "version": "0.0.1-pre",
        "processed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "delivered_file": input_file.name,
        "hashes": {
            "delivered_sha256": delivered_sha,
            "metadata_released_sha256": sha256_of_file(meta_rel_path),
        },
        "profile": prof,
        "security": {
            "signed": bool(sign),
            "signature_file": "package.sig" if sign else None,
            "transparency_log_url": None  # optional future feature
        }
    }
    manifest_path = outdir / "manifest.json"
    write_json(manifest_path, manifest)

    # Stage package inputs (based on profile: you might omit metadata_original.json)
    staging = {
        input_file.name: input_file,
        "metadata_released.json": meta_rel_path,
        "manifest.json": manifest_path,
    }

    # Create ZIP
    zip_path = outdir / f"{input_file.stem}_package.zip"
    make_deterministic_zip(zip_path, staging)

    # Optional: sign locally (detached)
    if sign:
        try:
            print("[sig] Signing package locally with gpg…")
            subprocess.check_call(["gpg", "--detach-sign", "--armor", "--output", str(outdir/"package.sig"), str(zip_path)])
            print("[sig] Signature written: package.sig")
        except Exception as e:
            print(f"[sig] Skipped signing (gpg not available): {e}")

    print(f"[done] Package created: {zip_path.resolve()}")
    print("[note] Verify with the browser page by selecting the ZIP (no upload).")

if __name__ == "__main__":
    main()
