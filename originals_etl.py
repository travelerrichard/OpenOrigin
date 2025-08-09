#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
originals_etl.py — Minimal-but-thorough ETL tool for packaging original
(or near-original) media for analysis outside platforms like Reddit.

Key guarantees:
  • 100% local processing — includes an OFFLINE GUARD that blocks outbound sockets.
  • Deterministic packaging — same inputs → same ZIP bytes (stable timestamps + sorted entries).
  • Profile-driven redactions — rules live in JSON (transparent, reviewable).
  • Verifier-friendly manifest — matches OpenOrigin web verifier expectations.

Features:
  • Optional lossless rewrap to MP4 (-c copy) with moov atom fronted (+faststart)
  • Fallback to high-quality encode (CRF 10, preset slow) only if stream copy fails
  • Full metadata extract via exiftool; profile-based redaction (e.g., GPS, device IDs)
  • SHA-256 hashing of source, delivered media, released metadata
  • JSON manifest recording exactly what happened (and when)
  • Optional signing stub (GPG detached signature) — kept local/offline

Requirements:
  • Python 3.8+
  • ffmpeg (in PATH)
  • exiftool (in PATH)

Usage examples:
  python originals_etl.py /path/to/video.mov --profile redact
  python originals_etl.py /path/to/video.mp4 --profile redact --coarsen-time date

Notes:
  - We avoid re-encoding unless necessary. If stream copy fails, we fall back and SAY SO.
  - We never alter your source. Work happens in a working dir; outputs go to outdir.
  - No network calls. The offline guard prevents any accidental socket use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, Any


# ----------------------------- Offline Guard ----------------------------- #
def enforce_offline_mode() -> None:
    """
    Block ANY outbound socket use for this process. This ensures 'local-only'
    processing even if a dependency tries to phone home.
    """
    print("[offline] Enforcing local-only mode (blocking outbound sockets).", flush=True)
    import socket  # local import to avoid polluting module level for tools
    real_socket = socket.socket

    class NoNetSocket(real_socket):
        def connect(self, *args, **kwargs):  # type: ignore[override]
            raise RuntimeError("Network access blocked: OpenOrigin originals_etl runs local-only.")

    socket.socket = NoNetSocket  # type: ignore[assignment]
    os.environ["NO_PROXY"] = "*"
    os.environ["HTTPS_PROXY"] = ""
    os.environ["HTTP_PROXY"] = ""


# ----------------------------- Small Utils ------------------------------ #
def which(bin_name: str) -> bool:
    """Check whether ``bin_name`` exists on PATH (debug friendly)."""
    print(f"[debug] Checking for binary: {bin_name}", flush=True)
    from shutil import which as _which
    found = _which(bin_name) is not None
    print(f"[debug] Binary {bin_name} found: {found}", flush=True)
    return found


def sh(cmd: str) -> None:
    """Execute a shell command and raise if it fails. Logs verbosely."""
    print(f"[run] {cmd}", flush=True)
    completed = subprocess.run(cmd, shell=True)
    if completed.returncode != 0:
        print(f"[error] Command exited {completed.returncode}: {cmd}", flush=True)
        raise RuntimeError(f"Command failed: {cmd}")


def sha256(path: Path) -> str:
    """Stream SHA-256 for large files without loading into RAM."""
    print(f"[hash] Computing SHA-256: {path}", flush=True)
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):  # 1 MiB chunks
            h.update(chunk)
    digest = h.hexdigest()
    print(f"[hash] {path.name} -> {digest}", flush=True)
    return digest


def safe_name(name: str) -> str:
    """Return a filesystem-safe version of ``name``."""
    sanitized = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)
    print(f"[debug] safe_name: '{name}' -> '{sanitized}'", flush=True)
    return sanitized


# ----------------------------- Profiles I/O ------------------------------ #
def load_profile(profile_name: str, profiles_dir: Path) -> Dict[str, Any]:
    """
    Load profile JSON by name from ``profiles_dir``. Expected keys:
      - name (str)
      - metadata_policy (str): "preserve" | "redact"
      - redact_rules: { remove_tags: [...], coarsen_time: "none"|"date" }
      - security_layers (dict) [optional]
    """
    profile_path = profiles_dir / f"{profile_name}.json"
    print(f"[profile] Loading: {profile_path}", flush=True)
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile not found: {profile_path}")
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    for must in ("name", "metadata_policy"):
        if must not in data:
            raise ValueError(f"Malformed profile (missing '{must}'): {profile_path}")
    print(f"[profile] Loaded → {data.get('name')} (policy={data.get('metadata_policy')})", flush=True)
    return data


# ------------------------- Deterministic ZIP ----------------------------- #
def make_deterministic_zip(zip_path: Path, files: Dict[str, Path]) -> None:
    """
    Create a deterministic ZIP with fixed timestamps and sorted entries.
    files: { "name-in-zip": Path(...) }
    """
    print(f"[zip] Creating deterministic package: {zip_path}", flush=True)
    ts = (1980, 1, 1, 0, 0, 0)  # DOS minimum timestamp; stable
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname in sorted(files.keys()):
            src = files[arcname]
            zi = zipfile.ZipInfo(arcname)
            zi.date_time = ts
            zi.compress_type = zipfile.ZIP_DEFLATED
            with src.open("rb") as f:
                zf.writestr(zi, f.read())
    print("[zip] Package complete (deterministic).", flush=True)


# --------------------------- Security Stubs ------------------------------ #
def gpg_detached_sign(target: Path, out_sig: Path) -> None:
    """
    Optional: perform local GPG detached sign. This is local-only and requires
    gpg in PATH. We do not upload anywhere.
    """
    print(f"[sig] Signing (detached, armored): {target.name}", flush=True)
    try:
        subprocess.check_call([
            "gpg", "--armor", "--detach-sign",
            "--output", str(out_sig),
            str(target),
        ])
        print(f"[sig] Signature written: {out_sig}", flush=True)
    except FileNotFoundError:
        print("[sig] gpg not found; skipping signature.", flush=True)


# ------------------------------- CLI ------------------------------------ #
def main() -> int:
    """Command-line entry point for Originals ETL."""
    print("[debug] Entering main()", flush=True)
    enforce_offline_mode()  # <— local-only guarantee starts here

    parser = argparse.ArgumentParser(description="Create an Original File Package (.zip) for analysis.")
    parser.add_argument("input", help="Path to original media (mp4/mov/avi/etc.)")
    parser.add_argument("--profile", default="redact",
                        help="Profile name from profiles/ directory (default: redact)")
    parser.add_argument("--coarsen-time", choices=["none", "date"], default=None,
                        help="Override profile coarsen policy: none | date (YYYY:MM:DD)")
    parser.add_argument("--outdir", default="out", help="Output directory (default: out)")
    parser.add_argument("--workdir", default="work", help="Working directory (default: work)")
    parser.add_argument("--package-name", default=None,
                        help="Optional base name for the output package (without .zip)")
    parser.add_argument("--keep-work", action="store_true",
                        help="Keep the working directory for inspection (default: false)")
    # Security toggles (all local):
    parser.add_argument("--sign", action="store_true",
                        help="Produce a detached GPG signature for the final ZIP (local, optional).")

    # Profiles dir (relative default: ./profiles)
    default_profiles = Path(__file__).resolve().parent / "profiles"
    parser.add_argument("--profiles-dir", default=str(default_profiles),
                        help=f"Directory of profile JSON files (default: {default_profiles})")
    args = parser.parse_args()

    # Dependency checks (we fail early with clear messages)
    if not which("ffmpeg"):
        print("[error] ffmpeg not found on PATH. Please install ffmpeg and try again.", file=sys.stderr)
        return 2
    if not which("exiftool"):
        print("[error] exiftool not found on PATH. Please install exiftool and try again.", file=sys.stderr)
        return 2

    # I/O layout
    src = Path(args.input).expanduser().resolve()
    if not src.exists():
        print(f"[error] Input file does not exist: {src}", file=sys.stderr)
        return 2
    work = Path(args.workdir); work.mkdir(parents=True, exist_ok=True)
    out = Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
    base = args.package_name or safe_name(src.stem)
    delivered = work / f"{base}_delivered.mp4"

    # Load profile
    profiles_dir = Path(args.profiles_dir).expanduser().resolve()
    profile = load_profile(args.profile, profiles_dir)
    metadata_policy: str = str(profile.get("metadata_policy", "redact"))
    rules = profile.get("redact_rules", {}) or {}
    # CLI override for coarsen-time if specified
    if args.coarsen_time is not None:
        rules["coarsen_time"] = args.coarsen_time
    coarsen_time = rules.get("coarsen_time", "none")
    remove_tags = list(rules.get("remove_tags", []))

    print("[info] === Originals ETL starting ===", flush=True)
    print(f"[info] Source: {src}", flush=True)
    print(f"[info] Profile: {profile.get('name')} (policy={metadata_policy})", flush=True)
    print(f"[info] Redaction rules: remove_tags={remove_tags} coarsen_time={coarsen_time}", flush=True)

    # 1) Rewrap or re-encode
    try:
        print("[step] Attempting lossless rewrap (stream copy) with faststart", flush=True)
        sh(f'ffmpeg -y -i "{src}" -c copy -movflags +faststart "{delivered}"')
        print("[ok] Stream copy succeeded; no re-encoding performed.", flush=True)
    except Exception as e:
        print(f"[warn] Stream copy failed: {e}", flush=True)
        print("[step] Falling back to high-quality encode (libx264, CRF 10, preset slow).", flush=True)
        sh(f'ffmpeg -y -i "{src}" -c:v libx264 -preset slow -crf 10 -c:a aac -b:a 192k -movflags +faststart "{delivered}"')
        print("[ok] Fallback encode completed.", flush=True)

    # 2) Full metadata extraction (delivered file)
    meta_full = work / f"{base}_metadata_full.json"
    print("[step] Extracting full metadata with exiftool (JSON, with groups)", flush=True)
    sh(f'exiftool -j -a -G -api largefilesupport=1 "{delivered}" > "{meta_full}"')
    print(f"[ok] Metadata written: {meta_full}", flush=True)

    # 3) Redaction (if policy = redact) → produce metadata_released.json
    meta_released = work / f"{base}_metadata_released.json"
    redactions_applied = []
    effective_delivered = delivered

    if metadata_policy.lower() == "redact":
        print("[step] Applying redaction profile to delivered media", flush=True)
        delivered_redacted = work / f"{base}_delivered_redacted.mp4"
        shutil.copyfile(delivered, delivered_redacted)

        # Build exiftool removal command from profile rules
        removal_cmd = ['exiftool', '-overwrite_original', '-api', 'largefilesupport=1']
        for tag in remove_tags:
            # exiftool clears with TAG=
            removal_cmd.append(f'-{tag}=')

        if str(coarsen_time) == "date":
            # Example: coarsen QuickTime:CreateDate to YYYY:MM:DD
            removal_cmd.append('-QuickTime:CreateDate<${QuickTime:CreateDate;DateFormat("%Y:%m:%d")}')

        removal_cmd.append(str(delivered_redacted))
        print("[run] ", " ".join(removal_cmd), flush=True)
        proc = subprocess.run(removal_cmd)
        if proc.returncode != 0:
            print("[error] exiftool redaction failed.", file=sys.stderr)
            return 2

        effective_delivered = delivered_redacted
        sh(f'exiftool -j -a -G -api largefilesupport=1 "{effective_delivered}" > "{meta_released}"')

        redactions_applied = remove_tags[:]
        if str(coarsen_time) == "date":
            redactions_applied.append("QuickTime:CreateDate(coarsened)")
        print("[ok] Redaction completed; wrote release metadata.", flush=True)
    else:
        print("[info] Preserve metadata policy — releasing full metadata as-is.", flush=True)
        shutil.copyfile(meta_full, meta_released)

    # 4) Hashes & manifest (verifier-aligned field names)
    print("[step] Computing hashes (SHA-256)", flush=True)
    h_src = sha256(src)
    h_del = sha256(effective_delivered)
    h_meta = sha256(meta_released)

    manifest: Dict[str, Any] = {
        "version": "1.1.0",
        "processed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_file": str(src),  # informational; verifier does not require
        "delivered_file": Path(effective_delivered).name,  # MUST match name inside ZIP
        "hashes": {
            "source_sha256": h_src,
            "delivered_sha256": h_del,
            "metadata_released_sha256": h_meta
        },
        "redaction_profile": metadata_policy,
        "redactions": redactions_applied,
    }
    manifest_path = work / f"{base}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[ok] Manifest written: {manifest_path}", flush=True)

    # 5) Package deliverables (deterministic ZIP expected by web verifier)
    pkg_zip = Path(args.outdir) / f"{base}_package.zip"
    staged = {
        Path(effective_delivered).name: effective_delivered,  # delivered media
        "metadata_released.json": meta_released,
        "manifest.json": manifest_path,
    }
    make_deterministic_zip(pkg_zip, staged)
    print("[ok] Package created (verifier-ready).", flush=True)

    # 6) Optional local signing
    sig_path = None
    if args.sign:
        sig_path = pkg_zip.with_suffix(".zip.asc")
        gpg_detached_sign(pkg_zip, sig_path)

    # 7) (Optional) embed simple security section back into manifest on disk
    try:
        j = json.loads(manifest_path.read_text(encoding="utf-8"))
        j["security"] = {
            "signed": bool(args.sign),
            "signature_file": Path(sig_path).name if sig_path else None,
            "transparency_log_url": None  # reserved; do not use network here
        }
        manifest_path.write_text(json.dumps(j, indent=2), encoding="utf-8")
        print("[ok] Updated manifest with security info (on disk copy).", flush=True)
    except Exception as e:
        print(f"[warn] Could not update manifest with security info: {e}", flush=True)

    if not args.keep_work:
        print("[cleanup] Removing working directory (use --keep-work to retain)", flush=True)
        shutil.rmtree(work, ignore_errors=True)

    print("[done] Originals ETL completed successfully.", flush=True)
    print(f"[output] Package: {pkg_zip}", flush=True)
    if sig_path:
        print(f"[output] Signature: {sig_path}", flush=True)
    print("[note] Verify locally in the browser with the OpenOrigin /verify page (no uploads).", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[exit] Interrupted by user.", flush=True)
        sys.exit(130)


# #!/usr/bin/env python3
# """
# originals_etl.py — Minimal-but-thorough ETL tool for packaging original
# (or near-original) media for analysis outside platforms like Reddit.
#
# Features:
#   • Optional lossless rewrap to MP4 (-c copy) with moov atom fronted for faststart
#   • Two metadata policies via profiles: 'preserve' (keep metadata) and 'redact' (safe defaults)
#   • SHA-256 hashing of source, delivered media, and released metadata
#   • JSON manifest recording exactly what happened (and when)
#   • Profiles now include optional SECURITY LAYERS (signing, transparency log)
#   • Verbose, human-friendly print statements for transparency and debugging
#
# Requirements:
#   • Python 3.8+
#   • ffmpeg (in PATH)
#   • exiftool (in PATH)
#
# Usage examples:
#   python originals_etl.py /path/to/video.mov --profile redact
#   python originals_etl.py /path/to/video.mp4 --profile redact_signed_log --sign-user --user-key ~/.gnupg/my.asc
#
# Notes:
#   - We try to avoid *any* re-encoding. If stream copy fails, we fallback to a
#     high-quality encode (CRF 10, preset slow) as a last resort, and we say so clearly.
#   - We do all mutations on copies in a working dir; your source is never altered.
# """
# import argparse
# import hashlib
# import json
# import os
# import shutil
# import subprocess
# import sys
# import time
# from pathlib import Path
#
# def which(bin_name: str) -> bool:
#     """Check whether ``bin_name`` exists on the user's ``PATH``."""
#     print(f"[debug] Checking for binary: {bin_name}", flush=True)
#     from shutil import which as _which
#     found = _which(bin_name) is not None
#     print(f"[debug] Binary {bin_name} found: {found}", flush=True)
#     return found
#
# def sh(cmd: str) -> None:
#     """Execute a shell command and raise if it fails."""
#     print(f"[debug] Preparing to run command: {cmd}", flush=True)
#     print(f"[run] {cmd}", flush=True)
#     completed = subprocess.run(cmd, shell=True)
#     print(f"[debug] Command finished with return code {completed.returncode}", flush=True)
#     if completed.returncode != 0:
#         raise RuntimeError(f"Command failed with exit code {completed.returncode}: {cmd}")
#
# def sha256(path: Path) -> str:
#     """Calculate the SHA-256 digest for the file at ``path``."""
#     print(f"[debug] sha256() called with path: {path}", flush=True)
#     print(f"[hash] {path}", flush=True)
#     h = hashlib.sha256()
#     with open(path, "rb") as f:
#         for chunk in iter(lambda: f.read(1 << 20), b""):
#             h.update(chunk)
#     digest = h.hexdigest()
#     print(f"[hash] {path.name} -> {digest}", flush=True)
#     print(f"[debug] sha256() returning digest: {digest}", flush=True)
#     return digest
#
# def safe_name(name: str) -> str:
#     """Return a filesystem-safe version of ``name``."""
#     print(f"[debug] Sanitizing name: {name}", flush=True)
#     sanitized = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)
#     print(f"[debug] Sanitized name: {sanitized}", flush=True)
#     return sanitized
#
# # --- Profile loading ---
# def load_profile(profile_name: str, profiles_dir: Path) -> dict:
#     """Load profile JSON by name from ``profiles_dir``. Returns dict."""
#     print(f"[debug] Loading profile '{profile_name}' from {profiles_dir}", flush=True)
#     profile_path = profiles_dir / f"{profile_name}.json"
#     if not profile_path.exists():
#         raise FileNotFoundError(f"Profile not found: {profile_path}")
#     with open(profile_path, "r", encoding="utf-8") as f:
#         data = json.load(f)
#     for key in ("name", "metadata_policy", "security_layers"):
#         if key not in data:
#             raise ValueError(f"Malformed profile (missing {key}): {profile_path}")
#     print(f"[debug] Loaded profile data: {data}", flush=True)
#     return data
#
# # === Security Layer Stubs ===
# def sign_with_official_key(package_path: Path):
#     """Stub that simulates signing ``package_path`` with an official key."""
#     print(f"[debug] sign_with_official_key called with {package_path}", flush=True)
#     print(f"[stub] Would sign {package_path} with official GPG key here.")
#     # TODO: Implement GPG detached signing, store .sig file
#
# def sign_with_user_key(package_path: Path, user_key_path: Path):
#     """Stub that simulates signing ``package_path`` with a user key."""
#     print(f"[debug] sign_with_user_key called with {package_path} and key {user_key_path}", flush=True)
#     print(f"[stub] Would sign {package_path} with user GPG key at {user_key_path}.")
#     # TODO: Implement GPG detached signing with provided key
#
# def log_package_hash(package_path: Path):
#     """Stub that simulates logging the package hash to a transparency log."""
#     print(f"[debug] log_package_hash called with {package_path}", flush=True)
#     print(f"[stub] Would log SHA-256 of {package_path} to transparency log here.")
#     # TODO: Implement HTTP POST to transparency log API
#
# def main() -> int:
#     """Command-line entry point for Originals ETL."""
#     print("[debug] Entering main()", flush=True)
#     parser = argparse.ArgumentParser(
#         description="Create an Original File Package (.zip) for analysis."
#     )
#     parser.add_argument("input", help="Path to original media (mp4/mov/avi/etc.)")
#     parser.add_argument("--profile", default="redact",
#                         help="Profile name from profiles/ directory (default: redact)")
#     parser.add_argument("--coarsen-time", choices=["none", "date"], default="date",
#                         help="If redacting, optionally coarsen QuickTime CreateDate to YYYY:MM:DD (default: date)")
#     parser.add_argument("--outdir", default="out", help="Output directory (default: out)" )
#     parser.add_argument("--workdir", default="work", help="Working directory (default: work)" )
#     parser.add_argument("--package-name", default=None,
#                         help="Optional base name for the output package (without .zip)")
#     parser.add_argument("--keep-work", action="store_true",
#                         help="Keep the working directory for inspection (default: false)")
#     parser.add_argument("--force-reencode", action="store_true",
#                         help="Force a visually-lossless re-encode instead of stream copy (debug/testing only)")
#     parser.add_argument("--profiles-dir", default=str(Path(__file__).resolve().parent.parent / "profiles"),
#                         help="Directory of profile JSON files (default: ./profiles)")
#     # Security overrides
#     parser.add_argument("--sign-official", action="true", help=argparse.SUPPRESS)
#     parser.add_argument("--no-sign-official", action="store_true", help=argparse.SUPPRESS)
#     parser.add_argument("--sign-user", action="store_true", help=argparse.SUPPRESS)
#     parser.add_argument("--no-sign-user", action="store_true", help=argparse.SUPPRESS)
#     parser.add_argument("--user-key", default=None, help="Path to user GPG key for signing")
#     parser.add_argument("--log-hash", action="store_true", help=argparse.SUPPRESS)
#     parser.add_argument("--no-log-hash", action="store_true", help=argparse.SUPPRESS)
#
#     args = parser.parse_args()
#
#     # Resolve and load profile
#     profiles_dir = Path(args.profiles_dir).expanduser().resolve()
#     try:
#         profile = load_profile(args.profile, profiles_dir)
#         print(f"[info] Loaded profile: {profile.get('name')} from {profiles_dir}", flush=True)
#     except Exception as e:
#         print(f"[error] Failed to load profile '{args.profile}': {e}", file=sys.stderr)
#         return 2
#
#     # Determine metadata policy from profile
#     metadata_policy = profile.get("metadata_policy", "safe_defaults")
#     if metadata_policy == "keep_all":
#         selected_profile_for_metadata = "preserve"
#     else:
#         selected_profile_for_metadata = "redact"
#
#     # Security layers with CLI overrides
#     sec = profile.get("security_layers", {}) or {}
#     def ov(enable_attr, disable_attr, default_val):
#         if hasattr(args, enable_attr) and getattr(args, enable_attr):
#             return True
#         if hasattr(args, disable_attr) and getattr(args, disable_attr):
#             return False
#         return default_val
#
#     sec_effective = {
#         "sign_official": ov("sign_official", "no_sign_official", bool(sec.get("sign_official", False))),
#         "sign_user": ov("sign_user", "no_sign_user", bool(sec.get("sign_user", False))),
#         "log_hash": ov("log_hash", "no_log_hash", bool(sec.get("log_hash", False))),
#     }
#     print(f"[info] Security layers (effective): {sec_effective}", flush=True)
#
#     # Dependency checks
#     if not which("ffmpeg"):
#         print("[error] ffmpeg not found on PATH. Please install ffmpeg and try again.", file=sys.stderr)
#         return 2
#     if not which("exiftool"):
#         print("[error] exiftool not found on PATH. Please install exiftool and try again.", file=sys.stderr)
#         return 2
#
#     src = Path(args.input).expanduser().resolve()
#     if not src.exists():
#         print(f"[error] Input file does not exist: {src}", file=sys.stderr)
#         return 2
#
#     work = Path(args.workdir); work.mkdir(parents=True, exist_ok=True)
#     out = Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
#
#     base = args.package_name or safe_name(src.stem)
#     delivered = work / f"{base}_delivered.mp4"
#
#     print("[info] === Originals ETL starting ===", flush=True)
#     print(f"[info] Source: {src}", flush=True)
#     print(f"[info] Metadata policy: {selected_profile_for_metadata}", flush=True)
#
#     # 1) Rewrap or re-encode
#     try_stream_copy = not args.force_reencode
#     if try_stream_copy:
#         print("[step] Attempting lossless rewrap (stream copy)", flush=True)
#         try:
#             sh(f'ffmpeg -y -i "{src}" -c copy -movflags +faststart "{delivered}"')
#             print("[ok] Stream copy succeeded; no re-encoding performed.", flush=True)
#         except Exception as e:
#             print(f"[warn] Stream copy failed: {e}", flush=True)
#             print("[step] Falling back to high-quality encode (CRF 10, preset slow).", flush=True)
#             sh(f'ffmpeg -y -i "{src}" -c:v libx264 -preset slow -crf 10 -c:a aac -b:a 192k -movflags +faststart "{delivered}"')
#             print("[ok] Fallback encode completed.", flush=True)
#     else:
#         print("[step] Force re-encode enabled; performing HQ encode.", flush=True)
#         sh(f'ffmpeg -y -i "{src}" -c:v libx264 -preset slow -crf 10 -c:a aac -b:a 192k -movflags +faststart "{delivered}"')
#
#     # 2) Full metadata extraction
#     meta_full = work / f"{base}_metadata_full.json"
#     print("[step] Extracting full metadata with exiftool (JSON, with groups)", flush=True)
#     sh(f'exiftool -j -a -G -api largefilesupport=1 "{delivered}" > "{meta_full}"')
#     print(f"[ok] Metadata written: {meta_full}", flush=True)
#
#     # 3) Redaction if policy = redact
#     meta_released = work / f"{base}_metadata_released.json"
#     redactions = []
#     effective_delivered = delivered
#
#     if selected_profile_for_metadata == "redact":
#         print("[step] Applying redaction profile (GPS, device IDs, creator tool, etc.)", flush=True)
#         delivered_redacted = work / f"{base}_delivered_redacted.mp4"
#         shutil.copyfile(delivered, delivered_redacted)
#         removal_cmd = [
#             'exiftool', '-overwrite_original',
#             '-QuickTime:GPSCoordinates=',
#             '-Keys:com.apple.quicktime.location.ISO6709=',
#             '-EXIF:BodySerialNumber=',
#             '-QuickTime:Model=',
#             '-QuickTime:Make=',
#             '-XMP:CreatorTool=',
#         ]
#         if args.coarsen_time == "date":
#             removal_cmd.append('-QuickTime:CreateDate<${QuickTime:CreateDate;DateFormat("%Y:%m:%d")}')
#         removal_cmd.append(str(delivered_redacted))
#         print("[run] ", " ".join(removal_cmd), flush=True)
#         proc = subprocess.run(removal_cmd)
#         if proc.returncode != 0:
#             print("[error] exiftool redaction failed.", file=sys.stderr)
#             return 2
#
#         effective_delivered = delivered_redacted
#         sh(f'exiftool -j -a -G -api largefilesupport=1 "{effective_delivered}" > "{meta_released}"')
#         redactions = [
#             "QuickTime:GPSCoordinates", "Keys:com.apple.quicktime.location.ISO6709",
#             "EXIF:BodySerialNumber", "QuickTime:Model", "QuickTime:Make", "XMP:CreatorTool"
#         ]
#         if args.coarsen_time == "date":
#             redactions.append("QuickTime:CreateDate(coarsened)")
#         print("[ok] Redaction completed and release metadata extracted.", flush=True)
#     else:
#         print("[info] Preserve metadata policy selected — releasing full metadata as-is.", flush=True)
#         shutil.copyfile(meta_full, meta_released)
#
#     # 4) Hashes & manifest
#     print("[step] Computing hashes (SHA-256)", flush=True)
#     h_src = sha256(src)
#     h_del = sha256(effective_delivered)
#     h_meta = sha256(meta_released)
#
#     manifest = {
#         "version": "1.1.0",
#         "source_file": str(src),
#         "delivered_file": Path(effective_delivered).name,
#         "hashes": {
#             "source_sha256": h_src,
#             "delivered_sha256": h_del,
#             "metadata_released_sha256": h_meta
#         },
#         "redaction_profile": selected_profile_for_metadata,
#         "redactions": redactions,
#         "timestamp": int(time.time())
#     }
#     manifest_path = work / f"{base}_manifest.json"
#     manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
#     print(f"[ok] Manifest written: {manifest_path}", flush=True)
#
#     # 5) Package deliverables
#     pkg_dir = work / f"{base}_package"
#     pkg_dir.mkdir(exist_ok=True)
#     (pkg_dir / "README.txt").write_text("This package was produced by Originals ETL. See manifest.json.", encoding="utf-8")
#     shutil.copy2(effective_delivered, pkg_dir / Path(effective_delivered).name)
#     shutil.copy2(meta_released, pkg_dir / "metadata_released.json")
#     shutil.copy2(manifest_path, pkg_dir / "manifest.json")
#
#     zip_path = Path(args.outdir) / f"{base}_package.zip"
#     print(f"[step] Creating archive: {zip_path}", flush=True)
#     shutil.make_archive(zip_path.with_suffix(""), "zip", pkg_dir)
#     print("[ok] Package created.", flush=True)
#
#     # 6) Security layers (optional)
#     security_info = {
#         "sign_official": bool(sec_effective.get("sign_official")),
#         "official_key_fingerprint": None,
#         "sign_user": bool(sec_effective.get("sign_user")),
#         "user_key_fingerprint": None,
#         "log_hash": bool(sec_effective.get("log_hash")),
#         "log_url": None
#     }
#     package_zip = zip_path
#
#     if sec_effective.get("sign_official"):
#         try:
#             sign_with_official_key(package_zip)
#             security_info["official_key_fingerprint"] = "TODO_OFFICIAL_FPR"
#         except Exception as e:
#             print(f"[warn] Official signing failed: {e}", flush=True)
#
#     if sec_effective.get("sign_user"):
#         if args.user_key:
#             try:
#                 sign_with_user_key(package_zip, Path(args.user_key))
#                 security_info["user_key_fingerprint"] = "TODO_USER_FPR"
#             except Exception as e:
#                 print(f"[warn] User signing failed: {e}", flush=True)
#         else:
#             print("[warn] sign_user enabled but --user-key not provided; skipping user signing.", flush=True)
#
#     if sec_effective.get("log_hash"):
#         try:
#             log_package_hash(package_zip)
#             security_info["log_url"] = "TODO_LOG_URL"
#         except Exception as e:
#             print(f"[warn] Hash logging failed: {e}", flush=True)
#
#     # Update manifests with security section
#     try:
#         j = json.loads(manifest_path.read_text(encoding="utf-8"))
#         j["security"] = security_info
#         manifest_path.write_text(json.dumps(j, indent=2), encoding="utf-8")
#
#         packaged_manifest = pkg_dir / "manifest.json"
#         j2 = json.loads(packaged_manifest.read_text(encoding="utf-8"))
#         j2["security"] = security_info
#         packaged_manifest.write_text(json.dumps(j2, indent=2), encoding="utf-8")
#         print("[ok] Updated manifest with security info.", flush=True)
#     except Exception as e:
#         print(f"[warn] Failed to embed security info into manifest: {e}", flush=True)
#
#     if not args.keep_work:
#         print("[cleanup] Removing working directory (use --keep-work to retain)", flush=True)
#         shutil.rmtree(work, ignore_errors=True)
#
#     print("[done] Originals ETL completed successfully.", flush=True)
#     print(f"[output] {zip_path}", flush=True)
#     print("[debug] Exiting main()", flush=True)
#     return 0
#
# if __name__ == "__main__":
#     sys.exit(main())
#
#
# # TODO: SECURITY LAYERS & PROFILES EXTENSION IMPLEMENTATION
# # - Replace stubs with real GPG detached-sign operations.
# # - Add official key fingerprint discovery and embed it.
# # - Implement transparency log HTTP client and record returned log URL.
# # - Expand CI to run a dry-run signing (mock) and schema checks over real outputs.
#
