
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
originals_etl.py — ETL tool for packaging original (or near-original) media for analysis.

Upgrades in this version:
  • Local-only by default (socket-blocking offline guard). Opt-in network via --allow-network.
  • Deterministic ZIPs and atomic JSON writes.
  • Package SHA256 sidecar and post-pack self-verify.
  • Profile-driven redactions from helpers/profiles/*.json (+ profile SHA in manifest).
  • Tool versions recorded in manifest.
  • Optional GPG detached signing (official/user) — offline.
  • Optional transparency log POST (only with --allow-network).

Requirements: Python 3.8+, ffmpeg, exiftool, (optional) gpg
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
from tempfile import NamedTemporaryFile
from typing import Dict, Any

# ----------------------------- Offline Guard ----------------------------- #
def enforce_offline_mode(allow_network: bool) -> None:
    if allow_network:
        print("[offline] Network allowed by --allow-network.", flush=True)
        return
    print("[offline] Enforcing local-only mode (blocking outbound sockets).", flush=True)
    import socket
    real_socket = socket.socket
    class NoNetSocket(real_socket):
        def connect(self, *a, **k):  # type: ignore[override]
            raise RuntimeError("Network blocked: originals_etl runs local-only unless --allow-network is set.")
    socket.socket = NoNetSocket  # type: ignore
    os.environ.update({"NO_PROXY":"*", "HTTP_PROXY":"", "HTTPS_PROXY":""})

# ----------------------------- Small Utils ------------------------------ #
def which(bin_name: str) -> bool:
    from shutil import which as _which
    return _which(bin_name) is not None

def sh(cmd: str) -> None:
    print(f"[run] {cmd}", flush=True)
    c = subprocess.run(cmd, shell=True)
    if c.returncode != 0:
        print(f"[error] Command exited {c.returncode}: {cmd}", flush=True)
        raise RuntimeError(f"Command failed: {cmd}")

def sha256(path: Path, show_progress: bool=False) -> str:
    h = hashlib.sha256()
    size = path.stat().st_size
    done = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(4<<20)
            if not chunk: break
            h.update(chunk); done += len(chunk)
            if show_progress and size:
                print(f"\r[hash] {path.name} {done/size:6.1%}", end="", flush=True)
    if show_progress: print()
    return h.hexdigest()

def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = NamedTemporaryFile("w", delete=False, encoding="utf-8")
    try:
        json.dump(data, tmp, indent=2, ensure_ascii=False)
        tmp.flush(); os.fsync(tmp.fileno()); tmp.close()
        os.replace(tmp.name, path)
        print(f"[fs] Atomic write → {path}", flush=True)
    finally:
        try: os.unlink(tmp.name)
        except FileNotFoundError: pass

def validate_zip_name(name: str):
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError(f"Unsafe zip entry name: {name}")

def tool_versions() -> dict:
    def cap(cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            return out.splitlines()[0][:160] if out else "unknown"
        except Exception as e:
            return f"unavailable: {e}"
    return {
        "ffmpeg": cap(["ffmpeg","-version"]),
        "exiftool": cap(["exiftool","-ver"]),
        "gpg": cap(["gpg","--version"]),
    }

# ------------------------- Deterministic ZIP ----------------------------- #
def make_deterministic_zip(zip_path: Path, files: Dict[str, Path]) -> None:
    print(f"[zip] Creating deterministic package: {zip_path}", flush=True)
    ts = (1980,1,1,0,0,0)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname in sorted(files.keys()):
            validate_zip_name(arcname)
            zi = zipfile.ZipInfo(arcname); zi.date_time = ts; zi.compress_type = zipfile.ZIP_DEFLATED
            with files[arcname].open("rb") as f:
                zf.writestr(zi, f.read())
    print("[zip] Package complete.", flush=True)

# --------------------------- Security Layers ---------------------------- #
def gpg_detached_sign(target: Path, signer: str|None, out_sig: Path) -> str|None:
    if not which("gpg"):
        print("[sig] gpg not found; skipping.", flush=True); return None
    cmd = ["gpg","--armor","--detach-sign","--output",str(out_sig)]
    if signer: cmd += ["--local-user", signer]
    cmd.append(str(target))
    print("[sig] " + " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
    try:
        who = signer or ""
        out = subprocess.check_output(["gpg","--list-signatures","--with-colons",who], text=True, stderr=subprocess.STDOUT)
        for line in out.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
    except Exception:
        pass
    return None

def transparency_log_post(pkg_sha: str, endpoint: str) -> str:
    import urllib.request, urllib.error
    req = urllib.request.Request(endpoint, data=json.dumps({"sha256": pkg_sha}).encode("utf-8"),
                                 headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")[:200]
            return body or endpoint
    except urllib.error.URLError as e:
        print(f"[log] Transparency log failed: {e}", flush=True)
        return ""

# --------------------------------- CLI ---------------------------------- #
def main() -> int:
    print("[debug] Entering main()", flush=True)
    p = argparse.ArgumentParser(description="Create an Original File Package (.zip) for analysis.")
    p.add_argument("input", help="Path to original media (mp4/mov/avi/etc.)")
    p.add_argument("--profile", default="redact", help="Profile name from helpers/profiles (default: redact)")
    p.add_argument("--coarsen-time", choices=["none","date"], default=None, help="Override profile coarsen policy")
    p.add_argument("--outdir", default="out", help="Output directory (default: out)")
    p.add_argument("--workdir", default="work", help="Working directory (default: work)")
    p.add_argument("--package-name", default=None, help="Optional base name for the output package")
    p.add_argument("--keep-work", action="store_true", help="Keep working directory")
    p.add_argument("--allow-network", action="store_true", help="Allow network for transparency log")
    # signing
    p.add_argument("--sign-official", action="store_true", help="Sign with official key (gpg)")
    p.add_argument("--official-signer", default=os.environ.get("OPENORIGIN_OFFICIAL_SIGNER",""), help="GPG key id/email")
    p.add_argument("--sign-user", action="store_true", help="Sign with user key (gpg)")
    p.add_argument("--user-signer", default="", help="GPG key id/email")
    # log
    p.add_argument("--log-hash", action="store_true", help="POST package SHA to transparency log")
    p.add_argument("--log-endpoint", default=os.environ.get("OPENORIGIN_LOG_ENDPOINT",""), help="Transparency log endpoint")
    args = p.parse_args()

    enforce_offline_mode(args.allow_network)

    if not which("ffmpeg"):
        print("[error] ffmpeg not found on PATH.", file=sys.stderr); return 2
    if not which("exiftool"):
        print("[error] exiftool not found on PATH.", file=sys.stderr); return 2

    src = Path(args.input).expanduser().resolve()
    if not src.exists():
        print(f"[error] Input does not exist: {src}", file=sys.stderr); return 2

    work = Path(args.workdir); work.mkdir(parents=True, exist_ok=True)
    out = Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
    base = args.package_name or "".join(ch if ch.isalnum() or ch in ("-","_",".") else "_" for ch in src.stem)
    delivered = work / f"{base}_delivered.mp4"

    profiles_dir = Path("helpers/profiles").resolve()
    profile_path = profiles_dir / f"{args.profile}.json"
    if not profile_path.exists():
        print(f"[error] Profile not found: {profile_path}", file=sys.stderr); return 2
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    metadata_policy = profile.get("metadata_policy","redact")
    rules = profile.get("redact_rules",{}) or {}
    if args.coarsen_time is not None:
        rules["coarsen_time"] = args.coarsen_time
    coarsen_time = rules.get("coarsen_time","none")
    remove_tags = list(rules.get("remove_tags",[]))

    profile_bytes = json.dumps(profile, sort_keys=True).encode("utf-8")
    profile_sha = hashlib.sha256(profile_bytes).hexdigest()

    print("[info] === Originals ETL starting ===", flush=True)
    print(f"[info] Source: {src}", flush=True)
    print(f"[info] Profile: {profile.get('name', args.profile)} (policy={metadata_policy})", flush=True)
    print(f"[info] Rules: remove_tags={remove_tags} coarsen_time={coarsen_time}", flush=True)

    # 1) Rewrap or encode
    try:
        print("[step] Attempting stream copy (+faststart)", flush=True)
        sh(f'ffmpeg -y -i "{src}" -c copy -movflags +faststart "{delivered}"')
        print("[ok] Stream copy succeeded.", flush=True)
    except Exception as e:
        print(f"[warn] Stream copy failed: {e}", flush=True)
        print("[step] Fallback encode (libx264 CRF10 slow, AAC 192k)", flush=True)
        sh(f'ffmpeg -y -i "{src}" -c:v libx264 -preset slow -crf 10 -c:a aac -b:a 192k -movflags +faststart "{delivered}"')
        print("[ok] Fallback encode completed.", flush=True)

    # 2) Full metadata extraction
    meta_full = work / f"{base}_metadata_full.json"
    print("[step] exiftool extract (JSON, groups)", flush=True)
    sh(f'exiftool -j -a -G -api largefilesupport=1 "{delivered}" > "{meta_full}"')
    print(f"[ok] Metadata written: {meta_full}", flush=True)

    # 3) Redaction
    meta_released = work / f"{base}_metadata_released.json"
    redactions_applied = []
    effective_delivered = delivered

    if str(metadata_policy).lower() == "redact":
        print("[step] Applying redactions", flush=True)
        delivered_redacted = work / f"{base}_delivered_redacted.mp4"
        shutil.copyfile(delivered, delivered_redacted)

        removal_cmd = ['exiftool','-overwrite_original','-api','largefilesupport=1']
        for tag in remove_tags:
            removal_cmd.append(f'-{tag}=')
        if str(coarsen_time) == "date":
            removal_cmd.append('-QuickTime:CreateDate<${QuickTime:CreateDate;DateFormat("%Y:%m:%d")}')
        removal_cmd.append(str(delivered_redacted))

        print("[run] " + " ".join(removal_cmd), flush=True)
        proc = subprocess.run(removal_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print("[error] exiftool redaction failed; aborting.", file=sys.stderr); return 2

        effective_delivered = delivered_redacted
        sh(f'exiftool -j -a -G -api largefilesupport=1 "{effective_delivered}" > "{meta_released}"')
        redactions_applied = remove_tags[:]
        if str(coarsen_time) == "date":
            redactions_applied.append("QuickTime:CreateDate(coarsened)")
        print("[ok] Redaction complete.", flush=True)
    else:
        print("[info] Preserve metadata policy — releasing full metadata as-is.", flush=True)
        shutil.copyfile(meta_full, meta_released)

    # 4) Hashes & manifest
    print("[step] Computing hashes (SHA-256)", flush=True)
    h_src = sha256(src, show_progress=True)
    h_del = sha256(effective_delivered)
    h_meta = sha256(meta_released)

    env_versions = tool_versions()
    manifest = {
        "version": "1.2.0",
        "processed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_file": str(src),
        "delivered_file": Path(effective_delivered).name,
        "hashes": {
            "source_sha256": h_src,
            "delivered_sha256": h_del,
            "metadata_released_sha256": h_meta
        },
        "redaction_profile": metadata_policy,
        "redactions": redactions_applied,
        "profile": {"name": profile.get("name", args.profile), "sha256": profile_sha},
        "environment": env_versions
    }
    manifest_path = Path(args.workdir) / f"{base}_manifest.json"
    atomic_write_json(manifest_path, manifest)

    # 5) Package deliverables (deterministic)
    pkg_zip = Path(args.outdir) / f"{base}_package.zip"
    staged = {
        Path(effective_delivered).name: effective_delivered,
        "metadata_released.json": meta_released,
        "manifest.json": manifest_path,
    }
    # validate names
    for n in staged.keys(): validate_zip_name(n)
    make_deterministic_zip(pkg_zip, staged)

    # package sha + sidecar
    pkg_sha = sha256(pkg_zip)
    (pkg_zip.with_suffix(".zip.sha256")).write_text(f"{pkg_sha}  {pkg_zip.name}\n", encoding="utf-8")
    print(f"[hash] package -> {pkg_sha}", flush=True)

    # optional signatures
    security = {"signed_official": False, "official_fpr": None, "signed_user": False, "user_fpr": None, "transparency_log_url": None}
    if args.sign_official:
        sig = pkg_zip.with_suffix(".zip.official.asc")
        fpr = gpg_detached_sign(pkg_zip, args.official_signer or None, sig)
        security["signed_official"] = True; security["official_fpr"] = fpr
    if args.sign_user:
        sig = pkg_zip.with_suffix(".zip.user.asc")
        fpr = gpg_detached_sign(pkg_zip, args.user_signer or None, sig)
        security["signed_user"] = True; security["user_fpr"] = fpr

    if args.log_hash:
        if not args.allow_network:
            print("[log] --log-hash requested but network disabled. Re-run with --allow-network.", flush=True)
        elif not args.log_endpoint:
            print("[log] --log-hash requested but no --log-endpoint set.", flush=True)
        else:
            url = transparency_log_post(pkg_sha, args.log_endpoint)
            security["transparency_log_url"] = url or None

    # update manifest with security + package sha
    try:
        j = json.loads(manifest_path.read_text(encoding="utf-8"))
        j.setdefault("hashes",{})["package_sha256"] = pkg_sha
        j["security"] = security
        atomic_write_json(manifest_path, j)
    except Exception as e:
        print(f"[warn] Could not update manifest with security/package sha: {e}", flush=True)

    # 6) Self-verify
    try:
        print("[verify] Post-pack self-check…", flush=True)
        with zipfile.ZipFile(pkg_zip, "r") as z:
            m = json.loads(z.read("manifest.json"))
            import hashlib as _h
            if _h.sha256(z.read(m["delivered_file"])).hexdigest() != m["hashes"]["delivered_sha256"]:
                raise RuntimeError("delivered_sha256 mismatch inside ZIP")
            if _h.sha256(z.read("metadata_released.json")).hexdigest() != m["hashes"]["metadata_released_sha256"]:
                raise RuntimeError("metadata_released_sha256 mismatch inside ZIP")
        print("[verify] OK", flush=True)
    except Exception as e:
        print(f"[verify] FAILED: {e}", flush=True)
        return 2

    # 7) Write sample manifest for CI
    samples_dir = Path("samples"); samples_dir.mkdir(exist_ok=True)
    try:
        shutil.copy2(manifest_path, samples_dir / "last_run_manifest.json")
        print("[ci] Wrote samples/last_run_manifest.json", flush=True)
    except Exception as e:
        print(f"[ci] Could not write sample manifest: {e}", flush=True)

    if not args.keep_work:
        shutil.rmtree(Path(args.workdir), ignore_errors=True)

    print("[done] Originals ETL completed.", flush=True)
    print(f"[output] Package: {pkg_zip}", flush=True)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\\n[exit] Interrupted by user.", flush=True)
        sys.exit(130)
