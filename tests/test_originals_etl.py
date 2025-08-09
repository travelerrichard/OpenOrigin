import hashlib
from pathlib import Path
import sys

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))
from originals_etl import safe_name, sha256, load_profile, which, sh


def test_safe_name():
    assert safe_name("unsafe name!!.mp4") == "unsafe_name__.mp4"


def test_sha256(tmp_path: Path):
    p = tmp_path / "file.txt"
    data = b"hello world"
    p.write_bytes(data)
    assert sha256(p) == hashlib.sha256(data).hexdigest()


def test_load_profile():
    profiles_dir = Path(__file__).resolve().parent.parent / "profiles"
    profile = load_profile("redact", profiles_dir)
    assert profile["name"] == "redact"


def test_which():
    assert which("python3")


def test_sh():
    # 'true' command succeeds with exit code 0
    sh("true")

