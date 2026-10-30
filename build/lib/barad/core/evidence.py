"""Shared evidence identity and hashing helpers for the Barad CLI."""
import hashlib
import secrets
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc)


def utc_timestamp(moment=None):
    return (moment or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_run_id(source, moment=None):
    stamp = (moment or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    return f"{source}-{stamp}-{secrets.token_hex(3)}"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()
