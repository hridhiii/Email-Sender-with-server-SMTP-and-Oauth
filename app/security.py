"""Security & deduplication helpers.

Responsibilities:
- Symmetric encryption for stored Gmail app passwords.
- Normalization + salted hashing for email addresses.
- Persistent per-sender deduplication index using hashed recipient IDs.
"""

import base64
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Set

from cryptography.fernet import Fernet, InvalidToken

DATA_DIR = os.getenv("DATA_DIR", "/data")
SENT_INDEX_DIR = Path(DATA_DIR) / "sent_index"
SENT_INDEX_DIR.mkdir(parents=True, exist_ok=True)

_SECRET_ENV = "APP_SECRET_KEY"


def _base_key() -> bytes:
    key = os.getenv(_SECRET_ENV, "dev-insecure-key")
    raw = key.encode("utf-8")
    if len(raw) < 32:
        raw = raw.ljust(32, b"0")
    else:
        raw = raw[:32]
    return base64.urlsafe_b64encode(raw)


def _fernet() -> Fernet:
    return Fernet(_base_key())


def encrypt_secret(plain: str) -> str:
    """Encrypt a secret for storage in payloads.

    If encryption fails, falls back to returning the plain text
    so existing deployments do not break (but logs should warn in prod).
    """
    if not plain:
        return ""
    try:
        return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")
    except Exception:
        return plain


def decrypt_secret(token: str) -> str:
    """Decrypt a secret from payloads.

    If the value is not a valid token (e.g. legacy plaintext), it is
    returned as-is.
    """
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        return token


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _sent_index_path(from_email: str) -> Path:
    norm = normalize_email(from_email)
    safe = norm.replace("@", "_at_").replace(".", "_")
    return SENT_INDEX_DIR / f"{safe}.index"


def hash_email(email: str) -> str:
    """Return a salted hash for a recipient email, for deduplication only."""
    norm = normalize_email(email)
    salt = os.getenv(_SECRET_ENV, "")
    return hashlib.sha256((salt + "|" + norm).encode("utf-8")).hexdigest()


def load_sent_hashes(from_email: str) -> Set[str]:
    """Load the set of hashed recipient IDs previously mailed from this account."""
    path = _sent_index_path(from_email)
    hashes: Set[str] = set()
    if not path.exists():
        return hashes
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 1)
                if parts and parts[0]:
                    hashes.add(parts[0])
    except Exception:
        return hashes
    return hashes


def record_sent_hash(from_email: str, to_email: str, module: str, job_id: str) -> None:
    """Append a hashed recipient entry to the dedup index if not already present."""
    if not to_email:
        return
    h = hash_email(to_email)
    if not h:
        return
    existing = load_sent_hashes(from_email)
    if h in existing:
        return
    path = _sent_index_path(from_email)
    ts = datetime.utcnow().isoformat()
    line = f"{h},{ts},{module},{job_id}\n"
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # best-effort only
        pass
