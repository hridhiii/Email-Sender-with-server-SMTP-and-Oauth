"""Gmail quota awareness (best-effort, local).

We **do not** know true Gmail limits, but we keep a conservative local counter
per account to:
- throttle sends
- avoid blasting past typical free / workspace limits
- surface warnings in the UI logs
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Tuple

DATA_DIR = os.getenv("DATA_DIR", "/data")
QUOTA_DIR = Path(DATA_DIR) / "quotas"
QUOTA_DIR.mkdir(parents=True, exist_ok=True)

DAILY_LIMIT = int(os.getenv("GMAIL_DAILY_LIMIT", "1800"))
HOURLY_LIMIT = int(os.getenv("GMAIL_HOURLY_LIMIT", "400"))
WARN_PCT = float(os.getenv("GMAIL_WARN_PCT", "0.9"))


def _quota_path(from_email: str) -> Path:
    safe = from_email.replace("@", "_at_").replace(".", "_")
    return QUOTA_DIR / f"{safe}.json"


def _load(from_email: str) -> dict:
    p = _quota_path(from_email)
    if p.exists():
        try:
            return json.load(p.open("r", encoding="utf-8"))
        except Exception:
            pass
    return {"daily": {}, "hourly": {}}


def _save(from_email: str, q: dict) -> None:
    p = _quota_path(from_email)
    tmp = p.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(q, f)
    tmp.replace(p)


def can_send(from_email: str, n_messages: int = 1) -> Tuple[bool, str]:
    """Return (allowed, message). Message is warning or error description."""
    if DAILY_LIMIT <= 0 and HOURLY_LIMIT <= 0:
        return True, ""
    now = datetime.utcnow()
    day_key = now.strftime("%Y%m%d")
    hour_key = now.strftime("%Y%m%d%H")
    q = _load(from_email)
    q.setdefault("daily", {})
    q.setdefault("hourly", {})

    day_sent = int(q["daily"].get(day_key, 0))
    hour_sent = int(q["hourly"].get(hour_key, 0))

    if DAILY_LIMIT > 0 and day_sent + n_messages > DAILY_LIMIT:
        return False, (
            f"Local safety guard: daily Gmail send limit reached for {from_email} "
            f"(approx {day_sent}/{DAILY_LIMIT})."
        )
    if HOURLY_LIMIT > 0 and hour_sent + n_messages > HOURLY_LIMIT:
        return False, (
            f"Local safety guard: hourly Gmail send limit reached for {from_email} "
            f"(approx {hour_sent}/{HOURLY_LIMIT})."
        )

    msg = ""
    if DAILY_LIMIT > 0 and day_sent + n_messages > DAILY_LIMIT * WARN_PCT:
        msg = (
            f"Warning: nearing daily send limit for {from_email} "
            f"({day_sent}/{DAILY_LIMIT} by local counter)."
        )
    return True, msg


def consume(from_email: str, n_messages: int = 1) -> None:
    if DAILY_LIMIT <= 0 and HOURLY_LIMIT <= 0:
        return
    now = datetime.utcnow()
    day_key = now.strftime("%Y%m%d")
    hour_key = now.strftime("%Y%m%d%H")
    q = _load(from_email)
    q.setdefault("daily", {})
    q.setdefault("hourly", {})
    if DAILY_LIMIT > 0:
        q["daily"][day_key] = int(q["daily"].get(day_key, 0)) + n_messages
    if HOURLY_LIMIT > 0:
        q["hourly"][hour_key] = int(q["hourly"].get(hour_key, 0)) + n_messages
    _save(from_email, q)
