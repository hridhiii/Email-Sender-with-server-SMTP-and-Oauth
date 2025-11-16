"""Simple pluggable authentication layer.

By default uses:
- APP_USERS env var on first run (username:password pairs, comma-separated)
- /data/users.json to persist salted password hashes

Passwords are hashed with SHA-256 + APP_SECRET_KEY salt.
This is intentionally simple and can be replaced with SSO / OAuth in front
of the app without touching the core logic.
"""

import json
import os
import hashlib
import smtplib
from pathlib import Path
from typing import Dict

DATA_DIR = os.getenv("DATA_DIR", "/data")
USERS_FILE = Path(DATA_DIR) / "users.json"
ADMIN_FILE = Path(DATA_DIR) / "admins.json"
SECRET = os.getenv("APP_SECRET_KEY", "dev-insecure-secret")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT_SSL = 465



def _hash(password: str) -> str:
    return hashlib.sha256((SECRET + "::" + password).encode("utf-8")).hexdigest()


def _load_users() -> Dict[str, str]:
    if USERS_FILE.exists():
        try:
            return json.load(USERS_FILE.open("r", encoding="utf-8"))
        except Exception:
            pass

    env_val = os.getenv("APP_USERS", "").strip()
    users: Dict[str, str] = {}
    if env_val:
        for part in env_val.split(","):
            if ":" in part:
                u, p = part.split(":", 1)
                u = u.strip()
                p = p.strip()
                if u and p:
                    users[u] = _hash(p)

    if users:
        _save_users(users)
    return users


def _save_users(users: Dict[str, str]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    tmp.replace(USERS_FILE)




def get_admin_users():
    """Return the current set of admin usernames.

    Priority:
    1) /data/admins.json if present and non-empty
    2) ADMIN_USERS env var (comma-separated list)
    3) Fallback to single default admin user: "admin"
    """
    # Fallback from env/default
    env_val = os.getenv("ADMIN_USERS", "")
    default_admins = {u.strip() for u in env_val.split(",") if u.strip()} or {"admin"}

    if ADMIN_FILE.exists():
        try:
            data = json.load(ADMIN_FILE.open("r", encoding="utf-8"))
            admins = {u.strip() for u in data.get("admins", []) if u.strip()}
            if admins:
                return admins
        except Exception:
            # fall back to env/default
            pass
    return default_admins


def _save_admin_users(admins) -> None:
    """Persist admin usernames to ADMIN_FILE."""
    ADMIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = ADMIN_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump({"admins": sorted(admins)}, f, indent=2)
    tmp.replace(ADMIN_FILE)


def verify_gmail_credentials(email: str, app_password: str) -> bool:
    """Check Gmail SMTP login before allowing a Gmail user to sign in.

    Returns True if SMTP login succeeds, False otherwise.
    """
    email = (email or "").strip()
    app_password = app_password or ""
    if not email or not app_password:
        return False
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT_SSL, timeout=10) as server:
            server.login(email, app_password)
        return True
    except Exception:
        return False


def update_admin_credentials(current_username: str, new_username: str, new_password: str) -> None:
    """Update the admin username and password.

    - Ensures ``new_username`` exists in the user store with the given password.
    - Marks ``new_username`` as admin in ADMIN_FILE.
    - If ``current_username`` was previously an admin and differs from ``new_username``,
      it is removed from the admin set (but the underlying user account remains).
    """
    new_username = (new_username or "").strip()
    if not new_username or not new_password:
        raise ValueError("New admin username and password are required.")

    # Update user credentials
    users = _load_users()
    users[new_username] = _hash(new_password)
    _save_users(users)

    # Update admin list
    admins = get_admin_users()
    admins.add(new_username)
    if current_username and current_username in admins and current_username != new_username:
        admins.discard(current_username)
    _save_admin_users(admins)
def verify(username: str, password: str) -> bool:
    users = _load_users()
    if not username or not password:
        return False
    if username not in users:
        return False
    return users[username] == _hash(password)


def get_auth_mode() -> str:
    return os.getenv("AUTH_MODE", "simple").lower()
