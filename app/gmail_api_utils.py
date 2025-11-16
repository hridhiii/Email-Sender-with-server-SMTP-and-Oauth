
"""Gmail API helpers for OAuth-based sending and reply-aware follow-ups.

This module is used when delivery_mode == 'gmail_api', alongside the existing
SMTP/IMAP-based helpers.
"""

import base64
import json
import os
import time
import re
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, parseaddr


DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
TOKENS_FILE = DATA_DIR / "oauth_tokens.json"

GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    "",
)
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET",
    "",
)
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8501/")

SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

_AUTH_BASE = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
_GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"


def has_gmail_oauth_config() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)


def _load_tokens_store() -> Dict[str, Dict]:
    try:
        with TOKENS_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_tokens_store(store: Dict[str, Dict]) -> None:
    TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with TOKENS_FILE.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)


def build_auth_url(state: str) -> str:
    from urllib.parse import urlencode

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    return _AUTH_BASE + "?" + urlencode(params)


def exchange_code_for_tokens(code: str) -> Optional[Dict]:
    """Exchange authorization code for tokens; persist by email; return entry.

    On success returns a dict containing at least:
      - email
      - access_token
      - refresh_token (if Google returned one)
    """
    code = (code or "").strip()
    if not code:
        return None

    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    resp = requests.post(_TOKEN_ENDPOINT, data=data, timeout=10)
    if resp.status_code != 200:
        return None
    token_payload = resp.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        return None

    # Get profile info (email etc.)
    ui_resp = requests.get(
        _USERINFO_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if ui_resp.status_code != 200:
        return None
    info = ui_resp.json()
    email = (info.get("email") or "").strip()
    if not email:
        return None

    now = int(time.time())
    store = _load_tokens_store()
    existing = store.get(email, {})
    entry = {
        "email": email,
        "sub": info.get("sub") or existing.get("sub", ""),
        "name": info.get("name") or existing.get("name", ""),
        "picture": info.get("picture") or existing.get("picture", ""),
        "access_token": access_token,
        "refresh_token": token_payload.get("refresh_token") or existing.get("refresh_token", ""),
        "id_token": token_payload.get("id_token") or existing.get("id_token", ""),
        "scope": token_payload.get("scope", existing.get("scope", "")),
        "token_type": token_payload.get("token_type", existing.get("token_type", "Bearer")),
        "expires_in": int(token_payload.get("expires_in", existing.get("expires_in", 3600))),
        "obtained_at": now,
    }
    store[email] = entry
    _save_tokens_store(store)
    return entry


def _refresh_access_token(email: str) -> Optional[str]:
    store = _load_tokens_store()
    entry = store.get(email)
    if not entry:
        return None
    refresh_token = entry.get("refresh_token")
    if not refresh_token:
        return None

    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    resp = requests.post(_TOKEN_ENDPOINT, data=data, timeout=10)
    if resp.status_code != 200:
        return None
    payload = resp.json()
    access_token = payload.get("access_token")
    if not access_token:
        return None

    entry["access_token"] = access_token
    entry["expires_in"] = int(payload.get("expires_in", 3600))
    entry["obtained_at"] = int(time.time())
    store[email] = entry
    _save_tokens_store(store)
    return access_token


def get_valid_access_token(email: str) -> Optional[str]:
    store = _load_tokens_store()
    entry = store.get(email)
    if not entry:
        return None
    access_token = entry.get("access_token")
    if not access_token:
        return _refresh_access_token(email)

    obtained_at = int(entry.get("obtained_at", 0))
    expires_in = int(entry.get("expires_in", 3600))
    if time.time() > obtained_at + 0.8 * expires_in:
        return _refresh_access_token(email)
    return access_token




def _ensure_message_id_format(msgid: str) -> str:
    """Ensure a Message-ID is RFC 2822 compliant: angle-bracket wrapped."""
    msgid = (msgid or "").strip()
    if not msgid:
        return ""
    if msgid.startswith("<") and msgid.endswith(">"):
        return msgid
    first = msgid.split()[0]
    if not first.startswith("<"):
        first = f"<{first}>"
    return first


def _format_references_header(references: str, in_reply_to: str = "") -> str:
    """Build an RFC 2822 compliant References header."""
    raw = str(references or "").strip()
    parts = raw.split()
    normalized = []
    seen = set()
    for token in parts:
        token = token.strip()
        if not token:
            continue
        formatted = _ensure_message_id_format(token)
        if formatted and formatted not in seen:
            seen.add(formatted)
            normalized.append(formatted)
    parent = _ensure_message_id_format(in_reply_to)
    if parent and parent not in seen:
        normalized.append(parent)
    return " ".join(normalized)

def _build_html_message(
    from_email: str,
    to_email: str,
    subject: str,
    html_body: str,
    from_name: str = "",
    in_reply_to: str = "",
    references: str = "",
) -> MIMEMultipart:
    """Build an HTML MIME message with RFC 2822 compliant threading headers."""
    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    if in_reply_to:
        clean_in_reply = _ensure_message_id_format(in_reply_to)
        if clean_in_reply:
            msg["In-Reply-To"] = clean_in_reply

    if references:
        msg["References"] = _format_references_header(references, in_reply_to)

    msg.attach(MIMEText(html_body or "", "html", "utf-8"))
    return msg


def _gmail_send_raw(access_token: str, raw_rfc822: bytes, thread_id: str = "") -> Dict:
    raw_b64 = base64.urlsafe_b64encode(raw_rfc822).decode("utf-8")
    payload = {"raw": raw_b64}
    if thread_id:
        payload["threadId"] = thread_id
    url = f"{_GMAIL_API_BASE}/users/me/messages/send"
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def gmail_send_html(
    from_email: str,
    to_email: str,
    subject: str,
    html_body: str,
    from_name: str = "",
) -> Dict:
    """Send a new HTML email using Gmail API (no app password)."""
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    msg = _build_html_message(from_email, to_email, subject, html_body, from_name)
    return _gmail_send_raw(access_token, msg.as_bytes())


def gmail_reply_html(
    from_email: str,
    to_email: str,
    subject: str,
    html_body: str,
    thread_id: str,
    parent_message_id: str,
    from_name: str = "",
    references: str = "",
) -> Dict:
    """Reply in an existing thread using Gmail API with proper threading headers."""
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")

    # Ensure reply-style subject without duplicating "Re:"
    if subject and not re.match(r"(?i)^re:\s*", subject):
        subject = f"Re: {subject}"

    msg = _build_html_message(
        from_email,
        to_email,
        subject,
        html_body,
        from_name=from_name,
        in_reply_to=parent_message_id,
        references=references or parent_message_id,
    )
    return _gmail_send_raw(access_token, msg.as_bytes(), thread_id=thread_id)


def gmail_search_messages(from_email: str, query: str, max_results: int = 10) -> List[Dict]:
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    url = f"{_GMAIL_API_BASE}/users/me/messages"
    params = {"q": query, "maxResults": max_results}
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("messages", []) or []


def gmail_get_message(from_email: str, message_id: str, metadata_headers: Optional[List[str]] = None) -> Dict:
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    url = f"{_GMAIL_API_BASE}/users/me/messages/{message_id}"
    params = {
        "format": "metadata",
        "metadataHeaders": metadata_headers
        or ["Message-ID", "In-Reply-To", "References", "Subject", "From", "To"],
    }
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def gmail_fetch_message_id_header(
    from_email: str,
    message_id: str,
    attempts: int = 6,
    delay_min: float = 1.0,
    delay_max: float = 2.0,
) -> str:
    """Retry-fetch the RFC 2822 Message-ID header for a recently-sent message.

    Gmail sometimes lags in exposing the Message-ID header immediately after a
    send() call. This helper retries a few times until the header appears, so
    we can safely store it for reply-aware threading.

    IMPORTANT: Gmail may return the header name as ``Message-ID`` or
    ``Message-Id`` (or other case variants), so we must match on
    ``name.lower() == 'message-id'`` instead of relying on the exact key.
    """
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            msg = gmail_get_message(from_email, message_id, metadata_headers=["Message-ID"])
            headers_list = msg.get("payload", {}).get("headers", [])
            for h in headers_list:
                if str(h.get("name", "")).lower() == "message-id":
                    # Strip whitespace but keep angle brackets as-is; downstream
                    # code will normalize as needed.
                    val = (h.get("value") or "").strip()
                    if val:
                        return val
        except Exception as e:
            last_err = e
        time.sleep(random.uniform(delay_min, delay_max))
    return ""


def gmail_find_last_sent_to(from_email: str, to_email: str) -> Optional[Tuple[str, str]]:
    """Return (thread_id, message_id_header) of most recent sent mail to recipient."""
    # Search in:sent for latest message TO that address
    msgs = gmail_search_messages(from_email, f"to:{to_email} in:sent", max_results=5)
    if not msgs:
        return None
    mid = msgs[0]["id"]
    msg = gmail_get_message(from_email, mid, metadata_headers=["Message-ID"])
    thread_id = msg.get("threadId", "")
    headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
    msg_id_header = headers.get("Message-ID", "")
    if not thread_id or not msg_id_header:
        return None
    return thread_id, msg_id_header


def gmail_check_reply_exists(from_email: str, message_ids: List[str], prospect_email: str) -> bool:
    """Approximate reply detection using Gmail search.

    We look for messages FROM the prospect that reference any of the given
    Message-IDs, using the rfc822msgid: search operator where possible.
    """
    access_token = get_valid_access_token(from_email)
    if not access_token:
        return False

    # Use Gmail search: from:prospect rfc822msgid:<id>
    for mid in message_ids:
        mid = (mid or "").strip()
        if not mid:
            continue
        # Many servers wrap Message-ID in <...>
        if "<" in mid and ">" in mid:
            token = mid
        else:
            token = f"<{mid}>"
        query = f"from:{prospect_email} rfc822msgid:{token}"
        msgs = gmail_search_messages(from_email, query, max_results=1)
        if msgs:
            return True
    return False



def gmail_thread_has_prospect_reply(from_email: str, thread_id: str, prospect_email: str) -> bool:
    """Check if a Gmail thread contains a reply from the *prospect*.

    We:
      * Fetch the thread metadata with only the From header.
      * Parse the From header into an email address using parseaddr.
      * Compare that address against the prospect_email (also parsed).
    Only if the prospect's email address appears in the thread's From
    senders do we treat it as "replied".
    """
    thread_id = (thread_id or "").strip()
    if not thread_id:
        return False

    access_token = get_valid_access_token(from_email)
    if not access_token:
        return False

    url = f"{_GMAIL_API_BASE}/users/me/threads/{thread_id}"
    params = {"format": "metadata", "metadataHeaders": ["From"]}
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            params=params,
            timeout=10,
        )
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
    except Exception:
        return False

    data = resp.json()
    messages = data.get("messages", [])

    # Normalise prospect address
    _, prospect_addr = parseaddr(prospect_email or "")
    prospect_addr_lc = (prospect_addr or "").strip().lower()
    if not prospect_addr_lc:
        return False

    for msg in messages:
        headers = msg.get("payload", {}).get("headers", [])
        from_header = ""
        for h in headers:
            if str(h.get("name", "")).lower() == "from":
                from_header = h.get("value") or ""
                break
        if not from_header:
            continue
        _, from_addr = parseaddr(from_header)
        from_addr_lc = (from_addr or "").strip().lower()
        if from_addr_lc and from_addr_lc == prospect_addr_lc:
            return True

    return False
def gmail_check_bounce_for(from_email: str, prospect_email: str) -> bool:
    """Heuristic bounce detection using Gmail search.

    We look for mailer-daemon / Mail Delivery Subsystem messages that mention
    the prospect's address.
    """
    query = (
        f"from:(mailer-daemon OR \"Mail Delivery Subsystem\") "
        f"to:{from_email} {prospect_email} newer_than:30d"
    )
    msgs = gmail_search_messages(from_email, query, max_results=3)
    return bool(msgs)


from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr


def gmail_send_with_attachment(
    from_email: str,
    to_email: str,
    subject: str,
    html_body: str,
    attachment_bytes: bytes,
    filename: str,
    from_name: str = "",
) -> Dict:
    """Send an email with a single attachment via Gmail API.

    Used for "email CSV to self" in OAuth mode.
    """
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body or "", "html", "utf-8"))

    if attachment_bytes is not None:
        part = MIMEApplication(attachment_bytes, _subtype="octet-stream")
        part.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(part)

    return _gmail_send_raw(access_token, msg.as_bytes())


def gmail_list_labels(from_email: str) -> List[Dict]:
    """Return list of labels for the OAuth Gmail account."""
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    url = f"{_GMAIL_API_BASE}/users/me/labels"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("labels", []) or []


def gmail_ensure_label(from_email: str, label_name: str) -> str:
    """Get or create a label and return its ID."""
    label_name = (label_name or "").strip()
    if not label_name:
        raise ValueError("Label name must be non-empty")
    labels = gmail_list_labels(from_email)
    for lbl in labels:
        if lbl.get("name") == label_name:
            return lbl.get("id", "")
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")
    url = f"{_GMAIL_API_BASE}/users/me/labels"
    payload = {
        "name": label_name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("id", "")



def gmail_label_message(from_email: str, message_id: str, label_name: str) -> None:
    """Apply a label to a specific message ID for OAuth mode.

    If label_name or message_id is blank, this is a no-op. Any HTTP errors
    from Gmail are propagated to the caller.
    """
    label_name = (label_name or "").strip()
    if not label_name or not message_id:
        return

    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")

    label_id = gmail_ensure_label(from_email, label_name)
    if not label_id:
        return

    url = f"{_GMAIL_API_BASE}/users/me/messages/{message_id}/modify"
    payload = {"addLabelIds": [label_id]}
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()



def gmail_create_draft(
    from_email: str,
    to_email: str,
    subject: str,
    html_body: str,
    label_name: str = "",
    from_name: str = "",
) -> Dict:
    """Create a Gmail draft in OAuth mode, optionally with a label."""
    access_token = get_valid_access_token(from_email)
    if not access_token:
        raise RuntimeError(f"No valid OAuth tokens for {from_email}")

    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body or "", "html", "utf-8"))

    raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    draft: Dict[str, any] = {"message": {"raw": raw_b64}}

    if label_name:
        label_id = gmail_ensure_label(from_email, label_name)
        if label_id:
            draft["message"]["labelIds"] = [label_id]

    url = f"{_GMAIL_API_BASE}/users/me/drafts"
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=draft,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()