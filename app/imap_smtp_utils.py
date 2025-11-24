"""Low-level IMAP/SMTP helpers.

These are intentionally narrow wrappers so they can be mocked easily in tests.
"""

import imaplib
import smtplib
import re
import time
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid
from email.mime.application import MIMEApplication

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT_SSL = 465
IMAP_HOST = "imap.gmail.com"
GMAIL_SENT = '"[Gmail]/Sent Mail"'
GMAIL_DRAFTS = '"[Gmail]/Drafts"'
MAILER_DAEMON = ("mailer-daemon@googlemail.com", "Mail Delivery Subsystem")


def smtp_send_html(from_email: str, app_password: str, from_name: str,
                   to_email: str, subject: str, html_body: str) -> str:
    """
    Send an HTML email via Gmail SMTP and return the RFC 2822 Message-ID we used.

    We explicitly generate a stable Message-ID header before sending so that:
      - Module 1 can always record a non-empty orig_message_id in the CSV,
      - Module 2 (SMTP mode) can reliably use that ID for reply detection,
      - IMAP-based labeling can search by Message-ID instead of only by TO.
    """
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    # Ensure we always have a Message-ID for downstream threading logic.
    if not msg.get("Message-ID"):
        msg["Message-ID"] = make_msgid()
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT_SSL) as server:
        server.login(from_email, app_password)
        server.sendmail(from_email, [to_email], msg.as_string())

    # Return the Message-ID so callers can persist it in the result CSV
    return msg["Message-ID"]


def smtp_build_mime(from_email: str, from_name: str,
                    to_email: str, subject: str, html_body: str) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


def imap_login(user: str, app_password: str) -> imaplib.IMAP4_SSL:
    M = imaplib.IMAP4_SSL(IMAP_HOST)
    M.login(user, app_password)
    return M


def imap_search_last_sent_to_uid(M: imaplib.IMAP4_SSL, to_email: str):
    typ, _ = M.select(GMAIL_SENT)
    if typ != "OK":
        return None, None
    typ, data = M.uid("search", None, 'TO', f'"{to_email}"')
    if typ != "OK" or not data or not data[0]:
        return None, None
    ids = data[0].split()
    if not ids:
        return None, None
    last_uid = ids[-1]
    typ, msgdata = M.uid("fetch", last_uid, "(RFC822)")
    if typ != "OK" or not msgdata or not msgdata[0]:
        return (last_uid.decode() if isinstance(last_uid, bytes) else str(last_uid), None)
    msg = email.message_from_bytes(msgdata[0][1])
    return (last_uid.decode() if isinstance(last_uid, bytes) else str(last_uid), msg)



def imap_find_message_by_message_id(M: imaplib.IMAP4_SSL, message_id: str):
    """
    Locate the most recent message in Gmail Sent with the given Message-ID.

    Returns (uid, email.message.Message | None). If the UID is found but the
    RFC822 body cannot be fetched, returns (uid, None).
    """
    if not M:
        return None, None
    message_id = (message_id or "").strip()
    if not message_id:
        return None, None
    try:
        typ, _ = M.select(GMAIL_SENT)
        if typ != "OK":
            return None, None

        core = message_id.strip().strip("<>")
        if not core:
            return None, None

        variants = []
        for v in (message_id, core, f"<{core}>"):
            v = v.strip()
            if v and v not in variants:
                variants.append(v)

        all_uids = []
        for v in variants:
            typ, data = M.uid("search", None, "HEADER", "Message-ID", f'"{v}"')
            if typ == "OK" and data and data[0]:
                all_uids.extend(data[0].split())

        if not all_uids:
            return None, None

        # De-duplicate while preserving order, then take the last match.
        seen = set()
        unique_uids = []
        for uid in all_uids:
            key = uid.decode() if isinstance(uid, bytes) else str(uid)
            if key not in seen:
                seen.add(key)
                unique_uids.append(uid)

        last_uid = unique_uids[-1]
        typ, msgdata = M.uid("fetch", last_uid, "(RFC822)")
        if typ != "OK" or not msgdata or not msgdata[0]:
            return (last_uid.decode() if isinstance(last_uid, bytes) else str(last_uid), None)

        msg = email.message_from_bytes(msgdata[0][1])
        return (last_uid.decode() if isinstance(last_uid, bytes) else str(last_uid), msg)
    except Exception:
        # Best-effort only – callers should treat failures as "not found".
        return None, None


def imap_add_label_to_uid(M: imaplib.IMAP4_SSL, uid_val: str, label: str) -> None:
    if not (M and uid_val and label):
        return
    safe = re.sub(r"[\r\n]+", " ", str(label)).strip()
    if not safe:
        return
    try:
        M.uid("STORE", uid_val, "+X-GM-LABELS", f'("{safe}")')
    except Exception:
        # Best-effort only
        pass


def imap_append_draft(M: imaplib.IMAP4_SSL, mime_msg_bytes: bytes) -> None:
    """Append a MIME message bytes object to Drafts with the \Draft flag."""
    M.append(GMAIL_DRAFTS, "\\Draft", imaplib.Time2Internaldate(time.time()), mime_msg_bytes)



def check_reply_exists(
    M: imaplib.IMAP4_SSL,
    orig_message_id: str,
    from_email: str,
    peer_email: str,
    orig_subject: str = "",
) -> bool:
    """Best-effort heuristic: detect whether the peer has replied in this conversation (SMTP/IMAP).
    
    Strategy (SMTP mode is inherently more approximate than Gmail API threads):
    
    1. **Primary check – Message-ID threading**
       - Build a few variants of the stored `orig_message_id` (with and without angle
         brackets) and search both "INBOX" and "[Gmail]/All Mail" for messages whose
         `References` or `In-Reply-To` headers contain any of those variants.
       - For any such message:
         * Ignore messages clearly from `from_email` (the sending account).
         * If the sender is `peer_email`, treat this as a reply and return True.
    
    2. **Fallback – subject + FROM match**
       - If no Message-ID–based hits are found, search for messages:
         FROM peer_email AND SUBJECT contains (a token from `orig_subject`)
         in "INBOX" and "[Gmail]/All Mail".
       - If we find any such message from the prospect, treat it as a reply.
    
    3. **Additional check – Direct FROM search**
       - Search for ANY messages from peer_email that might be in the conversation
       - This catches cases where threading headers aren't properly set
    
    4. If all checks find nothing, return False.
    
    This is intentionally conservative: for a given campaign row, we only count
    emails specifically from the prospect as "replied", and Module 2 will skip
    further follow-ups only when the prospect has actually responded.
    """
    orig_message_id = (orig_message_id or "").strip()
    from_email_normalized = (from_email or "").strip().lower()
    peer_email_normalized = (peer_email or "").strip().lower()

    # Helper function to check if email address is from the sender (me)
    def is_from_me(from_header: str) -> bool:
        """Check if From header is from the sending account, handling display names."""
        from_lower = (from_header or "").strip().lower()
        if not from_lower:
            return False
        # Check if our email appears anywhere in the From header
        # This handles both "email@domain.com" and "Name <email@domain.com>" formats
        return from_email_normalized in from_lower
    
    # Helper function to check if email address is from the prospect
    def is_from_prospect(from_header: str) -> bool:
        """Check if From header is from the prospect."""
        from_lower = (from_header or "").strip().lower()
        if not from_lower:
            return False
        return peer_email_normalized in from_lower

    # Normalise Message-ID variants: bare core and angle-bracketed versions
    variants = set()
    if orig_message_id:
        variants.add(orig_message_id)
        core = orig_message_id.strip().strip("<>")
        if core:
            variants.add(core)
            variants.add(f"<{core}>")

    # 1) Message-ID–based threading (preferred).
    for mbox in ('"INBOX"', '"[Gmail]/All Mail"'):
        try:
            typ, _ = M.select(mbox)
            if typ != "OK":
                continue

            msg_ids = []
            if variants:
                for v in variants:
                    for header in ("References", "In-Reply-To"):
                        typ, data = M.uid("search", None, "HEADER", header, f'"{v}"')
                        if typ == "OK" and data and data[0]:
                            msg_ids.extend(data[0].split())

            # De-duplicate while preserving order
            seen = set()
            msg_ids = [mid for mid in msg_ids if not (mid in seen or seen.add(mid))]

            for mid in msg_ids:
                typ, msgdata = M.uid("fetch", mid, "(RFC822.HEADER)")
                if typ != "OK" or not msgdata or not msgdata[0]:
                    continue

                msg = email.message_from_bytes(msgdata[0][1])
                frm = msg.get("From") or ""

                # Skip messages from me (the sender)
                if is_from_me(frm):
                    continue

                # ✅ ONLY return True if it's specifically from the prospect
                if is_from_prospect(frm):
                    return True
                
                # ✅ REMOVED: The buggy "any non-me sender" logic

        except Exception:
            # Best-effort: IMAP quirks shouldn't crash the job.
            continue

    # 2) Fallback – FROM + SUBJECT match
    if peer_email_normalized and orig_subject:
        # Use a short, stable token from the subject (strip "Re:" and whitespace).
        subj = orig_subject
        # Normalise "Re: " prefix away
        if subj.lower().startswith("re:"):
            subj = subj[3:]
        subj = subj.strip()

        # Take a reasonable-length prefix to search for
        token = subj[:40] if len(subj) > 40 else subj

        if token:
            for mbox in ('"INBOX"', '"[Gmail]/All Mail"'):
                try:
                    typ, _ = M.select(mbox)
                    if typ != "OK":
                        continue

                    typ, data = M.uid("search", None, "FROM", f'"{peer_email}"', "SUBJECT", f'"{token}"')
                    msg_ids = data[0].split() if (typ == "OK" and data and data[0]) else []

                    for mid in msg_ids:
                        typ, msgdata = M.uid("fetch", mid, "(RFC822.HEADER)")
                        if typ != "OK" or not msgdata or not msgdata[0]:
                            continue

                        msg = email.message_from_bytes(msgdata[0][1])
                        frm = msg.get("From") or ""

                        # Skip messages from me
                        if is_from_me(frm):
                            continue

                        # ✅ ONLY return True if from prospect
                        if is_from_prospect(frm):
                            return True

                except Exception:
                    # Ignore mailbox-specific errors, continue to next.
                    continue

    # 3) Additional direct FROM search (catches cases where threading fails)
    if peer_email_normalized:
        for mbox in ('"INBOX"', '"[Gmail]/All Mail"'):
            try:
                typ, _ = M.select(mbox)
                if typ != "OK":
                    continue

                # Search for ANY messages from the prospect
                typ, data = M.uid("search", None, "FROM", f'"{peer_email}"')
                msg_ids = data[0].split() if (typ == "OK" and data and data[0]) else []

                # Check recent messages (last 10) to avoid scanning entire inbox
                for mid in msg_ids[-10:]:
                    typ, msgdata = M.uid("fetch", mid, "(RFC822.HEADER)")
                    if typ != "OK" or not msgdata or not msgdata[0]:
                        continue

                    msg = email.message_from_bytes(msgdata[0][1])
                    frm = msg.get("From") or ""
                    
                    # Verify it's actually from prospect
                    if is_from_prospect(frm):
                        # Check if subject is related to our conversation
                        msg_subject = (msg.get("Subject") or "").lower()
                        orig_subject_lower = (orig_subject or "").lower().replace("re:", "").strip()
                        
                        # If subject matches or references our message, count as reply
                        if orig_subject_lower and orig_subject_lower[:30] in msg_subject:
                            return True

            except Exception:
                continue

    return False


def check_bounce_for(M: imaplib.IMAP4_SSL, to_email: str, max_scan: int = 50) -> bool:
    """Scan recent DSNs for a bounce mentioning the recipient address."""
    try:
        typ, _ = M.select('"INBOX"')
        if typ != "OK":
            return False
        typ, data = M.uid("search", None, 'FROM', '"Mail Delivery Subsystem"')
        ids = data[0].split() if (typ == "OK" and data and data[0]) else []
        ids = ids[-max_scan:]
        for mid in reversed(ids):
            typ, msgdata = M.uid("fetch", mid, "(RFC822)")
            if typ != "OK" or not msgdata or not msgdata[0]:
                continue
            msg = email.message_from_bytes(msgdata[0][1])
            payload = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        try:
                            payload += part.get_payload(decode=True).decode(errors="ignore")
                        except Exception:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    payload = ""
            if to_email.lower() in payload.lower():
                return True
    except Exception:
        return False
    return False


def smtp_send_with_attachment(from_email: str, app_password: str, from_name: str,
                              to_email: str, subject: str, html_body: str,
                              attachment_bytes: bytes, attachment_filename: str,
                              mime_type: str = "text/csv") -> None:
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body or "", "html", "utf-8"))

    if attachment_bytes is not None:
        part = MIMEApplication(attachment_bytes, _subtype=mime_type.split("/")[-1])
        part.add_header("Content-Disposition", "attachment", filename=attachment_filename)
        msg.attach(part)

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT_SSL) as server:
        server.login(from_email, app_password)
        server.sendmail(from_email, [to_email], msg.as_string())
