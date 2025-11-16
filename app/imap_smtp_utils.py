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
from email.utils import formataddr
from email.mime.application import MIMEApplication

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT_SSL = 465
IMAP_HOST = "imap.gmail.com"
GMAIL_SENT = '"[Gmail]/Sent Mail"'
GMAIL_DRAFTS = '"[Gmail]/Drafts"'
MAILER_DAEMON = ("mailer-daemon@googlemail.com", "Mail Delivery Subsystem")


def smtp_send_html(from_email: str, app_password: str, from_name: str,
                   to_email: str, subject: str, html_body: str) -> None:
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT_SSL) as server:
        server.login(from_email, app_password)
        server.sendmail(from_email, [to_email], msg.as_string())


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


def check_reply_exists(M: imaplib.IMAP4_SSL, orig_message_id: str,
                       from_email: str, peer_email: str) -> bool:
    """Best-effort heuristic: look for messages referencing orig_message_id from peer."""
    if not orig_message_id:
        return False
    for mbox in ('"INBOX"', '"[Gmail]/All Mail"'):
        try:
            typ, _ = M.select(mbox)
            if typ != "OK":
                continue

            # References
            typ, data = M.uid("search", None, 'HEADER', 'References', f'"{orig_message_id}"')
            msg_ids = data[0].split() if (typ == "OK" and data and data[0]) else []

            # In-Reply-To fallback
            if not msg_ids:
                typ, data = M.uid("search", None, 'HEADER', 'In-Reply-To', f'"{orig_message_id}"')
                msg_ids = data[0].split() if (typ == "OK" and data and data[0]) else []

            for mid in msg_ids:
                typ, msgdata = M.uid("fetch", mid, "(RFC822)")
                if typ == "OK" and msgdata and msgdata[0]:
                    msg = email.message_from_bytes(msgdata[0][1])
                    frm = (msg.get("From") or "").lower()
                    if peer_email.lower() in frm and from_email.lower() not in frm:
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
