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
           * If the sender is `peer_email` or any other non-me address, treat this as
             a reply and return True.

    2. **Fallback – subject + FROM match**
       - If no Message-ID–based hits are found, search for messages:
             FROM peer_email  AND  SUBJECT contains (a token from `orig_subject`)
         in "INBOX" and "[Gmail]/All Mail".
       - If we find any such message not clearly from `from_email`, treat it as a
         reply and return True.

    3. If both checks find nothing, return False.

    This is intentionally a bit conservative: for a given campaign row, *any* mail
    from the prospect that matches the subject thread (or references the message-id)
    counts as "prospect has replied", and Module 2 will skip further follow-ups.
    """
    orig_message_id = (orig_message_id or "").strip()
    me_lc = (from_email or "").strip().lower()
    peer_lc = (peer_email or "").strip().lower()

    # Normalise Message-ID variants: bare core and <core>
    variants = set()
    if orig_message_id:
        variants.add(orig_message_id)
        core = orig_message_id.strip().strip("<>")
        if core:
            variants.add(core)
            variants.add(f"<{core}>")

    def _contains_any(hval: str) -> bool:
        if not variants:
            return False
        s = (hval or "").lower()
        if not s:
            return False
        for v in variants:
            if v.lower() in s:
                return True
        return False

    # 1) Message-ID–based threading (preferred).
    found_any_mid_hit = False
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
                found_any_mid_hit = True
                typ, msgdata = M.uid("fetch", mid, "(RFC822.HEADER)")
                if typ != "OK" or not msgdata or not msgdata[0]:
                    continue
                msg = email.message_from_bytes(msgdata[0][1])
                frm = (msg.get("From") or "").lower()

                # Ignore messages clearly from me (the sender)
                if me_lc and me_lc in frm:
                    continue

                # If the prospect themselves replied, that's definitely a reply.
                if peer_lc and peer_lc in frm:
                    return True

                # Otherwise, ANY non-me sender in this referenced chain counts as reply.
                if frm.strip():
                    return True

        except Exception:
            # Best-effort: IMAP quirks shouldn't crash the job.
            continue

    # 2) Fallback – FROM + SUBJECT match, only if Message-ID–based search found nothing.
    if not found_any_mid_hit and peer_lc and orig_subject:
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
                        frm = (msg.get("From") or "").lower()

                        # Ignore anything clearly from me.
                        if me_lc and me_lc in frm:
                            continue

                        if frm.strip():
                            return True

                except Exception:
                    # Ignore mailbox-specific errors, continue to next.
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
