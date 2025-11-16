import io
import json
import os
import re
import time
import random
from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd

from .celery_app import celery_app
from .email_styles import prepare_email_html, font_stack_from_key
from .imap_smtp_utils import (
    smtp_send_html,
    smtp_build_mime,
    imap_login,
    imap_search_last_sent_to_uid,
    imap_add_label_to_uid,
    imap_append_draft,
    check_reply_exists,
    check_bounce_for,
    smtp_send_with_attachment,
)
from .gmail_api_utils import (
    gmail_send_html,
    gmail_reply_html,
    gmail_find_last_sent_to,
    gmail_check_reply_exists,
    gmail_thread_has_prospect_reply,
    gmail_check_bounce_for,
    gmail_send_with_attachment,
    gmail_label_message,
    gmail_create_draft,
    gmail_get_message,
    gmail_fetch_message_id_header,
)

from .security import (
    decrypt_secret,
    normalize_email,
    hash_email,
    load_sent_hashes,
    record_sent_hash,
)
from .quota import can_send as quota_can_send, consume as quota_consume
from .concurrency import acquire_account_lock, release_account_lock

DATA_DIR = os.getenv("DATA_DIR", "/data")


class SafeDict(dict):
    """format_map-safe dict that leaves unknown placeholders untouched."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _ensure_job_dir(job_id: str) -> str:
    job_dir = os.path.join(DATA_DIR, "jobs", job_id)
    os.makedirs(job_dir, exist_ok=True)
    return job_dir


def _write_log(job_dir: str, line: str) -> None:
    path = os.path.join(job_dir, "log.txt")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {line}\n")


def _control_flag(job_dir: str, name: str) -> str:
    return os.path.join(job_dir, f"{name}.flag")


def _maybe_pause_or_stop(job_dir: str) -> str:
    if os.path.exists(_control_flag(job_dir, "stop")):
        return "stop"
    if os.path.exists(_control_flag(job_dir, "pause")):
        return "pause"
    return ""


def _load_csv_any(path_or_bytes) -> pd.DataFrame:
    if isinstance(path_or_bytes, (bytes, bytearray)):
        bio = io.BytesIO(path_or_bytes)
        return pd.read_csv(bio, dtype=str, encoding="utf-8", sep=None, engine="python")
    return pd.read_csv(path_or_bytes, dtype=str, encoding="utf-8", sep=None, engine="python")


HEADER_ALIASES = {
    "first": {
        "first",
        "first name",
        "firstname",
        "first_name",
        "first-name",
        "fname",
        "given",
        "given name",
    },
    "last": {
        "last",
        "last name",
        "lastname",
        "last_name",
        "last-name",
        "lname",
        "surname",
        "family name",
    },
    "email": {
        "email",
        "email address",
        "e-mail",
        "mail",
    },
    "company": {
        "company",
        "company name",
        "companyname",
        "company_name",
        "company-name",
        "organisation",
        "organization",
        "org",
        "business",
    },
    "title": {
        "title",
        "job title",
        "job_title",
        "job-title",
        "designation",
        "role",
        "position",
    },
}


def _canonical_header(name: str) -> str:
    """Normalize a raw header into a canonical key (first, last, company, etc.)."""
    if not isinstance(name, str):
        name = str(name or "")
    key = re.sub(r"[\s_\-]+", " ", name.strip().lower())
    for canon, aliases in HEADER_ALIASES.items():
        if key in aliases:
            return canon
    return key


def _normalize_header(s: str) -> str:
    """Wrapper kept for backward compatibility."""
    return _canonical_header(s)


def _fmt_ts_for_name(dt: datetime) -> str:
    # ddmmyyyy-HH:MM:SS
    return dt.strftime("%d%m%Y-%H:%M:%S")


def _label_from_rows(rows: List[Dict[str, Any]], fallback: str = "") -> str:
    if fallback:
        return fallback
    labels = [str(r.get("batch_label", "")).strip() for r in rows if str(r.get("batch_label", "")).strip()]
    if not labels:
        return "NoLabel"
    try:
        from collections import Counter

        return Counter(labels).most_common(1)[0][0]
    except Exception:
        return labels[0]


def _ensure_result_csv(job_dir: str, rows: List[Dict[str, Any]]) -> str:
    out_path = os.path.join(job_dir, "result.csv")
    if not os.path.exists(out_path):
        try:
            pd.DataFrame(rows).to_csv(out_path, index=False)
        except Exception:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("")
    return out_path


def _single_run_start(job_dir: str, module: str) -> bool:
    """
    Ensure a given job_id/module combination runs at most once.

    Returns:
        True  -> safe to proceed (this is the first/only run)
        False -> another run is in progress or already finished; caller must exit.
    """
    started_flag = os.path.join(job_dir, f"{module}_started.flag")
    done_flag = os.path.join(job_dir, f"{module}_done.flag")

    # Already completed once: never run again.
    if os.path.exists(done_flag):
        _write_log(job_dir, f"{module}: already completed; ignoring duplicate invocation.")
        return False

    # Try to claim the start.
    try:
        fd = os.open(started_flag, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        # Another worker / task invocation beat us.
        _write_log(job_dir, f"{module}: already running; ignoring duplicate invocation.")
        return False


def _single_run_finish(job_dir: str, module: str) -> None:
    """Mark job as finished so any stray duplicate tasks become no-ops."""
    started_flag = os.path.join(job_dir, f"{module}_started.flag")
    done_flag = os.path.join(job_dir, f"{module}_done.flag")
    try:
        with open(done_flag, "a", encoding="utf-8"):
            pass
    except Exception:
        pass
    try:
        os.remove(started_flag)
    except FileNotFoundError:
        pass



def _finalize_and_email(
    job_dir: str,
    rows: List[Dict[str, Any]],
    from_email: str,
    app_password: str,
    from_name: str,
    label_guess: str,
    module_name: str,
    delivery_mode: str = "smtp",
) -> None:
    """Guarantee a CSV + email snapshot to self on completion or stop."""
    csv_path = _ensure_result_csv(job_dir, rows)
    try:
        with open(csv_path, "rb") as fh:
            csv_bytes = fh.read()
    except Exception as e:
        _write_log(job_dir, f"Failed reading result.csv for mail: {e}")
        csv_bytes = b""

    label = _label_from_rows(rows, label_guess or "")
    ts = _fmt_ts_for_name(datetime.now())
    attach_name = f"mail-{label}-{ts}.csv"

    subject = f"[{module_name}] CSV export {label} @ {ts}"
    body = (
        f"<div>Attached is the CSV export for job <b>{os.path.basename(job_dir)}</b> "
        f"({module_name}).<br/>Label: <b>{label}</b><br/>Timestamp: <b>{ts}</b></div>"
    )

    try:
        if delivery_mode == "gmail_api":
            # OAuth / Gmail API mode: send snapshot via Gmail API (no app password).
            gmail_send_with_attachment(
                from_email=from_email,
                to_email=from_email,
                subject=subject,
                html_body=body,
                attachment_bytes=csv_bytes,
                filename=attach_name,
                from_name=from_name or "",
            )
            _write_log(job_dir, f"Emailed CSV snapshot to self via Gmail API as: {attach_name}")
        else:
            # Legacy SMTP mode.
            if not app_password:
                _write_log(
                    job_dir,
                    "Skipping 'email CSV to self' because no SMTP app password is configured. "
                    "result.csv is still saved on disk.",
                )
                return
            smtp_send_with_attachment(
                from_email=from_email,
                app_password=app_password,
                from_name=from_name or "",
                to_email=from_email,
                subject=subject,
                html_body=body,
                attachment_bytes=csv_bytes,
                attachment_filename=attach_name,
                mime_type="text/csv",
            )
            _write_log(job_dir, f"Emailed CSV snapshot to self as: {attach_name}")
    except Exception as e:
        _write_log(job_dir, f"ERROR emailing CSV to self: {e}")
def _prepare_rows_case_a(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Normalize outreach CSV into canonical columns for Module 1."""
    norm_lookup = {_canonical_header(c): c for c in df_raw.columns}
    required = ["first", "last", "title", "company", "email"]

    missing = [k for k in required if k not in norm_lookup]
    if missing:
        raise ValueError(
            "CSV must contain first/last/title/company/email columns. "
            "Any common variant is accepted (First Name, first_name, Company, Email Address, etc.)."
        )

    df = pd.DataFrame()
    for key in required:
        src = norm_lookup[key]
        df[key] = df_raw[src].astype(str).str.strip()

    if "sent_flag" in df_raw.columns:
        df["sent_flag"] = df_raw["sent_flag"]
    else:
        df["sent_flag"] = "not_sent"

    return df



def _prepare_rows_case_b(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Normalize CSV into canonical columns for Module 1 result / Module 2 input.

    This is used when:
      * Module 2 reads the result CSV from Module 1, or
      * Module 2 is re-run on its *own* result CSV for subsequent follow-ups.

    We:
      * Canonicalize headers using _canonical_header so we accept minor variants.
      * Always materialize the core identity columns (first, last, title, company, email).
      * Pass through any known metadata columns if present (sent_flag, orig_message_id, etc.).
      * Fill missing metadata columns with empty strings so downstream code can rely on them.
    """
    # Build canonical lookup: canonical_name -> original column name
    norm_lookup = {_canonical_header(c): c for c in df_raw.columns}

    required = ["first", "last", "title", "company", "email"]
    missing = [k for k in required if k not in norm_lookup]
    if missing:
        raise ValueError(
            "CSV must contain first/last/title/company/email columns. Any common variant is accepted."
        )

    df = pd.DataFrame()

    # Core identity columns
    for nm in required:
        src = norm_lookup[nm]
        df[nm] = df_raw[src].astype(str).str.strip()

    # Known optional / metadata columns that we want to preserve when present
    optional_cols = [
        "sent_flag",
        "orig_subject",
        "orig_message_id",
        "rfc_message_id",
        "orig_references",
        "orig_date",
        "orig_thread_id",
        "followup_flag",
        "followup_status",
        "followup_error",
        "followup_ts_utc",
        "batch_label",
        "prev_followup_flag",
        "prev_followup_status",
        "prev_followup_error",
        "prev_followup_ts_utc",
        "last_followup_message_id",
        "last_followup_references",
        "last_followup_date",
    ]

    for col in optional_cols:
        src = norm_lookup.get(col)
        if not src and col in df_raw.columns:
            # Column already exists with the canonical name.
            src = col
        if src:
            df[col] = df_raw[src]
        else:
            # Default to empty string; downstream code may overwrite or snapshot these.
            df[col] = ""

    # Basic hygiene: only keep rows with a plausible email and not entirely empty identity.
    df["email"] = df["email"].astype(str).str.strip()
    df = df[df["email"].str.contains("@", na=False)]
    df = df[
        ~(
            df[["first", "last", "title", "company", "email"]]
            .replace("", pd.NA)
            .isna()
            .all(axis=1)
        )
    ]
    return df



def _load_rows_for_module1(csv_content) -> pd.DataFrame:
    """Load outreach CSV with flexible header names into canonical columns."""
    df_raw = _load_csv_any(csv_content)
    df = _prepare_rows_case_a(df_raw)

    df = df[df["email"].str.contains("@", na=False)]
    df = df[
        ~(
            df[["first", "last", "title", "company", "email"]]
            .replace("", pd.NA)
            .isna()
            .all(axis=1)
        )
    ]
    return df



def _load_rows_for_module2(csv_content, require_orig_message_id: bool = True) -> pd.DataFrame:
    df = _prepare_rows_case_b(_load_csv_any(csv_content))

    # Ensure key columns exist
    for col in ["orig_subject", "sent_flag"]:
        if col not in df.columns:
            df[col] = ""

    # Snapshot any previous follow-up information (if this CSV is the
    # result of an earlier Module 2 run) so we can keep history while
    # starting with clean follow-up fields for this job.
    if "followup_flag" in df.columns:
        df["prev_followup_flag"] = df["followup_flag"].astype(str)
    else:
        df["prev_followup_flag"] = ""

    if "followup_status" in df.columns:
        df["prev_followup_status"] = df["followup_status"].astype(str)
    else:
        df["prev_followup_status"] = ""

    if "followup_error" in df.columns:
        df["prev_followup_error"] = df["followup_error"].astype(str)
    else:
        df["prev_followup_error"] = ""

    if "followup_ts_utc" in df.columns:
        df["prev_followup_ts_utc"] = df["followup_ts_utc"].astype(str)
    else:
        df["prev_followup_ts_utc"] = ""

    # Reset follow-up fields for this *new* Module 2 run so that
    # progress/proportions are computed from this job, not previous ones.
    df["followup_flag"] = "not_sent"
    df["followup_status"] = ""
    df["followup_error"] = ""
    df["followup_ts_utc"] = ""

    # Filter to only rows that represent successfully sent initial outreach.
    # For legacy SMTP/IMAP mode we require a non-empty original Message-ID.
    base_mask = (
        df["email"].str.contains("@", na=False)
        & (df["orig_subject"].astype(str).str.len() > 0)
        & (df["sent_flag"].astype(str).str.lower() == "sent")
    )
    if require_orig_message_id:
        base_mask = base_mask & (df["orig_message_id"].astype(str).str.len() > 0)

    # Primary filter: only rows that represent successfully sent initial outreach.
    df_filtered = df[base_mask].copy()

    # Fallback: if everything was filtered out (e.g. due to missing sent_flag or
    # Message-ID in a re-imported CSV), progressively relax the constraints so
    # that legitimate follow-up rows are not silently dropped.
    if df_filtered.empty:
        # First, ignore the sent_flag requirement but still require a subject
        # and (optionally) an original Message-ID.
        alt_mask = df["email"].str.contains("@", na=False) & (df["orig_subject"].astype(str).str.len() > 0)
        if require_orig_message_id:
            alt_mask = alt_mask & (df["orig_message_id"].astype(str).str.len() > 0)
        df_filtered = df[alt_mask].copy()

        # As a last resort (mainly for legacy data), drop the Message-ID
        # requirement entirely and just rely on email + subject.
        if df_filtered.empty and require_orig_message_id:
            alt_mask2 = df["email"].str.contains("@", na=False) & (
                df["orig_subject"].astype(str).str.len() > 0
            )
            df_filtered = df[alt_mask2].copy()

    df = df_filtered

    if "batch_label" not in df.columns:
        df["batch_label"] = ""
    if "last_followup_message_id" not in df.columns:
        df["last_followup_message_id"] = ""
    if "last_followup_references" not in df.columns:
        df["last_followup_references"] = ""
    if "last_followup_date" not in df.columns:
        df["last_followup_date"] = ""

    return df

def _apply_selection(df: pd.DataFrame, selection_mode: str, selected_indices) -> pd.DataFrame:
    df = df.copy()
    df["__selected__"] = False
    if selected_indices:
        for idx in selected_indices:
            if idx in df.index:
                df.at[idx, "__selected__"] = True
    return df


def _row_action(selection_mode: str, is_selected: bool) -> str:
    """Decide per-row action (send / draft / skip) based on selection mode.

    selection_mode values:
      - send_all: send every row
      - send_selected: only send selected rows
      - draft_all: draft every row
      - draft_selected_only: only draft selected rows
      - draft_selected_and_send_rest: draft selected, send the rest
    """
    if selection_mode == "send_all":
        return "send"
    if selection_mode == "send_selected":
        return "send" if is_selected else "skip"
    if selection_mode == "draft_all":
        return "draft"
    if selection_mode == "draft_selected_only":
        return "draft" if is_selected else "skip"
    if selection_mode == "draft_selected_and_send_rest":
        return "draft" if is_selected else "send"
    return "send"



def _progress_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Compute aggregate counts for progress bars for both modules.

    For Module 1 we use the generic ``status`` column.
    For Module 2 we fall back to follow-up specific columns (``followup_flag``
    and ``followup_status``).
    """
    sent = drafted = skipped = errors = 0
    for r in rows:
        s = str(r.get("status") or "").upper()
        fs = str(r.get("followup_status") or "").upper()
        ff = str(r.get("followup_flag") or "").lower()

        # Errors take precedence so they do not get double-counted
        if s == "ERROR" or fs == "ERROR":
            errors += 1
        # Sent / successfully followed-up
        elif s == "SENT" or ff == "sent" or fs == "FOLLOWED_UP":
            sent += 1
        # Drafts are only used by Module 1
        elif s == "DRAFTED":
            drafted += 1
        # Any kind of skip (including skipped_reply / skipped_bounce)
        elif s == "SKIPPED" or ff.startswith("skipped") or fs == "SKIPPED":
            skipped += 1

    return {"sent": sent, "drafted": drafted, "skipped": skipped, "errors": errors}


def _update_state(self, job_id: str, module: str, rows: List[Dict[str, Any]], total: int) -> None:
    try:
        counts = _progress_counts(rows)
        current = counts["sent"] + counts["drafted"] + counts["skipped"] + counts["errors"]
        self.update_state(
            state="PROGRESS",
            meta={
                "module": module,
                "job_id": job_id,
                "current": current,
                "total": total,
                **counts,
            },
        )
    except Exception:
        pass


@celery_app.task(bind=True)
def module1_send_task(self, job_id: str, payload_path: str):
    """Initial outreach sender with locking, dedupe, quota, and CSV snapshot."""
    job_dir = _ensure_job_dir(job_id)

    # Per-job single-run guard
    if not _single_run_start(job_dir, "m1"):
        return {"sent": 0, "total": 0, "job_id": job_id, "status": "duplicate_invocation"}

    lock_path = None
    try:
        try:
            self.update_state(state="STARTED", meta={"job_id": job_id})
        except Exception:
            pass

        with open(payload_path, "r", encoding="utf-8") as f:
            P = json.load(f)

        _write_log(job_dir, f"Starting Module 1 for job {job_id}")

        from_email = P["from_email"]
        delivery_mode = P.get("delivery_mode", "smtp")

        app_password = decrypt_secret(P.get("app_password_enc") or P.get("app_password", ""))
        from_name = P.get("from_name") or ""
        label_name = P.get("label_name") or ""
        cooldown = int(P.get("cooldown_s", 30))
        overhead = int(P.get("overhead_s", 3))
        cooldown_random_enabled = bool(P.get("cooldown_random_enabled", False))
        cooldown_min_s = int(P.get("cooldown_min_s", cooldown))
        cooldown_max_s = int(P.get("cooldown_max_s", cooldown))
        force_send_duplicates = bool(P.get("force_send_duplicates", False))

        def _compute_cooldown_for_row() -> float:
            """Return cooldown (seconds) for this row, applying randomness if enabled."""
            if cooldown_random_enabled:
                lo = max(0.0, float(cooldown_min_s))
                hi = max(lo, float(cooldown_max_s))
                if hi > 0:
                    return random.uniform(lo, hi)
            return float(max(0, cooldown))

        subject_template = P.get("subject_template") or ""
        body_html_template = P.get("body_html_template") or ""

        font_key = P.get("font_family_key") or "Verdana"
        font_size_px = int(P.get("font_size_px", 13))
        para_gap_px = int(P.get("para_gap_px", 6))
        font_stack = font_stack_from_key(font_key)

        selection_mode = P.get("selection_mode", "send_all")
        selected_indices = P.get("selected_indices", [])

        if P.get("csv_path"):
            with open(P["csv_path"], "rb") as fh:
                csv_content = fh.read()
        else:
            csv_content = bytes(P.get("csv_bytes") or b"")

        df = _load_rows_for_module1(csv_content)
        df = _apply_selection(df, selection_mode, selected_indices)
        rows = df.to_dict(orient="records")
        # Pre-initialize RFC threading metadata so result CSV always has these columns.
        for r in rows:
            r.setdefault("orig_message_id", "")
            r.setdefault("rfc_message_id", "")
            r.setdefault("orig_references", "")
            r.setdefault("orig_date", "")
            r.setdefault("orig_thread_id", "")
        total = len(rows)
        if total == 0:
            _write_log(job_dir, "No valid rows found in CSV; exiting.")
            return {"sent": 0, "total": 0, "job_id": job_id}

        sent_hashes = load_sent_hashes(from_email)

        # Determine how long we are allowed to wait for the Gmail account lock.
        # "later" scheduled jobs can wait longer; "now" jobs should fail fast.
        schedule_info = P.get("schedule", {}) or {}
        schedule_mode = schedule_info.get("mode", "now")
        max_wait = 2 * 60 * 60 if schedule_mode == "later" else 60

        def _check_stop():
            return os.path.exists(_control_flag(job_dir, "stop"))

        ok, lock_path = acquire_account_lock(
            from_email,
            "gmail",
            log=lambda m: _write_log(job_dir, m),
            check_stop=_check_stop,
            max_wait_seconds=max_wait,
        )
        if not ok:
            _write_log(job_dir, "Account lock not acquired; another Gmail job is active. Aborting outreach job.")
            return {"sent": 0, "total": total, "job_id": job_id, "status": "account_lock_conflict"}

        M = None
        try:
            try:
                # In OAuth / Gmail API mode we do not have an app password, so skip IMAP.
                if delivery_mode != "gmail_api":
                    M = imap_login(from_email, app_password)
                else:
                    M = None
            except Exception as e:
                _write_log(job_dir, f"IMAP login failed (labeling/dedup from Sent partially disabled): {e}")
                M = None

            sent_count = 0

            for i, r in enumerate(rows):
                # pause/stop
                while True:
                    flag = _maybe_pause_or_stop(job_dir)
                    if flag == "stop":
                        _write_log(job_dir, "STOP flag detected. Ending job.")
                        break
                    if flag == "pause":
                        time.sleep(1.0)
                        continue
                    break
                if flag == "stop":
                    break

                to_addr_raw = r.get("email") or ""
                to_addr = normalize_email(to_addr_raw)
                if not to_addr or "@" not in to_addr:
                    r["status"] = "SKIPPED"
                    r["error"] = "Invalid email"
                    _write_log(job_dir, f"[{i+1}/{total}] SKIPPED invalid email -> {to_addr_raw}")
                    pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                    _update_state(self, job_id, "m1", rows, total)
                    continue

                act = _row_action(selection_mode, bool(r.get("__selected__")))

                if act == "send":
                    h = hash_email(to_addr)

                    if not force_send_duplicates:
                        # local history
                        if h in sent_hashes:
                            r["status"] = "SKIPPED"
                            r["sent_flag"] = "duplicate_history"
                            r["error"] = ""
                            _write_log(job_dir, f"[{i+1}/{total}] SKIPPED (already sent before) -> {to_addr}")
                            pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                            _update_state(self, job_id, "m1", rows, total)
                            continue

                        # Gmail Sent check
                        if M:
                            try:
                                uid_prev, msg_prev = imap_search_last_sent_to_uid(M, to_addr)
                            except Exception:
                                uid_prev, msg_prev = (None, None)
                            if uid_prev or msg_prev:
                                r["status"] = "SKIPPED"
                                r["sent_flag"] = "duplicate_gmail"
                                r["error"] = ""
                                record_sent_hash(from_email, to_addr, "m1", job_id)
                                sent_hashes.add(hash_email(to_addr))
                                _write_log(job_dir, f"[{i+1}/{total}] SKIPPED (found in Gmail Sent) -> {to_addr}")
                                pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                                _update_state(self, job_id, "m1", rows, total)
                                continue

                    allowed, msg = quota_can_send(from_email, 1)
                    if msg:
                        _write_log(job_dir, msg)
                    if not allowed:
                        r["status"] = "SKIPPED"
                        r["error"] = "Quota exceeded; job halted."
                        _write_log(
                            job_dir,
                            f"[{i+1}/{total}] Stopping further sends due to quota guard for {from_email}.",
                        )
                        break

                # Build personalized content
                ctx = dict(r)
                ctx["sender_name"] = from_name
                try:
                    subj_now = (subject_template or "").format_map(SafeDict(ctx))
                except Exception:
                    subj_now = subject_template or ""
                try:
                    raw_body = (body_html_template or "").format_map(SafeDict(ctx))
                except Exception:
                    raw_body = body_html_template or ""
                final_html = prepare_email_html(raw_body, para_gap_px, font_stack, font_size_px)

                try:
                    if act == "send":
                        if P.get("delivery_mode") == "gmail_api":
                            # Gmail API send (no app password); capture message + thread for reply-aware follow-ups.
                            api_msg = gmail_send_html(from_email, to_addr, subj_now, final_html, from_name=from_name)
                            _write_log(job_dir, f"[{i+1}/{total}] SENT (API) -> {to_addr}")
                            sent_count += 1

                            # Basic identifiers from the send response (always available)
                            api_msg_id = api_msg.get("id", "") or ""
                            api_thread_id = api_msg.get("threadId", "") or ""

                            if api_thread_id:
                                r["orig_thread_id"] = api_thread_id

                                                        # Apply label and fetch RFC822 headers for reply-aware Module 2.
                            try:
                                msg_id = api_msg_id
                                if msg_id and label_name:
                                    gmail_label_message(from_email, msg_id, label_name)

                                msg_id_hdr = ""
                                hdrs: Dict[str, str] = {}
                                if msg_id:
                                    # First, retry-fetch the RFC 2822 Message-ID header. Gmail can lag a bit
                                    # after send(), so we give it multiple chances.
                                    msg_id_hdr = gmail_fetch_message_id_header(from_email, msg_id) or ""

                                    # Then, make a single richer metadata call to also capture References / Date.
                                    try:
                                        meta = gmail_get_message(
                                            from_email,
                                            msg_id,
                                            metadata_headers=["Message-ID", "References", "In-Reply-To", "Date"],
                                        )
                                        headers_list = meta.get("payload", {}).get("headers", [])
                                        hdrs = {
                                            str(h.get("name", "")).lower(): (h.get("value") or "").strip()
                                            for h in headers_list
                                        }
                                        if not msg_id_hdr:
                                            msg_id_hdr = hdrs.get("message-id", "") or ""
                                    except Exception:
                                        hdrs = {}

                                if msg_id_hdr:
                                    # Canonical RFC 2822 Message-ID for all threading logic.
                                    r["orig_message_id"] = msg_id_hdr
                                    r["rfc_message_id"] = msg_id_hdr

                                if hdrs:
                                    r["orig_references"] = hdrs.get("references", "") or r.get("orig_references", "")
                                    r["orig_date"] = hdrs.get("date", "") or r.get("orig_date", "")
                            except Exception as e:
                                _write_log(
                                    job_dir,
                                    f"[{i+1}/{total}] WARNING: could not enrich OAuth send metadata for {to_addr}: {e}",
                                )
                        else:
                            smtp_send_html(from_email, app_password, from_name, to_addr, subj_now, final_html)
                            _write_log(job_dir, f"[{i+1}/{total}] SENT -> {to_addr}")
                            sent_count += 1

                        record_sent_hash(from_email, to_addr, "m1", job_id)
                        sent_hashes.add(hash_email(to_addr))

                        if M:
                            uid_val, msg_obj = None, None
                            for _ in range(5):
                                try:
                                    uid_val, msg_obj = imap_search_last_sent_to_uid(M, to_addr)
                                except Exception:
                                    uid_val, msg_obj = (None, None)
                                if msg_obj is not None:
                                    break
                                time.sleep(2)
                            if msg_obj:
                                r["orig_message_id"] = msg_obj.get("Message-ID", "") or ""
                                r["orig_references"] = msg_obj.get("References", "") or ""
                                r["orig_date"] = msg_obj.get("Date", "") or ""
                            if uid_val:
                                r["orig_imap_uid"] = str(uid_val)
                                if label_name:
                                    imap_add_label_to_uid(M, uid_val, label_name)

                        r["sent_flag"] = "sent"
                        r["status"] = "SENT"
                        r["error"] = ""
                        quota_consume(from_email, 1)

                    elif act == "draft":
                        if P.get("delivery_mode") == "gmail_api":
                            # OAuth mode: create draft via Gmail API (optionally with label).
                            try:
                                gmail_create_draft(from_email, to_addr, subj_now, final_html, label_name=label_name, from_name=from_name)
                                _write_log(job_dir, f"[{i+1}/{total}] DRAFTED (API) -> {to_addr}")
                                r["status"] = "DRAFTED"
                                r["error"] = ""
                            except Exception as e:
                                _write_log(job_dir, f"[{i+1}/{total}] ERROR draft (API) -> {to_addr} | {e}")
                                r["status"] = "ERROR"
                                r["error"] = str(e)
                        elif M:
                            mime = smtp_build_mime(from_email, from_name, to_addr, subj_now, final_html)
                            imap_append_draft(M, mime.as_bytes())
                            _write_log(job_dir, f"[{i+1}/{total}] DRAFTED -> {to_addr}")
                            r["status"] = "DRAFTED"
                            r["error"] = ""
                        else:
                            _write_log(job_dir, f"[{i+1}/{total}] ERROR draft (no IMAP) -> {to_addr}")
                            r["status"] = "ERROR"
                            r["error"] = "IMAP unavailable for Drafts"
                    else:
                        _write_log(job_dir, f"[{i+1}/{total}] SKIPPED -> {to_addr}")
                        r["status"] = "SKIPPED"
                        r["error"] = ""

                except Exception as e:
                    r["status"] = "ERROR"
                    r["error"] = str(e)
                    _write_log(job_dir, f"[{i+1}/{total}] ERROR -> {to_addr} | {e}")
                    msg_text = str(e) or ""
                    lower_msg = msg_text.lower()
                    if any(tok in lower_msg for tok in ["auth", "authentication", "535", "invalid credentials", "application-specific password"]):
                        _write_log(job_dir, "Authentication error detected; stopping job early to avoid repeated failures.")
                        pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                        _update_state(self, job_id, "m1", rows, total)
                        break

                r["batch_label"] = label_name
                r["orig_subject"] = r.get("orig_subject") or subj_now
                r["ts_utc"] = datetime.now(timezone.utc).isoformat()

                pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                _update_state(self, job_id, "m1", rows, total)

                if i < total - 1 and act == "send":
                    # Compute per-email cooldown (fixed or random) and add overhead.
                    base_delay = _compute_cooldown_for_row()
                    sleep_total = max(0.0, base_delay + float(overhead))
                    if sleep_total > 0:
                        slept = 0.0
                        while slept < sleep_total:
                            flag2 = _maybe_pause_or_stop(job_dir)
                            if flag2 == "stop":
                                _write_log(job_dir, "STOP flag detected during cooldown. Ending job.")
                                break
                            if flag2 == "pause":
                                time.sleep(1.0)
                                slept += 1.0
                                continue
                            step = min(1.0, sleep_total - slept)
                            time.sleep(step)
                            slept += step
                        if flag2 == "stop":
                            break

            _write_log(job_dir, f"Job finished. Sent={sent_count} of {total}.")
            try:
                _finalize_and_email(job_dir, rows, from_email, app_password, from_name, label_name, "Module 1", P.get("delivery_mode", "smtp"))
            except Exception as e:
                _write_log(job_dir, f"Finalize/email failed: {e}")
            return {"sent": sent_count, "total": total, "job_id": job_id}

        finally:
            release_account_lock(lock_path, log=lambda m: _write_log(job_dir, m))

    finally:
        _single_run_finish(job_dir, "m1")



@celery_app.task(bind=True)
def module2_followup_task(self, job_id: str, payload_path: str):
    """Threaded follow-up sender (reply-aware, bounce-aware, account-locked)."""
    job_dir = _ensure_job_dir(job_id)

    # Per-job single-run guard
    if not _single_run_start(job_dir, "m2"):
        return {
            "sent": 0,
            "total": 0,
            "job_id": job_id,
            "skipped_reply": 0,
            "skipped_bounce": 0,
            "status": "duplicate_invocation",
        }

    M = None
    lock_path = None
    try:
        try:
            self.update_state(state="STARTED", meta={"job_id": job_id})
        except Exception:
            pass

        with open(payload_path, "r", encoding="utf-8") as f:
            P = json.load(f)

        _write_log(job_dir, f"Starting Module 2 for job {job_id}")

        force_reply = bool(P.get("force_reply", False))

        from_email = P["from_email"]
        delivery_mode = P.get("delivery_mode", "smtp")

        app_password = decrypt_secret(P.get("app_password_enc") or P.get("app_password", ""))
        from_name = P.get("from_name") or ""
        cooldown = int(P.get("cooldown_s", 30))
        cooldown_random_enabled = bool(P.get("cooldown_random_enabled", False))
        cooldown_min_s = int(P.get("cooldown_min_s", cooldown))
        cooldown_max_s = int(P.get("cooldown_max_s", cooldown))

        def _compute_cooldown_for_row() -> float:
            """Return cooldown (seconds) for this follow-up row, applying randomness if enabled."""
            if cooldown_random_enabled:
                lo = max(0.0, float(cooldown_min_s))
                hi = max(lo, float(cooldown_max_s))
                if hi > 0:
                    return random.uniform(lo, hi)
            return float(max(0, cooldown))

        body_html_template = P.get("body_html_template") or ""

        font_key = P.get("font_family_key") or "Verdana"
        font_size_px = int(P.get("font_size_px", 13))
        para_gap_px = int(P.get("para_gap_px", 6))
        font_stack = font_stack_from_key(font_key)

        if P.get("csv_path"):
            with open(P["csv_path"], "rb") as fh:
                csv_content = fh.read()
        else:
            csv_content = bytes(P.get("csv_bytes") or b"")

        df = _load_rows_for_module2(
            csv_content,
            require_orig_message_id=(delivery_mode != "gmail_api"),
        )
        rows = df.to_dict(orient="records")
        total = len(rows)
        if total == 0:
            _write_log(job_dir, "No eligible follow-up rows; exiting.")
            return {
                "sent": 0,
                "total": 0,
                "job_id": job_id,
                "skipped_reply": 0,
                "skipped_bounce": 0,
            }

        # Account-level Gmail lock shared between Module 1 and Module 2
        schedule_info = P.get("schedule", {}) or {}
        schedule_mode = schedule_info.get("mode", "now")
        max_wait = 2 * 60 * 60 if schedule_mode == "later" else 60

        def _check_stop():
            return os.path.exists(_control_flag(job_dir, "stop"))

        ok, lock_path = acquire_account_lock(
            from_email,
            "gmail",
            log=lambda m: _write_log(job_dir, m),
            check_stop=_check_stop,
            max_wait_seconds=max_wait,
        )
        if not ok:
            _write_log(job_dir, "Account lock not acquired; another Gmail job is active. Aborting follow-up job.")
            return {
                "sent": 0,
                "total": total,
                "job_id": job_id,
                "skipped_reply": 0,
                "skipped_bounce": 0,
                "status": "account_lock_conflict",
            }

        # IMAP login for reply / bounce checks and capturing follow-up Message-IDs.
        try:
            if delivery_mode != "gmail_api":
                M = imap_login(from_email, app_password)
            else:
                M = None
        except Exception as e:
            _write_log(job_dir, f"IMAP login failed (reply/bounce checks disabled): {e}")
            M = None

        sent_count = 0
        skipped_reply = 0
        skipped_bounce = 0

        for i, r in enumerate(rows):
            # pause/stop
            while True:
                flag = _maybe_pause_or_stop(job_dir)
                if flag == "stop":
                    _write_log(job_dir, "STOP flag detected. Ending job.")
                    break
                if flag == "pause":
                    time.sleep(1.0)
                    continue
                break
            if flag == "stop":
                break

            to_addr_raw = r.get("email") or ""
            to_addr = normalize_email(to_addr_raw)
            if not to_addr or "@" not in to_addr:
                r["followup_status"] = "SKIPPED"
                r["followup_error"] = "Invalid email"
                r["followup_flag"] = "skipped_invalid"
                _write_log(job_dir, f"[{i+1}/{total}] SKIPPED invalid email -> {to_addr_raw}")
                pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                _update_state(self, job_id, "m2", rows, total)
                continue

            orig_subj = r.get("orig_subject") or ""
            if not re.match(r"(?i)^re:\s", orig_subj or ""):
                reply_subject_now = f"Re: {orig_subj}"
            else:
                reply_subject_now = orig_subj

            # Respect previous follow-ups unless force_reply is True.
            prev_flag = str(r.get("prev_followup_flag") or r.get("followup_flag") or "").lower()
            if not force_reply and prev_flag == "sent":
                _write_log(job_dir, f"[{i+1}/{total}] SKIP (already followed up in previous batch) -> {to_addr}")
                r["followup_flag"] = "skipped_previous_followup"
                r["followup_status"] = "SKIPPED"
                r["followup_error"] = ""
                pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                _update_state(self, job_id, "m2", rows, total)
                continue

            # Reply-aware skip: ALWAYS skip if the prospect has replied in this thread,
            # even when force_reply is True.
            if P.get("delivery_mode") == "gmail_api":
                has_reply = False

                # Prefer robust thread-based detection when we have a thread ID.
                thread_id = (r.get("orig_thread_id") or "").strip()
                if thread_id:
                    try:
                        has_reply = gmail_thread_has_prospect_reply(from_email, thread_id, to_addr)
                    except Exception:
                        has_reply = False

                # Fallback: Message-ID based search when threadId is missing or inconclusive.
                if not has_reply:
                    msg_ids_to_check = []
                    orig_mid = (r.get("orig_message_id") or "").strip()
                    if orig_mid:
                        msg_ids_to_check.append(orig_mid)
                    last_mid = (r.get("last_followup_message_id") or "").strip()
                    if last_mid and last_mid not in msg_ids_to_check:
                        msg_ids_to_check.append(last_mid)
                    if msg_ids_to_check:
                        try:
                            has_reply = gmail_check_reply_exists(from_email, msg_ids_to_check, to_addr)
                        except Exception:
                            has_reply = False

                if has_reply:
                    _write_log(job_dir, f"[{i+1}/{total}] SKIP (prospect already replied in thread) [API] -> {to_addr}")
                    r["followup_flag"] = "skipped_reply"
                    r["followup_status"] = "SKIPPED"
                    r["followup_error"] = ""
                    skipped_reply += 1
                    pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                    _update_state(self, job_id, "m2", rows, total)
                    continue


            # Bounce-aware skip in Gmail API mode
            if P.get("delivery_mode") == "gmail_api":
                try:
                    if gmail_check_bounce_for(from_email, to_addr):
                        _write_log(job_dir, f"[{i+1}/{total}] SKIP (bounced) [API] -> {to_addr}")
                        r["followup_flag"] = "skipped_bounce"
                        r["followup_status"] = "SKIPPED"
                        r["followup_error"] = ""
                        skipped_bounce += 1
                        pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                        _update_state(self, job_id, "m2", rows, total)
                        continue
                except Exception:
                    pass
            elif M:
                reply_detected = False
                msg_ids_to_check = []
                orig_mid = (r.get("orig_message_id") or "").strip()
                if orig_mid:
                    msg_ids_to_check.append(orig_mid)
                last_mid = (r.get("last_followup_message_id") or "").strip()
                if last_mid and last_mid not in msg_ids_to_check:
                    msg_ids_to_check.append(last_mid)

                for mid in msg_ids_to_check:
                    if not mid:
                        continue
                    try:
                        if check_reply_exists(M, mid, from_email, to_addr):
                            reply_detected = True
                            break
                    except Exception as e:
                        _write_log(
                            job_dir,
                            f"[{i+1}/{total}] WARNING: reply check failed for {to_addr} (mid={mid}): {e}",
                        )
                        break

                if reply_detected:
                    _write_log(job_dir, f"[{i+1}/{total}] SKIP (prospect already replied in thread) -> {to_addr}")
                    r["followup_flag"] = "skipped_reply"
                    r["followup_status"] = "SKIPPED"
                    r["followup_error"] = ""
                    skipped_reply += 1
                    pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                    _update_state(self, job_id, "m2", rows, total)
                    continue

                # Bounce-aware skip
                try:
                    if check_bounce_for(M, to_addr):
                        _write_log(job_dir, f"[{i+1}/{total}] SKIP (bounced) -> {to_addr}")
                        r["followup_flag"] = "skipped_bounce"
                        r["followup_status"] = "SKIPPED"
                        r["followup_error"] = ""
                        skipped_bounce += 1
                        pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                        _update_state(self, job_id, "m2", rows, total)
                        continue
                except Exception:
                    pass

                    try:
                        if check_reply_exists(M, mid, from_email, to_addr):
                            reply_detected = True
                            break
                    except Exception as e:
                        _write_log(
                            job_dir,
                            f"[{i+1}/{total}] WARNING: reply check failed for {to_addr} (mid={mid}): {e}",
                        )
                        break

                if reply_detected:
                    _write_log(job_dir, f"[{i+1}/{total}] SKIP (prospect already replied in thread) -> {to_addr}")
                    r["followup_flag"] = "skipped_reply"
                    r["followup_status"] = "SKIPPED"
                    r["followup_error"] = ""
                    skipped_reply += 1
                    pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                    _update_state(self, job_id, "m2", rows, total)
                    continue

                # Bounce-aware skip
                try:
                    if check_bounce_for(M, to_addr):
                        _write_log(job_dir, f"[{i+1}/{total}] SKIP (bounced) -> {to_addr}")
                        r["followup_flag"] = "skipped_bounce"
                        r["followup_status"] = "SKIPPED"
                        r["followup_error"] = ""
                        skipped_bounce += 1
                        pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                        _update_state(self, job_id, "m2", rows, total)
                        continue
                except Exception:
                    pass

            # Quota guard
            allowed, msg = quota_can_send(from_email, 1)
            if msg:
                _write_log(job_dir, msg)
            if not allowed:
                r["followup_status"] = "SKIPPED"
                r["followup_error"] = "Quota exceeded; job halted."
                r["followup_flag"] = "skipped_quota"
                _write_log(
                    job_dir,
                    f"[{i+1}/{total}] Stopping further follow-ups due to quota guard for {from_email}.",
                )
                break

            ctx = dict(r)
            ctx["sender_name"] = from_name
            try:
                raw_body = (body_html_template or "").format_map(SafeDict(ctx))
            except Exception:
                raw_body = body_html_template or ""
            final_html = prepare_email_html(raw_body, para_gap_px, font_stack, font_size_px)

            try:
                if P.get("delivery_mode") == "gmail_api":
                    # Gmail API follow-up; no app password needed.
                    # Prefer per-row RFC metadata from Module 1 / prior Module 2 runs,
                    # and only fall back to a Sent search if that metadata is missing.
                    thread_id = str(r.get("orig_thread_id") or "").strip()
                    # Prefer the most recent follow-up's RFC Message-ID, then the original.
                    parent_mid = str(r.get("last_followup_message_id") or "").strip()
                    if not parent_mid:
                        parent_mid = str(r.get("rfc_message_id") or r.get("orig_message_id") or "").strip()

                    # Fallback: ask Gmail for the last sent message to this recipient.
                    if not thread_id or not parent_mid:
                        try:
                            thread_info = gmail_find_last_sent_to(from_email, to_addr)
                        except Exception as e_find:
                            thread_info = None
                            _write_log(
                                job_dir,
                                f"[{i+1}/{total}] WARNING: gmail_find_last_sent_to failed for {to_addr}: {e_find}",
                            )
                        if thread_info:
                            t_id, p_mid = thread_info
                            if not thread_id:
                                thread_id = t_id
                            if not parent_mid:
                                parent_mid = p_mid

                    if thread_id and parent_mid:
                        gmail_reply_html(
                            from_email,
                            to_addr,
                            reply_subject_now,
                            final_html,
                            thread_id=thread_id,
                            parent_message_id=parent_mid,
                            from_name=from_name,
                            references=parent_mid,
                        )
                    else:
                        # Absolute fallback: send as a fresh message (new thread)
                        gmail_send_html(from_email, to_addr, reply_subject_now, final_html, from_name=from_name)
                else:
                    smtp_send_html(from_email, app_password, from_name, to_addr, reply_subject_now, final_html)
                _write_log(job_dir, f"[{i+1}/{total}] FOLLOWED UP -> {to_addr}")
                r["followup_flag"] = "sent"
                r["followup_status"] = "FOLLOWED_UP"
                r["followup_error"] = ""
                r["followup_ts_utc"] = datetime.now(timezone.utc).isoformat()
                sent_count += 1
                quota_consume(from_email, 1)

                # Capture the most recent follow-up Message-ID so that future
                # follow-up waves can be reply-aware even if the prospect replies
                # to a later follow-up instead of the original outreach.
                if M:
                    uid_val, msg_obj = None, None
                    for _ in range(5):
                        try:
                            uid_val, msg_obj = imap_search_last_sent_to_uid(M, to_addr)
                        except Exception:
                            uid_val, msg_obj = (None, None)
                        if msg_obj is not None:
                            break
                        time.sleep(2)
                    if msg_obj:
                        r["last_followup_message_id"] = msg_obj.get("Message-ID", "") or ""
                        r["last_followup_references"] = msg_obj.get("References", "") or ""
                        r["last_followup_date"] = msg_obj.get("Date", "") or ""

            except Exception as e:
                r["followup_flag"] = "not_sent"
                r["followup_status"] = "ERROR"
                r["followup_error"] = str(e)
                _write_log(job_dir, f"[{i+1}/{total}] ERROR -> {to_addr} | {e}")
                msg_text = str(e) or ""
                lower_msg = msg_text.lower()
                if any(
                    tok in lower_msg
                    for tok in [
                        "auth",
                        "authentication",
                        "535",
                        "invalid credentials",
                        "application-specific password",
                    ]
                ):
                    _write_log(
                        job_dir,
                        "Authentication error detected during follow-ups; stopping job early to avoid repeated failures.",
                    )
                    pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
                    _update_state(self, job_id, "m2", rows, total)
                    break

            pd.DataFrame(rows).to_csv(os.path.join(job_dir, "result.csv"), index=False)
            _update_state(self, job_id, "m2", rows, total)

            if i < total - 1:
                sleep_total = _compute_cooldown_for_row()
                if sleep_total > 0:
                    slept = 0.0
                    while slept < sleep_total:
                        flag2 = _maybe_pause_or_stop(job_dir)
                        if flag2 == "stop":
                            _write_log(job_dir, "STOP flag detected during cooldown. Ending job.")
                            break
                        if flag2 == "pause":
                            time.sleep(1.0)
                            slept += 1.0
                            continue
                        step = min(1.0, sleep_total - slept)
                        time.sleep(step)
                        slept += step
                    if flag2 == "stop":
                        break

        _write_log(
            job_dir,
            f"Job finished. FollowedUp={sent_count} / total={total}. "
            f"Skipped(replied)={skipped_reply}, Skipped(bounced)={skipped_bounce}",
        )
        try:
            _finalize_and_email(job_dir, rows, from_email, app_password, from_name, "", "Module 2", P.get("delivery_mode", "smtp"))
        except Exception as e:
            _write_log(job_dir, f"Finalize/email failed: {e}")
        return {
            "sent": sent_count,
            "total": total,
            "skipped_reply": skipped_reply,
            "skipped_bounce": skipped_bounce,
            "job_id": job_id,
        }

    finally:
        if M:
            try:
                M.logout()
            except Exception:
                pass
        release_account_lock(lock_path, log=lambda m: _write_log(job_dir, m))
        _single_run_finish(job_dir, "m2")
