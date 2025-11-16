#!/usr/bin/env python3
"""Streamlit frontend - CORRECTED VERSION with proper imports"""

import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_quill import st_quill

from app.celery_app import celery_app
from app.tasks import module1_send_task, module2_followup_task
from app.email_styles import prepare_email_html, font_stack_from_key, SafeDict
from app.auth import get_auth_mode, verify, verify_gmail_credentials, get_admin_users, update_admin_credentials
from app.gmail_api_utils import has_gmail_oauth_config, build_auth_url, exchange_code_for_tokens

from app.security import encrypt_secret

DATA_DIR = os.getenv("DATA_DIR", "/data")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(JOBS_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)


SENDER_PREFS_FILE = os.path.join(DATA_DIR, "sender_names.json")


def _load_sender_prefs() -> dict:
    try:
        with open(SENDER_PREFS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_sender_pref(user: str, sender_name: str) -> None:
    if not user:
        return
    prefs = _load_sender_prefs()
    prefs[str(user)] = sender_name
    os.makedirs(os.path.dirname(SENDER_PREFS_FILE), exist_ok=True)
    tmp = SENDER_PREFS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2)
    os.replace(tmp, SENDER_PREFS_FILE)


st.set_page_config(page_title="Bulk Outreach Scheduler", layout="wide")


# ---------- Tiny helpers ----------

def render_preview_html(body_html_raw: str, para_gap_px: int, font_key: str, font_px: int) -> str:
    """Use the EXACT same function as email sending"""
    stack = font_stack_from_key(font_key)
    return prepare_email_html(body_html_raw or "", int(para_gap_px), stack, int(font_px))


def _first_nonempty(lower_map, keys):
    for k in keys:
        if k in lower_map and str(lower_map[k]).strip():
            return str(lower_map[k]).strip()
    return ""


def normalize_for_template(row_dict, sender_name_val: str = ""):
    """Normalize CSV row into flexible context for templates."""
    lower = {}
    for k, v in row_dict.items():
        key = re.sub(r"[\s_\-]+", " ", str(k).strip().lower())
        lower[key] = "" if v is None else str(v)

    out = {}
    out["first"] = _first_nonempty(
        lower,
        ["first", "first name", "firstname", "given name", "fname"],
    )
    out["last"] = _first_nonempty(
        lower,
        ["last", "last name", "lastname", "surname", "lname"],
    )
    out["company"] = _first_nonempty(
        lower,
        ["company", "company name", "companyname", "organization", "organisation", "org", "business"],
    )
    out["email"] = _first_nonempty(
        lower,
        ["email", "email address", "e-mail", "mail"],
    )
    out["title"] = _first_nonempty(
        lower,
        ["title", "job title", "designation", "role", "position"],
    )

    out["first name"] = out["first"]
    out["last name"] = out["last"]
    out["company name"] = out["company"]
    out["sender_name"] = sender_name_val or ""

    return out


def save_upload_to_disk(uploaded_file):
    if not uploaded_file:
        return None
    content = uploaded_file.getvalue()
    fname = f"{uuid.uuid4().hex}_{uploaded_file.name}"
    fpath = os.path.join(UPLOADS_DIR, fname)
    with open(fpath, "wb") as f:
        f.write(content)
    return fpath


def create_job_payload(job_kind: str, params: dict, csv_file, current_user: str):
    """Persist job payload; return (job_id, job_dir, payload_path)."""
    safe_user = re.sub(r"[^a-zA-Z0-9_.-]", "_", current_user or "anon")
    job_id = f"{safe_user}__{job_kind}-{uuid.uuid4().hex[:8]}"
    job_dir = os.path.join(JOBS_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)

    csv_path = save_upload_to_disk(csv_file) if csv_file else None

    if not csv_path and params.get("csv_text"):
        csv_path = os.path.join(job_dir, "input.csv")
        with open(csv_path, "w", encoding="utf-8") as fh:
            fh.write(params["csv_text"])

    payload = {
        **params,
        "csv_path": csv_path,
        "csv_bytes": None,
        "created_at": datetime.now().isoformat(),
        "job_id": job_id,
        "job_kind": job_kind,
        "user": current_user,
    }

    payload_path = os.path.join(job_dir, "payload.json")
    with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return job_id, job_dir, payload_path


def is_admin(user: str) -> bool:
    """Return True if user is configured as an admin."""
    admins = get_admin_users()
    return user in admins


def list_jobs(current_user: str):
    """List job IDs visible to the given user."""
    if not os.path.exists(JOBS_DIR):
        return []

    if is_admin(current_user):
        items = []
        for name in os.listdir(JOBS_DIR):
            jdir = os.path.join(JOBS_DIR, name)
            if os.path.isdir(jdir) and os.path.exists(os.path.join(jdir, "payload.json")):
                items.append(name)
        return sorted(items, reverse=True)

    safe_user = re.sub(r"[^a-zA-Z0-9_.-]", "_", current_user or "anon") + "__"
    items = []
    for name in os.listdir(JOBS_DIR):
        if not name.startswith(safe_user):
            continue
        jdir = os.path.join(JOBS_DIR, name)
        if os.path.isdir(jdir) and os.path.exists(os.path.join(jdir, "payload.json")):
            items.append(name)
    return sorted(items, reverse=True)


def load_payload(job_id: str) -> dict:
    p = os.path.join(JOBS_DIR, job_id, "payload.json")
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def read_log(job_id: str) -> str:
    path = os.path.join(JOBS_DIR, job_id, "log.txt")
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_result_df(job_id: str):
    path = os.path.join(JOBS_DIR, job_id, "result.csv")
    if not os.path.exists(path):
        return None
    try:
        return pd.read_csv(path, dtype=str)
    except Exception:
        return None


def control_flag(job_id: str, name: str, set_on: bool = True) -> None:
    f = os.path.join(JOBS_DIR, job_id, f"{name}.flag")
    if set_on:
        open(f, "a").close()
    else:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass


def to_utc_from_local(date_val, time_val):
    """Treat the chosen date/time as server-local time and convert to UTC."""
    local_tz = datetime.now().astimezone().tzinfo
    naive = datetime.combine(date_val, time_val)
    aware_local = naive.replace(tzinfo=local_tz)
    return aware_local.astimezone(timezone.utc)


# ---------- Theme CSS ----------
st.markdown(
    """
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.stTabs [data-baseweb="tab-list"] button { font-size: 16px; }
</style>
""",
    unsafe_allow_html=True,
)

# ---------- Authentication ----------



auth_mode = get_auth_mode()
current_user = "default"

if auth_mode != "none":
    if "auth_user" not in st.session_state:
        st.sidebar.header("Login")

        admins = get_admin_users()

        # Build login options
        login_options = []
        if has_gmail_oauth_config():
            login_options.append("Google OAuth")
        login_options.extend(["Gmail user", "Admin"])

        login_as = st.sidebar.radio(
            "Login as",
            login_options,
            index=0,
            key="auth_login_mode",
        )

        if login_as == "Admin":
            u = st.sidebar.text_input("Admin username", key="auth_admin_username")
            p = st.sidebar.text_input("Admin password", key="auth_admin_password", type="password")
            if st.sidebar.button("Sign in", key="auth_admin_login_btn"):
                if u and p and verify(u, p) and u in admins:
                    st.session_state["auth_user"] = u
                    st.session_state["login_mode"] = "admin"
                    st.rerun()
                else:
                    st.sidebar.error("Invalid admin credentials.")
                st.stop()

        elif login_as == "Gmail user":
            gmail = st.sidebar.text_input("Gmail address", key="auth_gmail_username")
            app_pwd = st.sidebar.text_input("Gmail App Password", key="auth_gmail_app_pwd", type="password")
            if st.sidebar.button("Sign in", key="auth_gmail_login_btn"):
                if verify_gmail_credentials(gmail, app_pwd):
                    st.session_state["auth_user"] = gmail
                    st.session_state["login_mode"] = "gmail"
                    st.session_state["gmail_from_email"] = gmail
                    from app.security import encrypt_secret as _enc
                    st.session_state["gmail_app_password_enc"] = _enc(app_pwd)
                    st.rerun()
                else:
                    st.sidebar.error("Could not log in to Gmail. Please check your email/app password.")
                st.stop()

        else:  # Google OAuth
            # If we already have an OAuth user, reuse it
            if "oauth_email" in st.session_state:
                st.session_state["auth_user"] = st.session_state["oauth_email"]
                st.session_state["login_mode"] = "oauth"
                st.rerun()

            # Read query params for OAuth code
            try:
                params = st.query_params
            except Exception:
                params = st.experimental_get_query_params()
            code = params.get("code")
            if isinstance(code, list):
                code = code[0] if code else None

            if code:
                info = exchange_code_for_tokens(code)
                if info and info.get("email"):
                    email = info["email"]
                    st.session_state["oauth_email"] = email
                    st.session_state["auth_user"] = email
                    st.session_state["login_mode"] = "oauth"
                    st.rerun()
                else:
                    st.sidebar.error("Google OAuth login failed. Please try again.")
            else:
                import uuid as _uuid
                state_val = _uuid.uuid4().hex
                auth_url = build_auth_url(state_val)
                st.sidebar.markdown(
                    f'<a href="{auth_url}" target="_self" style="text-decoration:none;">'
                    '🔑 Sign in with Google</a>',
                    unsafe_allow_html=True,
                )
                st.sidebar.caption("After signing in, you will be redirected back here automatically.")

        # Footer
        st.sidebar.markdown("---")
        st.sidebar.markdown("**Created by:** Hridhi Nandu P P")
        st.sidebar.caption("Bulk outreach with SMTP + Gmail API dual delivery.")
        st.sidebar.markdown("[📘 Documentation](<https://www.notion.so/Bulk-Outreach-Email-Application-2ad81f2b2f7c80ab8194d91ff140eaa3?source=copy_link>)")

        st.stop()
    else:
        current_user = st.session_state["auth_user"]

    login_mode = st.session_state.get(
        "login_mode",
        "admin" if current_user in get_admin_users() else "gmail",
    )
    st.sidebar.markdown(f"**User:** `{current_user}` ({login_mode})")
else:
    current_user = os.getenv("DEFAULT_USER", "default")
    st.sidebar.info(f"Auth disabled. Using user: `{current_user}`")

# ---------- Sidebar: credentials & style ----------


st.sidebar.header("Gmail & Style")

login_mode = st.session_state.get("login_mode", "admin" if is_admin(current_user) else "gmail")

if login_mode == "oauth":
    # OAuth users: use their Google account email, no app password required
    from_email = st.session_state.get("oauth_email", current_user)
    st.sidebar.text_input("Gmail address (FROM)", value=from_email, disabled=True)
    app_password = None
elif is_admin(current_user):
    # Admin can freely choose Gmail account and app password per job (SMTP mode)
    from_email = st.sidebar.text_input("Gmail address (FROM)", value="")
    app_password = st.sidebar.text_input("Gmail App Password", type="password", value="")
else:
    # Gmail users must use the Gmail/App password they logged in with (SMTP mode)
    from_email = st.session_state.get("gmail_from_email", "")
    st.sidebar.text_input("Gmail address (FROM)", value=from_email, disabled=True)
    app_password = None  # we reuse the encrypted value from login

sender_prefs = _load_sender_prefs()
default_sender = sender_prefs.get(current_user, "")
sender_name = st.sidebar.text_input("Sender Display Name", value=default_sender)
remember_sender = st.sidebar.checkbox(
    "Remember this sender name for this account",
    value=bool(default_sender),
)

cooldown_s = st.sidebar.number_input(
    "Cooldown between sends (s)",
    min_value=0,
    max_value=600,
    value=30,
    step=1,
)

font_key = st.sidebar.selectbox(
    "Email font family",
    ["Verdana", "Arial", "Tahoma", "Helvetica", "Times New Roman", "Georgia", "Courier New"],
)

font_px = st.sidebar.number_input(
    "Email font size (px)",
    min_value=10,
    max_value=24,
    value=13,
    step=1,
)

para_gap_px = st.sidebar.number_input(
    "Default paragraph gap (px)",
    min_value=0,
    max_value=24,
    value=4,
    step=1,
)



# ---------- Admin settings (optional) ----------

if is_admin(current_user) and auth_mode != "none":
    st.sidebar.markdown("---")
    st.sidebar.subheader("Admin account settings")

    new_admin_user = st.sidebar.text_input(
        "New admin username",
        value=current_user,
        key="admin_settings_new_username",
    )
    new_admin_pass = st.sidebar.text_input(
        "New admin password",
        type="password",
        key="admin_settings_new_password",
    )
    if st.sidebar.button("Update admin credentials", key="admin_settings_update_btn"):
        if not new_admin_user or not new_admin_pass:
            st.sidebar.error("Please provide both a username and a password.")
        else:
            try:
                update_admin_credentials(current_user, new_admin_user, new_admin_pass)
                st.sidebar.success("Admin credentials updated. Please sign in again.")
                if "auth_user" in st.session_state:
                    del st.session_state["auth_user"]
                st.stop()
            except Exception as e:
                st.sidebar.error(f"Failed to update admin credentials: {e}")

tab1, tab2, tab3 = st.tabs(
    ["Module 1 — Outreach", "Module 2 — Follow-ups", "Jobs Monitor"]
)

# ---------- Module 1 UI ----------

with tab1:
    st.subheader("Module 1 — Initial Outreach")

    left, right = st.columns([1, 1])
    with left:
        label_name = st.text_input("Gmail Label for this batch", value="Campaign-Label-1")
        subject_template = st.text_area(
            "Subject Template",
            value="Hi {first} — quick note about {company}",
            height=80,
        )

    with right:
        st.write("Body (Quill editor)")
        html_body = st_quill(
            key="m1_quill",
            value="<p>Your email body goes here</p>",
            html=True,
            placeholder="Write your email here...",
        )

    selection_mode = st.selectbox(
        "Row selection mode",
        ["send_all", "send_selected", "draft_all", "draft_selected_only", "draft_selected_and_send_rest"],
    )


    force_send_duplicates = st.checkbox(
        "Force send to already-contacted emails",
        value=True,
    )

    csv_file = st.file_uploader("Upload contacts CSV", type=["csv"], key="m1_csv")

    selected_indices = []
    edited = None

    if csv_file:
        df = pd.read_csv(csv_file, dtype=str, encoding="utf-8", sep=None, engine="python")
        st.write("### Preview & Select rows")

        if "__selected__" not in df.columns:
            df.insert(0, "__selected__", False)

        sel_col = st.column_config.CheckboxColumn("Select", default=False)
        edited = st.data_editor(
            df,
            use_container_width=True,
            num_rows="dynamic",
            column_config={"__selected__": sel_col},
            hide_index=True,
            key="m1_editor",
        )

        selected_indices = edited.index[edited["__selected__"]].tolist()

    # Preview
    st.markdown("### Email Preview")

    if csv_file and edited is not None and len(edited) > 0:
        choices = list(edited.index.astype(str))
        sel = st.selectbox("Pick a row for preview", choices, index=0, key="m1_preview_row")

        try:
            sel_idx = int(sel)
        except Exception:
            sel_idx = edited.index[0]

        row = edited.loc[sel_idx].fillna("")
        ctx = normalize_for_template(row.to_dict(), sender_name)

        # RENDER PREVIEW WITH EXACT SAME FUNCTION
        try:
            subj_preview = (subject_template or "").format_map(SafeDict(ctx))
        except Exception as e:
            subj_preview = subject_template or ""
            st.warning(f"Subject template formatting issue: {e}")
        html_preview = render_preview_html(html_body or "", para_gap_px, font_key, font_px)
        try:
            html_preview = html_preview.format_map(SafeDict(ctx))
        except Exception as e:
            st.warning(f"Body template formatting issue: {e}")

        with st.expander("🔍 Debug: Column mapping", expanded=False):
            st.json(ctx)

    else:
        st.info("Upload a CSV to preview with real data.")
        sample = {
            "first": "Ada",
            "last": "Lovelace",
            "title": "CTO",
            "company": "Analytical Engines",
            "email": "ada@example.com",
            "sender_name": sender_name or "",
        }
        try:
            subj_preview = (subject_template or "").format_map(SafeDict(sample))
        except Exception as e:
            subj_preview = subject_template or ""
            st.warning(f"Subject template formatting issue: {e}")
        html_preview = render_preview_html(html_body or "", para_gap_px, font_key, font_px)
        try:
            html_preview = html_preview.format_map(SafeDict(sample))
        except Exception as e:
            st.warning(f"Body template formatting issue: {e}")

    st.write("**Subject**:", subj_preview or "(no subject)")

    # DISPLAY PREVIEW AS HTML
    st.markdown("**Email Preview:**")
    st.markdown(
        f"""
<div style="
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 20px;
    background-color: #ffffff;
    color: #000000;
    max-height: 600px;
    overflow-y: auto;
    font-family: Verdana, sans-serif;
">
{html_preview}
</div>
""",
        unsafe_allow_html=True,
    )

    # Scheduling
    st.markdown("---")
    st.subheader("⏰ Schedule")

    sched_left, sched_mid, sched_right = st.columns(3)
    with sched_left:
        when = st.selectbox("When?", ["now", "later"], key="m1_when")
    with sched_mid:
        eta_date = st.date_input("Run on date", key="m1_eta_date")
    with sched_right:
        eta_time = st.time_input("At time", key="m1_eta_time")


    if st.button("🚀 Schedule Module 1 Job", key="m1_submit", type="primary"):
        # Determine credentials based on login mode
        if login_mode == "oauth":
            delivery_mode = "gmail_api"
            has_creds = bool(from_email)
            encrypted_pwd = ""
        elif is_admin(current_user):
            delivery_mode = "smtp"
            has_creds = bool(from_email and app_password)
            encrypted_pwd = encrypt_secret(app_password) if app_password else ""
        else:
            delivery_mode = "smtp"
            enc = st.session_state.get("gmail_app_password_enc", "")
            has_creds = bool(from_email and enc)
            encrypted_pwd = enc

        if not has_creds or not csv_file or not html_body or not subject_template:

            st.error("Please fill in all required fields")
        else:
            # Optionally remember sender name for this account
            if sender_name and remember_sender:
                _save_sender_pref(current_user, sender_name)

            # Decide the *actual* schedule (Option 1 behavior)
            now_local = datetime.now()
            local_tz = now_local.astimezone().tzinfo
            target_naive = datetime.combine(eta_date, eta_time)
            future_delta_sec = (target_naive - now_local).total_seconds()

            if when == "now":
                # If user picked a clearly future time but left "now" selected,
                # treat it as a scheduled job for that future time.
                if future_delta_sec > 120:
                    schedule_mode = "later"
                    eta_utc = to_utc_from_local(eta_date, eta_time)
                    schedule_dt_local = target_naive.replace(tzinfo=local_tz)
                    detected_future = True
                else:
                    schedule_mode = "now"
                    eta_utc = None
                    schedule_dt_local = now_local.astimezone(local_tz)
                    detected_future = False
            else:
                schedule_mode = "later"
                eta_utc = to_utc_from_local(eta_date, eta_time)
                schedule_dt_local = target_naive.replace(tzinfo=local_tz)
                detected_future = False

            schedule_info = {
                "mode": schedule_mode,
                "date": schedule_dt_local.date().isoformat(),
                "time": schedule_dt_local.strftime("%H:%M"),
                "timezone": str(local_tz),
            }

            csv_path = save_upload_to_disk(csv_file)
            job_id, job_dir, payload_path = create_job_payload(
                "m1",
                {
                    "from_email": from_email,
            "delivery_mode": delivery_mode,
                    "app_password_enc": encrypted_pwd,
                    "from_name": sender_name,
                    "label_name": label_name,
                    "subject_template": subject_template,
                    "body_html_template": html_body,
                    "font_family_key": font_key,
                    "font_size_px": font_px,
                    "para_gap_px": para_gap_px,
                    "selection_mode": selection_mode,
                    "force_send_duplicates": force_send_duplicates,
                    "selected_indices": selected_indices,
                    "cooldown_s": cooldown_s,
                    "schedule": schedule_info,
                },
                csv_file,
                current_user,
            )

            # Dispatch Celery task based on resolved schedule
            if schedule_mode == "now":
                module1_send_task.delay(job_id, payload_path)
                st.success(f"✓ Job {job_id} scheduled immediately!")
            else:
                module1_send_task.apply_async(args=(job_id, payload_path), eta=eta_utc)
                if detected_future and when == "now":
                    st.success(f"✓ Detected future time; job {job_id} scheduled for {eta_date} {eta_time}")
                else:
                    st.success(f"✓ Job {job_id} scheduled for {eta_date} {eta_time}")

            st.info("Check Jobs Monitor to track progress")


# ---------- Module 2 UI ----------

with tab2:
    st.subheader("Module 2 — Follow-up Replies")

    html_body2 = st_quill(
        key="m2_quill",
        value="<p>Your follow-up email goes here</p>",
        html=True,
        placeholder="Write your follow-up here...",
    )

    force_reply = st.checkbox(
        "Force follow-up even if a previous follow-up/reply exists",
        value=True,
        help=(
            "When off, Module 2 will skip rows that already have a follow-up sent "
            "or where the prospect has replied. When on, it will ignore your previous "
            "follow-ups (so you can send reminders) but will still skip any thread "
            "where the prospect has replied."
        ),
    )

    csv_file2 = st.file_uploader(
        "Upload Module 1 result CSV",
        type=["csv"],
        key="m2_csv",
    )

    st.markdown("### Email Preview (Follow-up)")

    if csv_file2:
        try:
            df2 = pd.read_csv(csv_file2, dtype=str, encoding="utf-8", sep=None, engine="python")
        except Exception:
            df2 = None

        if df2 is not None and len(df2) > 0:
            choices2 = list(df2.index.astype(str))
            sel2 = st.selectbox("Pick a row for preview", choices2, index=0, key="m2_preview_row")

            try:
                sel2_idx = int(sel2)
            except Exception:
                sel2_idx = df2.index[0]

            row2 = df2.loc[sel2_idx].fillna("")
            ctx2 = normalize_for_template(row2.to_dict(), sender_name)

            subj2_preview = (ctx2.get("orig_subject") or ctx2.get("orig subject") or row2.get("orig_subject", ""))
            if subj2_preview and not re.match(r"(?i)^re:\s", subj2_preview):
                subj2_preview = f"Re: {subj2_preview}"

            html2_preview = render_preview_html(html_body2 or "", para_gap_px, font_key, font_px)
            try:
                html2_preview = html2_preview.format_map(SafeDict(ctx2))
            except Exception as e:
                st.warning(f"Follow-up body template formatting issue: {e}")

            with st.expander("🔍 Debug: Column mapping", expanded=False):
                st.json(ctx2)

        else:
            st.info("Uploaded CSV has no rows to preview.")
            subj2_preview = ""
            html2_preview = ""
    else:
        st.info("Upload the Module 1 CSV export to preview.")
        sample2 = {
            "first": "Ada",
            "last": "Lovelace",
            "title": "CTO",
            "company": "Analytical Engines",
            "email": "ada@example.com",
            "sender_name": sender_name or "",
            "orig_subject": "Initial intro",
        }
        subj2_preview = f"Re: {sample2['orig_subject']}"
        html2_preview = render_preview_html(html_body2 or "", para_gap_px, font_key, font_px)
        try:
            html2_preview = html2_preview.format_map(SafeDict(sample2))
        except Exception as e:
            st.warning(f"Follow-up body template formatting issue: {e}")

    st.write("**Subject**:", subj2_preview or "(no subject)")

    st.markdown("**Email Preview:**")
    st.markdown(
        f"""
<div style="
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 20px;
    background-color: #ffffff;
    color: #000000;
    max-height: 600px;
    overflow-y: auto;
    font-family: Verdana, sans-serif;
">
{html2_preview}
</div>
""",
        unsafe_allow_html=True,
    )

    # Scheduling
    st.markdown("---")
    st.subheader("⏰ Schedule")

    sched_left, sched_mid, sched_right = st.columns(3)
    with sched_left:
        when2 = st.selectbox("When?", ["now", "later"], key="m2_when")
    with sched_mid:
        eta_date2 = st.date_input("Run on date", key="m2_eta_date")
    with sched_right:
        eta_time2 = st.time_input("At time", key="m2_eta_time")


    if st.button("🚀 Schedule Module 2 Job", key="m2_submit", type="primary"):
        # Determine credentials based on login mode
        if login_mode == "oauth":
            delivery_mode = "gmail_api"
            has_creds = bool(from_email)
            encrypted_pwd = ""
        elif is_admin(current_user):
            delivery_mode = "smtp"
            has_creds = bool(from_email and app_password)
            encrypted_pwd = encrypt_secret(app_password) if app_password else ""
        else:
            delivery_mode = "smtp"
            enc = st.session_state.get("gmail_app_password_enc", "")
            has_creds = bool(from_email and enc)
            encrypted_pwd = enc

        if not has_creds or not csv_file2 or not html_body2:

            st.error("Please fill in all required fields")
        else:
            # Optionally remember sender name for this account
            if sender_name and remember_sender:
                _save_sender_pref(current_user, sender_name)

            # Decide the *actual* schedule (Option 1 behavior)
            now_local = datetime.now()
            local_tz = now_local.astimezone().tzinfo
            target_naive = datetime.combine(eta_date2, eta_time2)
            future_delta_sec = (target_naive - now_local).total_seconds()

            if when2 == "now":
                if future_delta_sec > 120:
                    schedule_mode = "later"
                    eta_utc = to_utc_from_local(eta_date2, eta_time2)
                    schedule_dt_local = target_naive.replace(tzinfo=local_tz)
                    detected_future = True
                else:
                    schedule_mode = "now"
                    eta_utc = None
                    schedule_dt_local = now_local.astimezone(local_tz)
                    detected_future = False
            else:
                schedule_mode = "later"
                eta_utc = to_utc_from_local(eta_date2, eta_time2)
                schedule_dt_local = target_naive.replace(tzinfo=local_tz)
                detected_future = False

            schedule_info = {
                "mode": schedule_mode,
                "date": schedule_dt_local.date().isoformat(),
                "time": schedule_dt_local.strftime("%H:%M"),
                "timezone": str(local_tz),
            }

            csv_path = save_upload_to_disk(csv_file2)
            job_id, job_dir, payload_path = create_job_payload(
                "m2",
                {
                    "from_email": from_email,
            "delivery_mode": delivery_mode,
                    "app_password_enc": encrypted_pwd,
                    "from_name": sender_name,
                    "body_html_template": html_body2,
                    "font_family_key": font_key,
                    "font_size_px": font_px,
                    "para_gap_px": para_gap_px,
                    "cooldown_s": cooldown_s,
                    "force_reply": force_reply,
                    "schedule": schedule_info,
                },
                csv_file2,
                current_user,
            )

            # Dispatch Celery task based on resolved schedule
            if schedule_mode == "now":
                module2_followup_task.delay(job_id, payload_path)
                st.success(f"✓ Job {job_id} scheduled immediately!")
            else:
                module2_followup_task.apply_async(args=(job_id, payload_path), eta=eta_utc)
                if detected_future and when2 == "now":
                    st.success(f"✓ Detected future time; job {job_id} scheduled for {eta_date2} {eta_time2}")
                else:
                    st.success(f"✓ Job {job_id} scheduled for {eta_date2} {eta_time2}")

            st.info("Check Jobs Monitor to track progress")


# ---------- Module 3: Jobs Monitor ----------

with tab3:
    st.subheader("Jobs Monitor — Status & Control")

    st.markdown("---")

    refresh_interval = st.number_input(
        "Auto-refresh every N seconds (0 = off)",
        min_value=0,
        max_value=60,
        value=2,
        step=1,
    )

    if refresh_interval > 0:
        st_autorefresh(interval=refresh_interval * 1000, key="refresh_jobs")

    if st.button("🔄 Refresh Now", key="refresh_btn"):
        st.rerun()

    jobs = list_jobs(current_user)

    if not jobs:
        st.info("No jobs yet.")
    else:
        # Build metadata for sorting and filtering
        job_records = []
        for job_id in jobs:
            payload = load_payload(job_id) or {}
            created_raw = payload.get("created_at", "")
            try:
                created_at = datetime.fromisoformat(created_raw)
            except Exception:
                created_at = None

            # Derive label, preferring payload label_name; fall back to batch_label in result CSV (Module 2)
            label_name = payload.get("label_name", "") or ""
            if not label_name:
                df_tmp = read_result_df(job_id)
                if df_tmp is not None and "batch_label" in df_tmp.columns:
                    non_empty = df_tmp["batch_label"].astype(str)
                    non_empty = non_empty[non_empty.str.strip() != ""]
                    if not non_empty.empty:
                        label_name = non_empty.iloc[0]

            job_records.append({
                "job_id": job_id,
                "payload": payload,
                "created_at": created_at,
                "user": payload.get("user", "?"),
                "label": label_name,
                "kind": payload.get("job_kind", "?"),
            })

        # Admin filters
        if is_admin(current_user):
            users = sorted({rec["user"] for rec in job_records})
            user_filter = st.selectbox("Filter by user", ["(all)"] + users, index=0)
        else:
            user_filter = "(all)"

        labels = sorted({(rec["label"] or "NoLabel") for rec in job_records})
        label_filter = st.selectbox("Filter by label", ["(all)"] + labels, index=0)

        # Apply filters
        filtered = []
        for rec in job_records:
            if user_filter != "(all)" and rec["user"] != user_filter:
                continue
            label_name = rec["label"] or "NoLabel"
            if label_filter != "(all)" and label_name != label_filter:
                continue
            filtered.append(rec)

        # Sort by created_at desc, fallback to job_id desc
        filtered.sort(key=lambda r: (r["created_at"] or datetime.min, r["job_id"]), reverse=True)

        for rec in filtered:
            job_id = rec["job_id"]
            payload = rec["payload"]
            label_name = rec["label"] or "NoLabel"
            kind = rec["kind"]

            log = read_log(job_id)
            pause_f = os.path.exists(os.path.join(JOBS_DIR, job_id, "pause.flag"))
            stop_f = os.path.exists(os.path.join(JOBS_DIR, job_id, "stop.flag"))

            # Started / done flags for this module
            started_flag = os.path.join(JOBS_DIR, job_id, f"{kind}_started.flag")
            done_flag = os.path.join(JOBS_DIR, job_id, f"{kind}_done.flag")

            # Load results once for status + display
            result_df = read_result_df(job_id)

            # For Module 2, if label is missing or 'NoLabel', try to derive it from batch_label column
            if kind == "m2" and (not label_name or label_name == "NoLabel") and result_df is not None and "batch_label" in result_df.columns:
                non_empty_bl = result_df["batch_label"].astype(str)
                non_empty_bl = non_empty_bl[non_empty_bl.str.strip() != ""]
                if not non_empty_bl.empty:
                    label_name = non_empty_bl.iloc[0]

            # Initialize progress tracking
            progress_value = None
            progress_text = ""
            if result_df is not None and len(result_df) > 0:
                total_rows = len(result_df)
                processed_mask = None

                if kind == "m1" and "status" in result_df.columns:
                    status_series = result_df["status"].astype(str).str.upper()
                    processed_mask = status_series.isin(["SENT", "DRAFTED", "SKIPPED", "ERROR"])
                elif kind == "m2":
                    cols = set(result_df.columns)
                    processed_mask = pd.Series(False, index=result_df.index)
                    if "followup_flag" in cols:
                        ff = result_df["followup_flag"].astype(str).str.lower()
                        processed_mask |= ff.eq("sent") | ff.str.startswith("skipped")
                    if "followup_status" in cols:
                        fs = result_df["followup_status"].astype(str).str.upper()
                        processed_mask |= fs.isin(["FOLLOWED_UP", "ERROR", "SKIPPED"])

                if processed_mask is not None:
                    processed_count = int(processed_mask.sum())
                    if total_rows > 0:
                        progress_value = processed_count / total_rows
                        progress_text = f"{processed_count} / {total_rows}"

            # Derive high-level status
            status_label = "PENDING"
            if os.path.exists(done_flag):
                sent = drafted = skipped = errors = 0
                if result_df is not None and len(result_df) > 0:
                    cols = set(result_df.columns)
                    # Module 1 uses generic 'status' column
                    if "status" in cols:
                        status_series = result_df["status"].astype(str).str.upper()
                        sent = int((status_series == "SENT").sum())
                        drafted = int((status_series == "DRAFTED").sum())
                        skipped = int((status_series == "SKIPPED").sum())
                        errors = int((status_series == "ERROR").sum())
                    else:
                        # Module 2 follow-up columns
                        if "followup_flag" in cols:
                            ff = result_df["followup_flag"].astype(str).str.lower()
                            sent = int((ff == "sent").sum())
                            skipped = int(ff.str.startswith("skipped").sum())
                        if "followup_status" in cols:
                            fs = result_df["followup_status"].astype(str).str.upper()
                            errors = int((fs == "ERROR").sum())

                if errors and not (sent or drafted):
                    status_label = "FAILED"
                elif errors:
                    status_label = "COMPLETED (with errors)"
                else:
                    status_label = "COMPLETED"
            elif stop_f:
                status_label = "STOPPED"
            elif os.path.exists(started_flag):
                status_label = "RUNNING"
            elif pause_f:
                status_label = "PAUSED"
            else:
                status_label = "PENDING"

            core_id = job_id.split("__", 1)[-1]
            from_email = payload.get("from_email", "?")

            header = f"Job {core_id} || {kind.upper()} || {from_email} || Label: {label_name} || {status_label}"
            with st.expander(
                header,
                expanded=False,
            ):
                left, mid, right = st.columns(3)

                with left:
                    st.write(f"**Module:** {kind}")
                    st.write(f"**User:** {payload.get('user', '?')}")
                    st.write(f"**Created:** {payload.get('created_at', '?')[:16]}")

                    # Scheduled time (if recorded)
                    sched = payload.get("schedule", {})
                    if sched:
                        mode = sched.get("mode", "now")
                        if mode == "now":
                            st.write("**Scheduled:** Now (immediate)")
                        else:
                            s_date = sched.get("date", "-")
                            s_time = sched.get("time", "-")
                            s_tz = sched.get("timezone", "Local")
                            st.write(f"**Scheduled:** {s_date} @ {s_time} ({s_tz})")
                    else:
                        st.write("**Scheduled:** (not recorded)")

                with mid:
                    st.write(f"**Label:** {label_name}")
                    st.write(f"**From:** {from_email}")

                # Progress (derived from result CSV)
                if progress_value is not None:
                    st.write(f"Progress: {progress_text}")
                    st.progress(progress_value)

                # Log tail
                if log:
                    st.markdown("**Log (scrollable, full)**")
                    st.code(log, language="text")

                # Control buttons
                left, mid, right = st.columns(3)

                with left:
                    if st.button("Pause", key=f"pause_{job_id}"):
                        control_flag(job_id, "pause", True)
                        st.rerun()

                with mid:
                    if st.button("Resume", key=f"resume_{job_id}"):
                        control_flag(job_id, "pause", False)
                        st.rerun()

                with right:
                    if st.button("Stop", key=f"stop_{job_id}"):
                        control_flag(job_id, "stop", True)
                        st.rerun()

                # Results
                if result_df is not None and len(result_df) > 0:
                    st.write(f"**Result CSV ({len(result_df)} rows):**")
                    st.dataframe(result_df, use_container_width=True)
                    csv_bytes = result_df.to_csv(index=False).encode("utf-8")

                    # Build label-aware, timestamped filename
                    safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "_", label_name or "NoLabel")
                    created_raw = payload.get("created_at", "")
                    try:
                        created_at = datetime.fromisoformat(created_raw)
                    except Exception:
                        created_at = datetime.now()
                    ts_name = created_at.strftime("%d%m%Y-%H:%M")
                    if kind == "m1":
                        prefix = "sent"
                    elif kind == "m2":
                        prefix = "replied"
                    else:
                        prefix = "job"
                    fname = f"{prefix}-{safe_label}-{ts_name}.csv"

                    st.download_button(
                        "Download CSV",
                        csv_bytes,
                        file_name=fname,
                        mime="text/csv",
                        key=f"dl_{job_id}",
                    )
