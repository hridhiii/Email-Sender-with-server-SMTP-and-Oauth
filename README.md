# Bulk Outreach Email Application

A production-grade, multi-account bulk email and follow-up manager built with Streamlit, Celery, and Redis.

It supports SMTP and Gmail API (OAuth), reply-aware follow-ups, safe scheduling with account locking, and flexible draft/send workflows. This README is written for both **regular users** (non-technical operators) and **developers**.

Author: **Hridhi Nandu P P**  
Version: **1.0**

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Intended CSV Workflow (Very Important)](#intended-csv-workflow-very-important)
4. [Tech Stack](#tech-stack)
5. [Usage Guide (Non-Technical Users)](#usage-guide-non-technical-users)  
   5.1 [Key Concepts](#51-key-concepts)  
   5.2 [Logging In and Roles](#52-logging-in-and-roles)  
   5.3 [Home Screen Layout](#53-home-screen-layout)  
   5.4 [Module 1 – Initial Outreach](#54-module-1--initial-outreach)  
   5.5 [Module 2 – Reply-Aware Follow-ups](#55-module-2--reply-aware-follow-ups)  
   5.6 [A/B Testing for Users](#56-ab-testing-for-users)  
   5.7 [High-Level Server Behaviour](#57-high-level-server-behaviour)
6. [Developer Guide](#developer-guide)  
   6.1 [Architecture Overview](#61-architecture-overview)  
   6.2 [Repository Structure (Example)](#62-repository-structure-example)  
   6.3 [Prerequisites](#63-prerequisites)  
   6.4 [Local Installation](#64-local-installation)  
   6.5 [Running with Docker Compose](#65-running-with-docker-compose)  
   6.6 [Authentication & Modes](#66-authentication--modes)  
   6.7 [Jobs, Locks, and Timing](#67-jobs-locks-and-timing)  
   6.8 [Reply-Aware Logic (Technical)](#68-reply-aware-logic-technical)  
   6.9 [A/B Testing & Metrics (Technical)](#69-ab-testing--metrics-technical)  
   6.10 [Logging & Debugging](#610-logging--debugging)
7. [Security & Privacy Notes](#security--privacy-notes)
8. [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
9. [License](#license)

---

## Overview

This application is a multi-account bulk email and follow-up manager designed for sales, marketing, and outreach workflows.

It allows you to:

- Send personalized cold email campaigns (**Module 1 – Initial Outreach**).
- Send **reply-aware follow-ups** in the same Gmail thread (**Module 2 – Follow-ups**).
- Use different delivery modes:
  - SMTP (App Password / standard SMTP).
  - Gmail API via OAuth.
- Choose between sending emails directly or creating Gmail drafts.
- Schedule jobs for later with an **account-level lock** so that only one job per account runs at a time.
- Enforce safety rules such as:
  - A fixed delay between individual emails.
  - A minimum time gap (~2 hours) between jobs for the same Gmail account.
- View logs, monitor progress, and run A/B tests on templates.

The rest of this document is split into:

- A **Usage Guide** for non-technical users.
- A **Developer Guide** covering installation and internal architecture.

---

## Key Features

- **Module 1 – Initial Outreach**
  - CSV-driven personalized campaigns.
  - Placeholder support (`{first}`, `{last}`, `{company}`, etc.).
  - Rich-text editor with custom spacing tags (`[gap:0]`, `[gap:1]`, etc.).
  - Send vs Draft options.
  - Optional selection modes: send all, send selected, draft all, draft selected, draft selected and send rest.

- **Module 2 – Reply-Aware Follow-ups**
  - Sends follow-ups into existing Gmail threads.
  - Skips prospects who **already replied** (reply-aware).
  - Optional **“Force send”** reminder mode:
    - Still skips threads where the prospect replied.
    - Allows reminder emails if only **you** (the sender) replied earlier.
  - Uses message metadata (Message-ID, References, thread ID) to preserve threading.

- **Safety & Deliverability**
  - **Per-account lock**: only one job per sending account runs at a time.
  - **~2-hour guard window** between jobs for the same account.
  - Per-email throttling with delays between messages.

- **Multi-Mode Delivery**
  - SMTP mode for standard mail servers.
  - Gmail API (OAuth) mode for modern Gmail integration.

- **Roles**
  - **Admin** view for all jobs and logs.
  - **User** view limited to the logged-in user’s jobs.

- **A/B Testing**
  - Use a `variant` column in the CSV.
  - Run separate jobs for each variant.
  - Compare reply rates and performance.

---

## Intended CSV Workflow (Very Important)

This is the **intended workflow** for using CSV files with the application. It prevents a very common mistake that causes Module 2 jobs to finish immediately.

### Module 1 CSV = Your Master File

The CSV you use with **Module 1** becomes your **master file** for that campaign.

You should continue to use the **same Module 1 output CSV** for:

- First follow-up (Module 2 – Follow-up 1)
- Second follow-up (Module 2 – Follow-up 2)
- Third follow-up (Module 2 – Follow-up 3)
- And so on.

For each follow-up round, you only change:

- The **Module 2 template** (different follow-up copy), and  
- The **follow-up number / mode settings** in the Module 2 UI.

### Module 2 CSVs = Reporting / Logs Only

Module 2 can produce “reply files” or output CSVs. These should be treated as:

- Logs
- Analytics / records
- Files for manual review

They are **not** meant to be used as input for a new Module 2 job.

> **Do not feed Module 2 output CSVs back into Module 2.**  
> Always return to the **master Module 1 CSV** when scheduling follow-ups.

### Why This Matters

If you use a Module 2 output CSV as input to a new Module 2 job:

- Rows are already marked with follow-up status and metadata.
- The system often concludes that everyone is processed or replied.
- The job “immediately completes” with 0 emails sent.

To avoid this, follow this pattern:

- **Module 1 CSV → master campaign file (used for all follow-up stages).**  
- **Module 2 CSVs → logs only, not reused as input.**

---

## Tech Stack

- **Frontend:** Streamlit  
- **Background Jobs:** Celery  
- **Broker / Cache:** Redis  
- **Email Delivery:** SMTP, Gmail API (OAuth)  
- **Data Handling:** pandas  
- **Config & Secrets:** Environment variables via `python-dotenv`

---

## Usage Guide (Non-Technical Users)

### 5.1 Key Concepts

1. **Account**  
   A sending identity such as `you@company.com`, configured either with:
   - SMTP credentials, or
   - Gmail API (OAuth authorization).

2. **Delivery Mode**
   - **SMTP mode**: uses SMTP username/password or app password.
   - **Gmail API (OAuth) mode**: uses Google OAuth tokens.

3. **Module**
   - **Module 1:** Initial outreach (first email in a sequence).
   - **Module 2:** Follow-up emails (second, third, etc.) in existing threads.

4. **Job**
   - A single run of Module 1 or Module 2 with a specific CSV, template, account, and schedule.
   - Has a status like *Pending*, *Running*, *Completed*, or *Failed*.

5. **CSV File**
   - Your list of prospects as a CSV.
   - Typical columns:
     - `email`
     - `first_name`
     - `last_name`
     - `company`
     - Any additional custom fields.
   - For follow-ups, metadata for messages and threads is stored back into this CSV.

6. **Template & Placeholders**
   - Email subject and body created in the rich-text editor.
   - Placeholders like `{first}`, `{last}`, `{company}` get filled from CSV.
   - Header names are normalized (e.g., `"First Name"` → `first`).

7. **Draft vs Send**
   - **Draft**: create Gmail drafts only (for manual sending).
   - **Send**: send emails directly from the application.

8. **Account Lock**
   - Prevents more than one job from running simultaneously for the same account.

9. **2-Hour Guard Window**
   - Prevents another job from being scheduled for the same account within ~2 hours of a running/scheduled job.

---

### 5.2 Logging In and Roles

- **Login Screen**
  - Typically asks for username/email and password.
  - May allow selection of Admin vs User role (depending on configuration).

- **Admin**
  - Sees all jobs and logs.
  - Can monitor and sometimes cancel jobs.
  - May adjust global settings.

- **Regular User**
  - Works only with their own jobs and authorized accounts.

---

### 5.3 Home Screen Layout

- **Sidebar**
  - Module 1 (Initial Outreach)
  - Module 2 (Follow-ups)
  - Settings / Account configuration
  - Documentation / Help

- **Main Area**
  - Top: CSV upload, account selection, delivery mode, template editor, toggles.
  - Middle: CSV preview, email preview with example data.
  - Bottom: “Send now” / “Schedule later” and a job list with status and logs.

---

### 5.4 Module 1 – Initial Outreach

Module 1 sends the first email in your sequence.

#### When to Use

- To send a brand-new campaign to a list.
- To populate the master CSV with initial metadata (Message-ID, thread ID, etc.).

#### Steps

1. **Prepare CSV**
   - Include `email` plus as many personalization fields as you want.
   - Example: `email`, `first_name`, `last_name`, `company`, `city`, `industry`.

2. **Upload CSV**
   - Click “Upload CSV” and choose your file.
   - Preview shows the first few rows; headers are normalized internally.

3. **Choose Account & Delivery Mode**
   - Select a sending account (e.g., `outreach@company.com`).
   - Choose SMTP or Gmail API (OAuth) mode.

4. **Compose Template**
   - Write subject and body using the rich-text editor.
   - Use `{first}`, `{last}`, `{company}`, etc.
   - Local/global spacing tags like `[gap:0]` may be available to fine-tune spacing.

5. **Row Selection & Drafting**
   - Options may include:
     - Send all
     - Send selected
     - Draft all
     - Draft selected
     - Draft selected and send rest
   - If you have a “select” column in the CSV, “Send all” operates on all included rows, while “Send selected” operates on those you explicitly select.

6. **Scheduling & Safety**
   - **Send now**:
     - Starts immediately *if* no other job is running for that account.
   - **Schedule later**:
     - Choose date/time; job stays *Pending* until then.
   - If another job is running for the same account:
     - The new job will **fail immediately** (account lock).
   - If you attempt to schedule a job within ~2 hours of another job on the same account:
     - The new job is rejected (2-hour guard window).

7. **Per-Email Throttling**
   - The app waits between each email (e.g., ~30 seconds + optional random jitter).
   - You don’t need to configure it—this is built-in to protect deliverability.

8. **Monitoring**
   - Track total, sent, skipped, and failed rows.
   - Watch the progress bar.
   - Use logs to see details for each email.

---

### 5.5 Module 2 – Reply-Aware Follow-ups

Module 2 sends follow-ups into existing threads while respecting replies.

#### When to Use

- After Module 1 has already run.
- When you want follow-up emails that:
  - Skip people who replied.
  - Continue threads for non-responders.

#### Inputs

- **Master Module 1 CSV**:
  - Contains original columns + metadata (Message-ID, thread ID, statuses).
- **New Follow-up Template**:
  - A new subject/body or “bump” copy.

#### Core Behaviour

1. **Reply Detection**
   - For each row, the app looks up the corresponding thread:
     - Gmail API mode: uses stored `threadId`.
     - SMTP mode: uses `Message-ID` or related metadata.
   - Checks if the prospect’s email address has replied in the thread.
   - If the prospect replied:
     - Row is skipped (no follow-up).
   - If they did not reply:
     - Follow-up is sent or drafted into the same thread.

2. **“Force Send” Toggle (Reminder Mode)**
   - **When OFF**:
     - Skip rows where:
       - A follow-up already went out, or
       - The prospect replied.
   - **When ON**:
     - Still skip rows where the prospect replied.
     - But you *can* send again even if you (the sender) replied before, acting as a reminder.

3. **Draft vs Send, Selection, Scheduling**
   - Same options as Module 1:
     - Draft vs send.
     - All vs selected rows.
     - Send now vs schedule later.
   - Account lock and guard window still apply.

#### Critical Workflow Reminder

- Always use the **Module 1 master CSV** as input to Module 2.
- Treat Module 2 output CSVs as logs, not as fresh inputs.

---

### 5.6 A/B Testing for Users

To do simple A/B testing:

1. Add a column `variant` to your master CSV (values like `A` or `B`).
2. Run separate Module 1 jobs:
   - Job A: template A on variant A rows.
   - Job B: template B on variant B rows.
3. Track replies or external metrics (clicks, conversions).
4. For follow-ups, you can also split variants and use different follow-up copy for each group.

---

### 5.7 High-Level Server Behaviour

For non-technical users:

- You use the UI in a browser.
- When you create a job, it is pushed to a **background worker**.
- The worker:
  - Acquires an account lock.
  - Processes the CSV row by row.
  - Sends/drafts emails via SMTP or Gmail API.
  - Updates progress and logs.
  - Releases the lock at the end.

You can safely close your browser after job creation; the job continues on the server.

---

## Developer Guide

### 6.1 Architecture Overview

Core components:

- **Front-end / UI**: Streamlit app (`streamlit_app.py` or equivalent).
- **Background tasks**: Celery workers.
- **Broker / cache**: Redis.
- **Email delivery**:
  - SMTP for generic mail servers.
  - Gmail API (OAuth) for Gmail accounts.
- **Storage**:
  - Database and/or CSV + Redis for jobs and metadata.
- **Configuration**:
  - `.env` for environment variables and secrets.

---

### 6.2 Repository Structure (Example)

```text
app/
  streamlit_app.py        # UI + job creation
  tasks.py                # Celery tasks (module1, module2)
  auth.py                 # Authentication & roles
  email_utils.py          # Templates, placeholders, headers
  gmail_api.py            # Gmail API integration (OAuth, threads)
  smtp_client.py          # SMTP send helper
  models.py or storage/   # Job and account storage layer
requirements.txt
docker-compose.yml
.env                      # (not checked into git)
README.md
LICENSE.txt
docs/                     # Optional extended documentation
```

Actual filenames may differ; adjust as needed.

---

### 6.3 Prerequisites

- **System**
  - Python 3.10+
  - Redis server
  - Git

- **Python Packages**
  - `streamlit`
  - `celery`
  - `redis`
  - `python-dotenv`
  - `google-auth`, `google-auth-oauthlib`, `google-api-python-client`
  - `pandas`
  - IMAP / email parsing libs as required

- **Email Infrastructure**
  - SMTP credentials (host, port, username, password or app password).
  - Google Cloud project with Gmail API enabled (for OAuth mode).

---

### 6.4 Local Installation

1. **Clone the repository**

```bash
git clone <your-private-repo-url>.git
cd <repo-folder>
```

2. **Create and activate virtual environment**

```bash
python -m venv venv
source venv/bin/activate      # Linux / macOS
# or
venv\Scriptsctivate         # Windows
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Create `.env` file**

Example skeleton:

```env
APP_SECRET_KEY=change_me

REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=${REDIS_URL}
CELERY_RESULT_BACKEND=${REDIS_URL}

ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me
AUTH_MODE=simple

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=app_password
SMTP_USE_TLS=true

GMAIL_CLIENT_ID=your_google_client_id
GMAIL_CLIENT_SECRET=your_google_client_secret
GMAIL_REDIRECT_URI=http://localhost:8501
GMAIL_SCOPES=https://www.googleapis.com/auth/gmail.send,https://www.googleapis.com/auth/gmail.modify
```

Adjust for your environment and security requirements.

5. **Start Redis**

```bash
redis-server
```

6. **Start Celery worker**

```bash
celery -A app.tasks worker --loglevel=INFO
```

7. **Start Streamlit app**

```bash
streamlit run app/streamlit_app.py
```

Open `http://localhost:8501` in your browser.

---

### 6.5 Running with Docker Compose

If `docker-compose.yml` is available:

```bash
docker compose up --build
```

This usually starts:

- `web` – Streamlit app
- `worker` – Celery worker
- `redis` – Redis broker

Access via `http://localhost:8501` (or mapped port).

---

### 6.6 Authentication & Modes

#### SMTP Mode

- Uses SMTP credentials from `.env` or from user-provided account settings.
- Sending is done via standard Python SMTP libraries.
- Reply detection can use IMAP or Gmail API.

#### Gmail API (OAuth) Mode

- Requires:
  - Gmail API enabled in a Google Cloud project.
  - OAuth client ID & secret.
  - Redirect URI matching your deployment URL.
- Flow:
  - User clicks “Connect with Google”.
  - OAuth flow grants tokens with scopes like `gmail.send` and `gmail.modify`.
  - Tokens are stored securely (file, DB, etc.) mapped to an account.

#### Admin Mode

- Admin users have extended visibility (all jobs, logs).
- Implement via `auth.py` using either:
  - Environment-configured login, or
  - A user database with role flags.

---

### 6.7 Jobs, Locks, and Timing

#### Job Lifecycle

1. User submits job via UI.
2. Metadata stored (module, account, CSV path, schedule, settings).
3. Celery task queued.
4. Worker picks up the job when scheduled time is reached.
5. Worker processes rows, updates logs and progress.

#### Account Lock

- Implemented using Redis or DB-based locks.
- Before sending, worker tries to acquire `lock:account:<email>`.
- If lock fails, job fails immediately with an explanatory message.
- Lock is released when job finishes (successfully or not).

#### 2-Hour Guard Window

- At job creation, the app checks existing jobs for that account.
- If the new job’s scheduled time is within ~2 hours of another running/scheduled job:
  - Creation is rejected.
- This is a policy choice for deliverability; can be made configurable.

#### Per-Email Throttling

- Worker sleeps between sends:
  - e.g., `time.sleep(base_delay + random_jitter)`.
- Delay helps avoid spam flags and unnatural sending bursts.

---

### 6.8 Reply-Aware Logic (Technical)

For each row in Module 2:

1. Read metadata from master CSV:
   - Original `message_id`, `thread_id`, etc.
2. Fetch thread:
   - Gmail API: `users.threads.get`.
   - IMAP: search by Message-ID, then follow thread.
3. Classify messages:
   - Identify outbound messages (from sender).
   - Identify inbound messages (from prospect).
4. If at least one inbound message from prospect exists:
   - Mark as **replied** → skip.
5. Else:
   - If **Force send OFF** and a follow-up already sent → skip.
   - If **Force send ON** and only the sender replied → send.
6. For sending:
   - Gmail API: use `threadId` and appropriate headers.
   - SMTP: set `In-Reply-To` and `References` headers based on original Message-ID.

---

### 6.9 A/B Testing & Metrics (Technical)

- Add `variant` column to master CSV.
- Populate with values like `A`, `B`, etc.
- Run separate jobs with different templates and store job IDs.
- Track:
  - Replies per variant.
  - Failures, bounce data if available.
  - Optionally integrate click tracking via URLs and external analytics.

---

### 6.10 Logging & Debugging

- Use structured logging where possible:
  - Job start/end.
  - Account lock acquisition/release.
  - Per-row status (SENT, DRAFTED, SKIPPED, ERROR).
  - External API HTTP codes.
- Make log level configurable (`DEBUG`, `INFO`, `ERROR`).
- For production, ship logs to centralized logging if needed.

---

## Security & Privacy Notes

- Never commit `.env` or credentials to Git.
- Use HTTPS when exposing the app to the internet.
- Restrict access with strong credentials and role-based permissions.
- Follow your email provider’s terms and anti-spam rules.
- For GDPR and other regulations, consult legal advice.
- Inform users that:
  - Email content and recipient lists are processed by the server.
  - Gmail API scopes determine how much access the app has to their mailbox.

---

## Frequently Asked Questions (FAQ)

1. **Why did my Module 2 job finish immediately with 0 emails sent?**  
   Most likely because you used a **Module 2 output CSV** (“reply file”) as input to Module 2. Those rows are already flagged as processed, so everything gets skipped.  
   Always use the **master Module 1 CSV** for follow-ups and treat Module 2 outputs as logs only.

2. **Which CSV should I use for Follow-up 1, 2, and 3?**  
   Always use the **same Module 1 CSV** (the master file) for Follow-up 1, 2, 3, etc. Only change the follow-up template and settings in Module 2.

3. **What happens if I try to run two jobs at the same time for the same account?**  
   The **account lock** allows only one job to run. The second job fails immediately with a message that another job is running for that account.

4. **Why can’t I schedule two jobs close together on the same account?**  
   The app enforces a **~2-hour guard window** for the same account to avoid spammy patterns. A new job scheduled too close in time to another job is rejected.

5. **Can I use the app only to create drafts and send from Gmail manually?**  
   Yes. Use any of the **Draft** options (Draft all, Draft selected, etc.) in both Module 1 and Module 2 (in Gmail API mode).

6. **Does the app automatically detect replies?**  
   Yes. Module 2 uses **reply-aware logic** to detect replies in threads and skip prospects who have already responded.

7. **Can I test different templates (A/B testing)?**  
   Yes. Add a `variant` column to your CSV, create separate jobs per variant, and compare reply metrics.

8. **What if Gmail API or SMTP returns an error?**  
   The error is logged for that row, and the job proceeds with other rows unless the error is fatal. Check logs and fix credentials, tokens, or provider limits.

9. **Can multiple users share the same sending account?**  
   They can, but the account lock and guard window still apply. It is usually better to have one sending account per user or team.

---

## License

This project is **proprietary** and owned by **Hridhi Nandu P P**.

All rights reserved. See `LICENSE.txt` in this repository for full license terms.
