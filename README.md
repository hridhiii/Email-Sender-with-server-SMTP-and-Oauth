# Bulk Outreach Email Application

Production-ready bulk outreach and follow-up manager built with Streamlit, Celery, Redis, SMTP, and Gmail API (OAuth).
  
Full end-user documentation is available **inside the app** once it is running.

---

## Key Features

- **Multi-account sending**
  - Use multiple Gmail / SMTP accounts in parallel.
  - Account-level lock so only one job per account runs at a time.

- **Module 1 – Initial Outreach**
  - CSV-driven personalized cold email campaigns.
  - Placeholder support (e.g. `{first}`, `{last}`, `{company}`).
  - Rich-text editor with spacing / formatting controls.
  - Flexible sending modes:
    - Send all / send selected.
    - Draft all / draft selected.
    - Draft selected and send the rest.

- **Module 2 – Reply-Aware Follow-ups**
  - Sends follow-ups **inside the same thread**.
  - Skips prospects who already replied (reply-aware logic).
  - Optional *Force send* mode for reminder-style follow-ups.
  - Uses Message-ID / References / thread IDs (in OAuth mode) to preserve threading.

- **Safety & Deliverability**
  - Fixed delay between consecutive emails (throttling).
  - Guard window (~2 hours) between jobs for the same account.
  - Per-job logs with status for each row (SENT / DRAFTED / SKIPPED / ERROR).

- **Delivery Modes**
  - **SMTP mode** – works with App Passwords / standard SMTP servers.
  - **Gmail API (OAuth) mode** – modern, OAuth-based Gmail integration.

- **Admin & Monitoring**
  - Admin view to see all jobs, their status, and logs.
  - User view restricted to the logged-in user’s jobs.
  - Built-in job monitor and progress bar.

For all behavioural details (CSV workflow, reply detection, A/B testing, etc.), use the **in-app Documentation link** after installation.

---

## Installation

You can run the application either with **Docker Compose** (recommended) or directly with **Python** for local development.

### 1. Clone the Repository

```bash
git clone <your-private-repo-url>.git
cd <repo-folder>
```

---

### 2. Environment Configuration

Create a `.env` file in the project root. Use your own values for secrets:

```env
APP_SECRET_KEY=change_me

# Redis / Celery
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=${REDIS_URL}
CELERY_RESULT_BACKEND=${REDIS_URL}

# Admin login (for the web UI)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me

# Auth mode (e.g. simple / custom)
AUTH_MODE=simple

# SMTP defaults (optional; can also be set per-account in the UI)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=app_password
SMTP_USE_TLS=true

# Gmail OAuth (for Gmail API mode)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8501
```

> **Note:** Do **not** commit `.env` or any credentials to Git.

---

## Option A – Run with Docker Compose (Recommended)

1. Make sure you have **Docker** and **Docker Compose** installed.
2. From the project root, run:

   ```bash
   docker compose up --build
   ```

3. Once all services are up, open the app in your browser:

   - `http://localhost:8501`

4. Log in with the admin/user credentials you configured in `.env`.

---

## Option B – Run Locally with Python

Use this for development or debugging without Docker.

1. **Create and activate virtual environment**

   ```bash
   python -m venv venv
   # Linux / macOS
   source venv/bin/activate
   # Windows
   venv\Scriptsactivate
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Start Redis**

   Make sure Redis is running locally (or point `REDIS_URL` to your Redis instance):

   ```bash
   redis-server
   ```

4. **Start Celery worker**

   From the project root:

   ```bash
   celery -A app.tasks worker --loglevel=INFO
   ```

5. **Start the Streamlit app**

   ```bash
   streamlit run app/streamlit_app.py
   ```

6. Open the app in your browser:

   - `http://localhost:8501`

---

## Accessing Full Documentation

Once the application is running:

- Use the **“Documentation” / “Help” link** in the UI (usually on the login or sidebar).
- This opens the **full official documentation** (hosted separately, e.g. Notion), covering:
  - Detailed CSV workflow.
  - Module 1 & Module 2 behaviour.
  - Reply-aware logic.
  - A/B testing.
  - Examples and troubleshooting.

