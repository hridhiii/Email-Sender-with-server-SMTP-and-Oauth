import os
from celery import Celery

BROKER_URL = os.getenv("CELERY_BROKER_URL") or os.getenv("REDIS_URL") or "redis://redis:6379/0"
RESULT_URL = os.getenv("CELERY_RESULT_BACKEND") or os.getenv("REDIS_URL") or BROKER_URL

celery_app = Celery(
    "bulk_outreach",
    broker=BROKER_URL,
    backend=RESULT_URL,
    include=["app.tasks"],
)

celery_app.autodiscover_tasks(["app"])

celery_app.conf.update(
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=60 * 60 * 4,  # 4 hours
    result_expires=60 * 60 * 12,
    timezone=os.getenv("TZ", "UTC"),
    enable_utc=True,
    task_track_started=True,
)
