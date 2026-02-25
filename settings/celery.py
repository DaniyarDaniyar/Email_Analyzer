import os

from celery import Celery


# Ensure the project can run without manually exporting PROJECT_ENV_ID each time.
# This is primarily for local development.
os.environ.setdefault("PROJECT_ENV_ID", "local")
os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    f"settings.env.{os.environ.get('PROJECT_ENV_ID', 'local')}",
)


app = Celery("email_detector")

# Load any CELERY_* settings from Django settings.py
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks.py in installed apps
app.autodiscover_tasks()

