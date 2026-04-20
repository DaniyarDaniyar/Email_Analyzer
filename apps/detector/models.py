# Django modules
from django.conf import settings
from django.db import models

# Project modules
from apps.abstracts.models import AbstractBaseModel


class DetectorResult(AbstractBaseModel):
    """Stores a scan result for a user's submitted text or URL.

    Fields are stored as plain text in the DB.
    """

    INPUT_TEXT = "text"
    INPUT_URL = "url"
    INPUT_FILE = "file"
    INPUT_CHOICES = (
        (INPUT_TEXT, "text"),
        (INPUT_URL, "url"),
        (INPUT_FILE, "file"),
    )

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_QUEUED, "queued"),
        (STATUS_RUNNING, "running"),
        (STATUS_COMPLETED, "completed"),
        (STATUS_FAILED, "failed"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="detector_results",
    )
    input_type = models.CharField(max_length=10, choices=INPUT_CHOICES, default=INPUT_TEXT)
    input_data = models.TextField()
    score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    explanation = models.TextField(null=True, blank=True)
    is_safe = models.BooleanField(default=False)
    report_file = models.FileField(upload_to="reports/", null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_COMPLETED)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    score_details = models.JSONField(null=True, blank=True)

    class Meta:
        """Meta options for DetectorResult model."""
        ordering = ("-created_at",)

    def __str__(self) -> str:
        """String representation of the model instance."""
        return (
            f"DetectorResult(id={self.id}, user_id={self.user_id}, "
            f"status={self.status}, score={self.score})"
        )


class AuditLog(AbstractBaseModel):
    """Audit log for security/compliance events."""

    ACTION_MAX_LENGTH = 64
    OBJECT_MAX_LENGTH = 64

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=ACTION_MAX_LENGTH)
    object_type = models.CharField(max_length=OBJECT_MAX_LENGTH, null=True, blank=True)
    object_id = models.CharField(max_length=OBJECT_MAX_LENGTH, null=True, blank=True)
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"AuditLog(id={self.id}, action={self.action})"