from django.conf import settings
from django.db import models

from apps.abstracts.models import AbstractBaseModel


class DetectorResult(AbstractBaseModel):
    """Stores a scan result for a user's submitted text or URL.

    Fields are stored as plain text in the DB.
    """

    INPUT_TEXT = "text"
    INPUT_URL = "url"
    INPUT_CHOICES = ((INPUT_TEXT, "text"), (INPUT_URL, "url"))

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="detector_results",
    )
    input_type = models.CharField(max_length=10, choices=INPUT_CHOICES, default=INPUT_TEXT)
    input_data = models.TextField()
    score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    explanation = models.TextField(null=True, blank=True)
    is_safe = models.BooleanField(default=False)
    report_file = models.FileField(upload_to="reports/", null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"DetectorResult(id={self.id}, user_id={self.user_id}, score={self.score})"