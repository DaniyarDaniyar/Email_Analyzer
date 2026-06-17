# Python modules
from typing import Any, Dict

# Third-party modules
from celery import shared_task

# Project modules
from apps.detector.services.pipeline import process_detector_result


@shared_task(bind=True)
def analyze_email_task(self, detector_result_id: int) -> Dict[str, Any]:
    """Background task to analyze a DetectorResult by id."""
    return process_detector_result(detector_result_id, use_concurrency=False)
