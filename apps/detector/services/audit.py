# Python modules
from typing import Any, Dict, Optional

# Django modules
from django.http import HttpRequest

# Project modules
from apps.detector.models import AuditLog


def log_event(
    action: str,
    *,
    user=None,
    obj=None,
    meta: Optional[Dict[str, Any]] = None,
    request: Optional[HttpRequest] = None,
) -> None:
    """Persist a lightweight audit log entry for security/compliance."""
    meta_data: Dict[str, Any] = dict(meta or {})

    if request is not None:
        meta_data.setdefault("ip", request.META.get("REMOTE_ADDR"))
        meta_data.setdefault("user_agent", request.META.get("HTTP_USER_AGENT"))

    object_type = obj.__class__.__name__ if obj is not None else None
    object_id = str(getattr(obj, "id", "")) if obj is not None else None

    AuditLog.objects.create(
        user=user if user and user.is_authenticated else None,
        action=action,
        object_type=object_type,
        object_id=object_id,
        meta=meta_data,
    )
