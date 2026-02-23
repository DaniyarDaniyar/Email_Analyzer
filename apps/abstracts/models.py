from typing import Any

from django.db.models import DateTimeField, Model
from django.utils import timezone


class AbstractBaseModel(Model):
    """
    Abstract base model that provides common fields and methods for all models.
    """

    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)
    deleted_at = DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    def delete(self, *args: tuple[Any, ...], **kwargs: dict[Any, Any]) -> None:  # type: ignore
        """
        Soft delete the model instance by setting the deleted_at field to the current timestamp.
        """
        self.deleted_at = timezone.now()
        self.save(update_fields=["deleted_at"])