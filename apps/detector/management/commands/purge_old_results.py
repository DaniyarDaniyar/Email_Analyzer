# Django modules
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

# Project modules
from apps.detector.models import DetectorResult


class Command(BaseCommand):
    help = "Purge old detector results and their report files."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help="Override retention window in days (defaults to settings.RETENTION_DAYS)",
        )

    def handle(self, *args, **options):
        days = options.get("days")
        if days is None:
            days = int(getattr(settings, "RETENTION_DAYS", 0) or 0)

        if days <= 0:
            self.stdout.write(self.style.WARNING("RETENTION_DAYS is not set or <= 0; skipping"))
            return

        cutoff = timezone.now() - timezone.timedelta(days=days)
        qs = DetectorResult.objects.filter(created_at__lt=cutoff)
        total = qs.count()

        for result in qs:
            try:
                if result.report_file:
                    result.report_file.delete(save=False)
            except Exception:
                pass
            DetectorResult.objects.filter(id=result.id).delete()

        self.stdout.write(self.style.SUCCESS(f"Purged {total} results older than {days} days"))
