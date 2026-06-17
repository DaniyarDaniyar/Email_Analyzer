#Python modules
from typing import Any
from drf_spectacular.utils import extend_schema, OpenApiResponse

#Django_modeul
from django.db.models.query import QuerySet
from django.http import FileResponse
from django.urls import reverse

#Django Rest Framework modules
from rest_framework.viewsets import ViewSet
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response as DRFResponse
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_405_METHOD_NOT_ALLOWED,
    HTTP_201_CREATED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
)
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action

# Project modules
from apps.detector.models import DetectorResult
from apps.detector.serializers import (
    DetectorResultListSerializer,
    ScanRequestSerializer,
    DetectorResultSerializer,
)
from apps.abstracts.paginators import AbstractPageNumberPaginator
from apps.abstracts.mixins import DRFResponseMixin
from apps.detector.services.file_service import extract_text_from_pdf, extract_text_from_txt, extract_text_from_eml
from apps.detector.services.pipeline import run_sync_scan, create_queued_result, build_report_download_url
from apps.detector.services.audit import log_event
from apps.detector.tasks import analyze_email_task
class DetectorViewSet(ViewSet, DRFResponseMixin):
    """ViewSet for scanning emails/URLs and viewing personal scan history."""

    @extend_schema(
        summary="Scan email or URL (public)",
        description="Analyze email text or URL for phishing/security threats. No authentication required.",
        request=ScanRequestSerializer,
        responses={
            HTTP_201_CREATED: DetectorResultSerializer,
            HTTP_400_BAD_REQUEST: OpenApiResponse(description="Invalid input"),
            HTTP_405_METHOD_NOT_ALLOWED: OpenApiResponse(description="Only POST allowed"),
        },
    )
    @action(
        detail=False,
        methods=["POST"],
        permission_classes=[AllowAny],
        url_path="scan",
    )
    def scan(self, request: DRFRequest, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> DRFResponse:
        """
        Public endpoint to scan email, URL, or file. Saves result to authenticated user if provided.
        Supports: text, url, PDF/TXT/EML file upload.
        """
        serializer = ScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        input_type = serializer.validated_data["input_type"]
        async_requested = str(request.query_params.get("async", "")).lower() in ("1", "true", "yes")
        
        # Extract text based on input type
        try:
            if input_type == "text":
                input_data = serializer.validated_data["input_data"]
            elif input_type == "url":
                input_data = serializer.validated_data["input_data"]
            elif input_type == "file":
                file_obj = serializer.validated_data["file"]
                lower_name = str(file_obj.name).lower()
                # Extract text from PDF, read TXT, or preserve raw RFC822 EML content.
                if lower_name.endswith(".pdf"):
                    input_data = extract_text_from_pdf(file_obj)
                elif lower_name.endswith(".eml"):
                    input_data = extract_text_from_eml(file_obj)
                else:  # .txt
                    input_data = extract_text_from_txt(file_obj)
            else:
                return DRFResponse(
                    {"error": f"Unknown input_type: {input_type}"},
                    status=HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            return DRFResponse(
                {"error": f"File processing error: {str(e)}"},
                status=HTTP_400_BAD_REQUEST,
            )

        # Optional async mode (requires auth): save the raw input and process via Celery
        if async_requested:
            if not request.user.is_authenticated:
                return DRFResponse({"error": "Authentication required for async scan"}, status=HTTP_403_FORBIDDEN)

            detector_result = create_queued_result(request.user, input_type, input_data)
            analyze_email_task.delay(detector_result.id)
            status_url = request.build_absolute_uri(
                reverse("detector-status", kwargs={"pk": detector_result.id})
            )
            return DRFResponse(
                {"status": "queued", "result_id": detector_result.id, "status_url": status_url},
                status=HTTP_201_CREATED,
            )

        try:
            response_data = run_sync_scan(
                input_type,
                input_data,
                user=request.user if request.user.is_authenticated else None,
                request=request,
                use_concurrency=True,
            )
        except Exception as e:
            return DRFResponse({"error": f"Analysis error: {e}"}, status=HTTP_400_BAD_REQUEST)

        return DRFResponse(response_data, status=HTTP_201_CREATED)

    @extend_schema(
        summary="List user's scan history",
        description="Retrieve paginated list of scan results for the authenticated user.",
        responses={
            HTTP_200_OK: DetectorResultListSerializer(many=True),
            HTTP_403_FORBIDDEN: OpenApiResponse(description="Authentication required"),
            HTTP_405_METHOD_NOT_ALLOWED: OpenApiResponse(description="Only GET allowed"),
        },
    )
    @action(
        detail=False,
        methods=["GET"],
        permission_classes=[IsAuthenticated],
        url_path="history",
    )
    def history(self, request: DRFRequest, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> DRFResponse:
        """
        List all scan results for the authenticated user, ordered by most recent first.
        """
        results: QuerySet[DetectorResult] = DetectorResult.objects.filter(user=request.user)
        paginator = AbstractPageNumberPaginator(page_size=20)
        return self.get_drf_response(
            request=request,
            data=results,
            serializer_class=DetectorResultListSerializer,
            many=True,
            paginator=paginator,
        )

    @extend_schema(
        summary="Get a specific scan result",
        description="Retrieve details of a specific scan result (only accessible to owner)",
        responses={
            HTTP_200_OK: DetectorResultSerializer,
            HTTP_403_FORBIDDEN: OpenApiResponse(description="Not owner of result"),
            HTTP_405_METHOD_NOT_ALLOWED: OpenApiResponse(description="Only GET allowed"),
        },
    )
    @action(
        detail=True,
        methods=["GET"],
        permission_classes=[IsAuthenticated],
        url_path="result",
    )
    def get_result(self, request: DRFRequest, pk=None, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> DRFResponse:
        """Get a specific result if user owns it."""
        try:
            result = DetectorResult.objects.get(id=pk, user=request.user)
        except DetectorResult.DoesNotExist:
            return DRFResponse(
                {"error": "Result not found or access denied"},
                status=HTTP_403_FORBIDDEN,
            )
        serializer = DetectorResultSerializer(result)
        return DRFResponse(serializer.data, status=HTTP_200_OK)

    @extend_schema(
        summary="Get scan status",
        description="Retrieve async status for a specific scan result (only accessible to owner)",
        responses={
            HTTP_200_OK: OpenApiResponse(description="Status payload"),
            HTTP_403_FORBIDDEN: OpenApiResponse(description="Not owner of result"),
            HTTP_405_METHOD_NOT_ALLOWED: OpenApiResponse(description="Only GET allowed"),
        },
    )
    @action(
        detail=True,
        methods=["GET"],
        permission_classes=[IsAuthenticated],
        url_path="status",
    )
    def status(self, request: DRFRequest, pk=None, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> DRFResponse:
        try:
            result = DetectorResult.objects.get(id=pk, user=request.user)
        except DetectorResult.DoesNotExist:
            return DRFResponse(
                {"error": "Result not found or access denied"},
                status=HTTP_403_FORBIDDEN,
            )

        return DRFResponse(
            {
                "status": result.status,
                "score": result.score,
                "finished_at": result.finished_at,
                "error_message": result.error_message,
                "report_url": build_report_download_url(request, result),
            },
            status=HTTP_200_OK,
        )

    @extend_schema(
        summary="Download scan result PDF report",
        description="Download PDF report for a specific scan result (only accessible to owner)",
        responses={
            HTTP_200_OK: OpenApiResponse(description="PDF file"),
            HTTP_403_FORBIDDEN: OpenApiResponse(description="Not owner of result"),
            HTTP_404_NOT_FOUND: OpenApiResponse(description="Result or report not found"),
        },
    )
    @action(
        detail=True,
        methods=["GET"],
        permission_classes=[IsAuthenticated],
        url_path="report/download",
    )
    def download_report(self, request: DRFRequest, pk=None, *args: tuple[Any, ...], **kwargs: dict[str, Any]):
        """Download PDF report for a specific result if user owns it and report exists."""
        try:
            result = DetectorResult.objects.get(id=pk, user=request.user)
        except DetectorResult.DoesNotExist:
            return DRFResponse(
                {"error": "Result not found or access denied"},
                status=HTTP_403_FORBIDDEN,
            )

        if not result.report_file:
            return DRFResponse(
                {"error": "Report not available for this result"},
                status=HTTP_404_NOT_FOUND,
            )

        try:
            file_obj = result.report_file.open("rb")
            filename = result.report_file.name.split('/')[-1]
            response = FileResponse(file_obj, content_type="application/pdf")
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            log_event("report_downloaded", user=request.user, obj=result, request=request)
            return response
        except Exception as e:
            return DRFResponse(
                {"error": f"Failed to download report: {str(e)}"},
                status=HTTP_400_BAD_REQUEST,
            )