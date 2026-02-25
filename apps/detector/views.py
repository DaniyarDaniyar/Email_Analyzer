#Python modules
from typing import Any
from drf_spectacular.utils import extend_schema, OpenApiResponse

#Django_modeul
from django.db.models.query import QuerySet
from django.http import FileResponse

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
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.detector.models import DetectorResult
from apps.detector.serializers import (
    DetectorResultListSerializer,
    ScanRequestSerializer,
    DetectorResultSerializer,
)
from apps.abstracts.paginators import AbstractPageNumberPaginator
from apps.abstracts.mixins import DRFResponseMixin
from apps.detector.services.ai_service import analyze_parsed
from urllib.parse import urlparse
from apps.detector.services.file_service import extract_text_from_pdf, extract_text_from_txt
from apps.detector.services.parser import parse_email
from apps.detector.services.analysis import build_reputation, compute_scores
from apps.detector.services.report import generate_pdf
from django.conf import settings
import os
import time
from django.core.files import File as DjangoFile
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
        Supports: text, url, PDF/TXT file upload.
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
                # Extract text from PDF or read TXT
                if str(file_obj.name).lower().endswith(".pdf"):
                    input_data = extract_text_from_pdf(file_obj)
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

            detector_result = DetectorResult.objects.create(
                user=request.user,
                input_type=input_type,
                input_data=input_data,
            )
            analyze_email_task.delay(detector_result.id)
            return DRFResponse(
                {"status": "queued", "result_id": detector_result.id},
                status=HTTP_201_CREATED,
            )

        # Full pipeline: parse -> reputation checks -> AI -> scoring -> PDF report
        if input_type in ["text", "file"]:
            try:
                parsed = parse_email(input_data)
            except Exception as e:
                return DRFResponse({"error": f"Parsing error: {e}"}, status=HTTP_400_BAD_REQUEST)

            # Reputation checks (concurrent)
            reputation = build_reputation(parsed, use_concurrency=True)

            # Call AI on aggregated parsed+reputation
            try:
                ai_out = analyze_parsed(parsed, reputation)
            except Exception as e:
                return DRFResponse({"error": f"AI analysis error: {e}"}, status=HTTP_400_BAD_REQUEST)

            scores = compute_scores(parsed, reputation, ai_out)
            final_score = scores["final_score"]

            # Build report structure
            report = {
                "title": "Email Analysis Report",
                "summary": f"Final score: {final_score:.2f}",
                "parsed": parsed,
                "reputation": reputation,
                "ai": ai_out,
                "scoring": scores,
            }

            # Save PDF to media/reports
            media_root = getattr(settings, "MEDIA_ROOT", "media") or "media"
            filename = f"report_{int(time.time())}.pdf"
            out_dir = os.path.join(media_root, "reports")
            out_path = os.path.join(out_dir, filename)
            try:
                pdf_path = generate_pdf(report, out_path)
                pdf_url = os.path.join(getattr(settings, "MEDIA_URL", "/media/"), "reports", filename)
            except Exception as e:
                pdf_path = None
                pdf_url = None

            # Save to DB only if user is authenticated
            detector_result = None
            if request.user.is_authenticated:
                detector_result = DetectorResult.objects.create(
                    user=request.user,
                    input_type=input_type,
                    input_data=input_data,
                    score=round(final_score, 2),
                    explanation=ai_out.get("reasoning", ""),
                    is_safe=not bool(ai_out.get("is_phishing", False)),
                )
                # attach generated PDF to FileField if exists
                if pdf_path and os.path.exists(pdf_path):
                    try:
                        with open(pdf_path, "rb") as f:
                            django_file = DjangoFile(f)
                            detector_result.report_file.save(filename, django_file, save=True)
                    except Exception:
                        # ignore file save failures but log in future (kept simple here)
                        pass

            response_data = {
                "classification": "phishing" if ai_out.get("is_phishing") else "benign",
                "score": round(final_score, 2),
                "explanation": ai_out.get("reasoning", ""),
                "saved": detector_result is not None,
                "result_id": detector_result.id if detector_result else None,
                "report_url": pdf_url,
            }

            return DRFResponse(response_data, status=HTTP_201_CREATED)
        else:
            # URL path: build minimal parsed/reputation and use analyze_parsed
            try:
                parsed = {"urls": [input_data], "domains": [], "ips": []}
                netloc = urlparse(input_data).netloc or input_data
                # strip port if present
                domain = netloc.split(":")[0]
                if domain:
                    parsed["domains"].append(domain)
            except Exception:
                parsed = {"urls": [input_data], "domains": [], "ips": []}

            # Reputation checks (only for found indicators)
            reputation = build_reputation(parsed, use_concurrency=True)

            try:
                ai_out = analyze_parsed(parsed, reputation)
            except Exception as e:
                return DRFResponse({"error": f"AI analysis error: {e}"}, status=HTTP_400_BAD_REQUEST)

            result = {
                "classification": "phishing" if ai_out.get("is_phishing") else "benign",
                "score": ai_out.get("confidence", 0),
                "explanation": ai_out.get("reasoning", ai_out.get("explanation", "")),
            }

            detector_result = None
            if request.user.is_authenticated:
                detector_result = DetectorResult.objects.create(
                    user=request.user,
                    input_type=input_type,
                    input_data=input_data,
                    score=result.get("score"),
                    explanation=result.get("explanation"),
                    is_safe=result.get("classification") == "benign",
                )

            response_data = {
                "classification": result.get("classification"),
                "score": result.get("score"),
                "explanation": result.get("explanation"),
                "saved": detector_result is not None,
                "result_id": detector_result.id if detector_result else None,
            }
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
        authentication_classes=[SessionAuthentication, JWTAuthentication],
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
            try:
                file_obj = result.report_file.open("rb")
                filename = result.report_file.name.split('/')[-1]
                response = FileResponse(file_obj, content_type="application/pdf")
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            except FileNotFoundError:
                # attempt to find a file in MEDIA_ROOT/reports with same numeric prefix
                import re
                import os
                media_root = getattr(settings, "MEDIA_ROOT", "media") or "media"
                reports_dir = os.path.join(media_root, "reports")
                base = result.report_file.name.split('/')[-1]
                m = re.search(r'report_(\d+)', base)
                prefix = f"report_{m.group(1)}" if m else os.path.splitext(base)[0]
                try:
                    for f in os.listdir(reports_dir):
                        if f.startswith(prefix) and f.lower().endswith('.pdf'):
                            alt_path = os.path.join(reports_dir, f)
                            af = open(alt_path, 'rb')
                            response = FileResponse(af, content_type='application/pdf')
                            response['Content-Disposition'] = f'attachment; filename="{f}"'
                            return response
                except Exception:
                    pass
                return DRFResponse({"error": "Report file not found on disk"}, status=HTTP_404_NOT_FOUND)
        except Exception as e:
            return DRFResponse(
                {"error": f"Failed to download report: {str(e)}"},
                status=HTTP_400_BAD_REQUEST,
            )