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
from apps.detector.services.reputation import ReputationService
from apps.detector.services.report import generate_pdf
from django.conf import settings
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.files import File as DjangoFile


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

        # Full pipeline: parse -> reputation checks -> AI -> scoring -> PDF report
        if input_type in ["text", "file"]:
            try:
                parsed = parse_email(input_data)
            except Exception as e:
                return DRFResponse({"error": f"Parsing error: {e}"}, status=HTTP_400_BAD_REQUEST)

            # Reputation checks (concurrent)
            rep_service = ReputationService()
            reputation = {"urls": {}, "domains": {}, "ips": {}}
            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = {}
                for u in parsed.get("urls", []):
                    futures[ex.submit(rep_service.check_url, u)] = ("url", u)
                for d in parsed.get("domains", []):
                    futures[ex.submit(rep_service.check_domain, d)] = ("domain", d)
                for ip in parsed.get("ips", []):
                    futures[ex.submit(rep_service.check_ip, ip)] = ("ip", ip)

                for fut in as_completed(futures):
                    kind, val = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {"error": str(e)}
                    if kind == "url":
                        reputation["urls"][val] = res
                    elif kind == "domain":
                        reputation["domains"][val] = res
                    else:
                        reputation["ips"][val] = res

            # Call AI on aggregated parsed+reputation
            try:
                ai_out = analyze_parsed(parsed, reputation)
            except Exception as e:
                return DRFResponse({"error": f"AI analysis error: {e}"}, status=HTTP_400_BAD_REQUEST)

            # Scoring: combine AI confidence, malicious IOC ratio, header anomaly score
            def _is_malicious(rep: dict) -> bool:
                try:
                    vt = rep.get("virustotal") or rep.get("virustotal_submit")
                    if isinstance(vt, dict):
                        data = vt.get("data") or vt
                        attrs = data.get("attributes") if isinstance(data, dict) else None
                        if attrs and isinstance(attrs, dict):
                            stats = attrs.get("last_analysis_stats") or {}
                            if isinstance(stats, dict) and int(stats.get("malicious", 0)) > 0:
                                return True
                    abuse = rep.get("abuseipdb") or {}
                    # abuseipdb returns data->abuseConfidenceScore
                    if isinstance(abuse, dict):
                        a_data = abuse.get("data") or {}
                        if isinstance(a_data, dict) and a_data.get("abuseConfidenceScore", 0) and int(a_data.get("abuseConfidenceScore", 0)) > 0:
                            return True
                except Exception:
                    return False
                return False

            total_indicators = 0
            malicious_count = 0
            for url, r in reputation["urls"].items():
                total_indicators += 1
                if _is_malicious(r):
                    malicious_count += 1
            for dom, r in reputation["domains"].items():
                total_indicators += 1
                if _is_malicious(r):
                    malicious_count += 1
            for ip, r in reputation["ips"].items():
                total_indicators += 1
                if _is_malicious(r):
                    malicious_count += 1

            malicious_ratio = (malicious_count / total_indicators) if total_indicators > 0 else 0.0

            ai_conf = float(ai_out.get("confidence", 0))
            # header anomaly: count non-pass results
            anomalies = 0
            checks = 0
            for field in ("spf", "dkim", "dmarc"):
                val = parsed.get(field)
                if val is not None:
                    checks += 1
                    if str(val).lower() != "pass":
                        anomalies += 1
            header_score = (anomalies / checks * 100) if checks > 0 else 0.0

            final_score = ai_conf * 0.5 + malicious_ratio * 100 * 0.3 + header_score * 0.2

            # Build report structure
            report = {
                "title": "Email Analysis Report",
                "summary": f"Final score: {final_score:.2f}",
                "parsed": parsed,
                "reputation": reputation,
                "ai": ai_out,
                "scoring": {"final_score": round(final_score, 2), "malicious_ratio": malicious_ratio, "header_score": header_score},
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
            rep_service = ReputationService()
            reputation = {"urls": {}, "domains": {}, "ips": {}}
            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = {}
                for u in parsed.get("urls", []):
                    futures[ex.submit(rep_service.check_url, u)] = ("url", u)
                for d in parsed.get("domains", []):
                    futures[ex.submit(rep_service.check_domain, d)] = ("domain", d)
                for ip in parsed.get("ips", []):
                    futures[ex.submit(rep_service.check_ip, ip)] = ("ip", ip)

                for fut in as_completed(futures):
                    kind, val = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {"error": str(e)}
                    if kind == "url":
                        reputation["urls"][val] = res
                    elif kind == "domain":
                        reputation["domains"][val] = res
                    else:
                        reputation["ips"][val] = res

            try:
                ai_out = analyze_parsed(parsed, reputation)
            except Exception as e:
                return DRFResponse({"error": f"AI analysis error: {e}"}, status=HTTP_400_BAD_REQUEST)

            result = {
                "classification": "malicious" if ai_out.get("is_phishing") else "benign",
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
            return response
        except Exception as e:
            return DRFResponse(
                {"error": f"Failed to download report: {str(e)}"},
                status=HTTP_400_BAD_REQUEST,
            )