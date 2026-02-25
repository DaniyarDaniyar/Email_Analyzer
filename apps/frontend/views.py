from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods

from apps.detector.services.ai_service import analyze_parsed
from urllib.parse import urlparse
from apps.detector.services.file_service import extract_text_from_pdf, extract_text_from_txt
from apps.detector.models import DetectorResult
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from apps.users.models import CustomUser
from apps.users.serializers import UserRegisterSerializer
from apps.detector.services.parser import parse_email
from apps.detector.services.analysis import build_reputation, compute_scores
from apps.detector.services.report import generate_pdf
from apps.detector.services.reputation import ReputationService
from django.conf import settings
from django.core.files import File as DjangoFile
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


@require_http_methods(["GET", "POST"])
def index(request):
    """Show scan form and handle scan submissions."""
    result = None
    if request.method == 'POST':
        input_type = request.POST.get('input_type')
        try:
            if input_type == 'text':
                input_data = request.POST.get('input_data', '').strip()
            elif input_type == 'url':
                input_data = request.POST.get('input_data', '').strip()
            elif input_type == 'file':
                f = request.FILES.get('file')
                if not f:
                    messages.error(request, 'File is required')
                    return redirect('index')
                if str(f.name).lower().endswith('.pdf'):
                    input_data = extract_text_from_pdf(f)
                else:
                    input_data = extract_text_from_txt(f)
            else:
                messages.error(request, 'Unknown input type')
                return redirect('index')
        except Exception as e:
            messages.error(request, f'File error: {e}')
            return redirect('index')

        # Full pipeline: parse -> reputation checks -> AI -> scoring -> PDF report
        if input_type in ['text', 'file']:
            try:
                parsed = parse_email(input_data)
            except Exception as e:
                messages.error(request, f'Parsing error: {e}')
                return redirect('index')

            # Reputation checks (concurrent)
            reputation = build_reputation(parsed, use_concurrency=True)

            # Call AI on aggregated parsed+reputation
            try:
                ai_out = analyze_parsed(parsed, reputation)
            except Exception as e:
                messages.error(request, f'AI analysis error: {e}')
                return redirect('index')

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
            pdf_path = None
            pdf_url = None
            try:
                pdf_path = generate_pdf(report, out_path)
                pdf_url = os.path.join(getattr(settings, "MEDIA_URL", "/media/"), "reports", filename)
            except Exception as e:
                pass

            # save if authenticated
            detector_obj = None
            if request.user.is_authenticated:
                detector_obj = DetectorResult.objects.create(
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
                            detector_obj.report_file.save(filename, django_file, save=True)
                    except Exception:
                        pass

            result = {
                'classification': "phishing" if ai_out.get("is_phishing") else "benign",
                'score': round(final_score, 2),
                'explanation': ai_out.get("reasoning", ""),
                'saved': detector_obj is not None,
                'result_id': detector_obj.id if detector_obj else None,
                'report_url': pdf_url,
            }
        else:
            # URL path: build minimal parsed/reputation and use analyze_parsed
            try:
                parsed = {"urls": [input_data], "domains": [], "ips": []}
                netloc = urlparse(input_data).netloc or input_data
                domain = netloc.split(":")[0]
                if domain:
                    parsed["domains"].append(domain)
            except Exception:
                parsed = {"urls": [input_data], "domains": [], "ips": []}

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
                messages.error(request, f'AI analysis error: {e}')
                return redirect('index')

            detector_obj = None
            if request.user.is_authenticated:
                detector_obj = DetectorResult.objects.create(
                    user=request.user,
                    input_type=input_type,
                    input_data=input_data,
                    score=ai_out.get('confidence', 0),
                    explanation=ai_out.get('reasoning', ai_out.get('explanation', '')),
                    is_safe=not bool(ai_out.get('is_phishing', False)),
                )

            result = {
                'classification': 'phishing' if ai_out.get('is_phishing') else 'benign',
                'score': ai_out.get('confidence', 0),
                'explanation': ai_out.get('reasoning', ai_out.get('explanation', '')),
                'saved': detector_obj is not None,
                'result_id': detector_obj.id if detector_obj else None,
            }

    return render(request, 'frontend/index.html', {'result': result})


@login_required
def history(request):
    qs = DetectorResult.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(qs, 10)
    page = request.GET.get('page')
    try:
        items = paginator.page(page)
    except PageNotAnInteger:
        items = paginator.page(1)
    except EmptyPage:
        items = paginator.page(paginator.num_pages)

    start_index = items.start_index()
    context = {
        'items': items,  # Page object is iterable
        'page_obj': items,
        'paginator': paginator,
        'is_paginated': items.has_other_pages(),
        'start_index': start_index,
    }
    return render(request, 'frontend/history.html', context)


@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.method == 'POST':
        data = {
            "email": request.POST.get('email'),
            "username": request.POST.get('username'),
            "first_name": request.POST.get('first_name') or "",
            "last_name": request.POST.get('last_name') or "",
            "password": request.POST.get('password'),
            "password2": request.POST.get('password2'),
        }

        serializer = UserRegisterSerializer(data=data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                user = authenticate(request, username=data["email"], password=data["password"])
                if user:
                    login(request, user)
                    messages.success(request, 'Registered and logged in')
                    return redirect('index')
                messages.error(request, 'Registration successful, but automatic login failed')
            except Exception as e:
                messages.error(request, f'Registration error: {e}')
        else:
            # Show first error message in flash, rest will be visible on the form if rendered
            errors = []
            for field, msgs in serializer.errors.items():
                if isinstance(msgs, (list, tuple)):
                    errors.extend(msgs)
                else:
                    errors.append(str(msgs))
            if errors:
                messages.error(request, errors[0])

        return redirect('register')

    return render(request, 'frontend/register.html')


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user:
            login(request, user)
            messages.success(request, 'Logged in')
            return redirect('index')
        messages.error(request, 'Invalid credentials')
        return redirect('login')
    return render(request, 'frontend/login.html')


def logout_view(request):
    logout(request)
    return redirect('index')
