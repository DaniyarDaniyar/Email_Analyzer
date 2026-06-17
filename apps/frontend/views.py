# Django modules
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# Project modules
from apps.detector.services.file_service import extract_text_from_pdf, extract_text_from_txt, extract_text_from_eml
from apps.detector.models import DetectorResult
from apps.users.serializers import UserRegisterSerializer
from apps.detector.services.pipeline import run_sync_scan

# Python modules
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
                lower_name = str(f.name).lower()
                if lower_name.endswith('.pdf'):
                    input_data = extract_text_from_pdf(f)
                elif lower_name.endswith('.eml'):
                    input_data = extract_text_from_eml(f)
                else:
                    input_data = extract_text_from_txt(f)
            else:
                messages.error(request, 'Unknown input type')
                return redirect('index')
        except Exception as e:
            messages.error(request, f'File error: {e}')
            return redirect('index')

        try:
            result = run_sync_scan(
                input_type,
                input_data,
                user=request.user if request.user.is_authenticated else None,
                request=request,
                use_concurrency=True,
            )
        except Exception as e:
            messages.error(request, f'Analysis error: {e}')
            return redirect('index')

    return render(request, 'frontend/index.html', {'result': result})


@login_required
def history(request):
    """Show paginated history of user's scans."""
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
    """Show registration form and handle user registration."""
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
    """Show login form and handle user authentication."""
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
