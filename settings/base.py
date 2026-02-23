import os

from settings.conf import *  # noqa: F403

# ----------------------------------------------------------------
# Path
#
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_URLCONF = 'settings.urls'
WSGI_APPLICATION = 'settings.wsgi.application'
ASGI_APPLICATION = 'settings.asgi.application'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'users.CustomUser'

# ----------------------------------------------------------------
# Apps
#

DJANGO_AND_THIRD_PARTY_APPS = [
    "unfold",
    "unfold.contrib.filters",
    "unfold.contrib.constance",
    "unfold.contrib.import_export",
    "unfold.contrib.guardian",
    "unfold.contrib.simple_history",
    "unfold.contrib.forms",
    "unfold.contrib.inlines",
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_spectacular',
]

PROJECT_APPS = [
    'apps.users.apps.UsersConfig',
    'apps.abstracts.apps.AbstractsConfig',
    'apps.detector.apps.DetectorConfig',
    'apps.frontend.apps.FrontendConfig',
]

INSTALLED_APPS = DJANGO_AND_THIRD_PARTY_APPS + PROJECT_APPS


# ----------------------------------------------------------------
# Middleware | Templates | Validators
#
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ----------------------------------------------------------------
# Encryption Configuration
#
# Fernet key for encrypting sensitive fields in DB. 
# Generate: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())
FERNET_KEY = os.getenv('FERNET_KEY', '')

# ----------------------------------------------------------------
# Internationalization
#

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ----------------------------------------------------------------
# REST Framework Configuration
#

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}


# ----------------------------------------------
# Static | Media
#
STATIC_URL = "static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")
MEDIA_URL = "media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")
