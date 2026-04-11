from decouple import Csv, config

from settings.base import *  # noqa

DEBUG = False
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv(), default="")
if not ALLOWED_HOSTS:
    raise ValueError("ALLOWED_HOSTS must be set in production.")
if "*" in ALLOWED_HOSTS:
    raise ValueError("Wildcard '*' is not allowed in ALLOWED_HOSTS for production.")

_DB_ENGINE = config("DB_ENGINE", default="")
_DB_NAME = config("DB_NAME", default="")
if not _DB_ENGINE:
    raise ValueError("DB_ENGINE must be set in production.")
if _DB_ENGINE == "django.db.backends.sqlite3":
    raise ValueError("SQLite is not allowed as the database engine in production.")
if not _DB_NAME:
    raise ValueError("DB_NAME must be set in production.")

DATABASES = {
    "default": {
        "ENGINE": _DB_ENGINE,
        "NAME": _DB_NAME,
    }
}

# Security hardening for production deployments.
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", cast=int, default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config("SECURE_HSTS_INCLUDE_SUBDOMAINS", cast=bool, default=True)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", cast=bool, default=True)
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", cast=bool, default=True)
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", cast=bool, default=True)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", cast=bool, default=True)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")