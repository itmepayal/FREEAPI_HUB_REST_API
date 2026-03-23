import os
import ssl
import redis
import dj_database_url
from pathlib import Path
from datetime import timedelta
from django.conf import settings
from decouple import Config, RepositoryEnv

# =====================================================
# ENVIRONMENT CONFIGURATION
# =====================================================
env_file = os.environ.get("ENV_FILE", default="")

if env_file and Path(env_file).exists():
    config = Config(repository=RepositoryEnv(env_file))
elif Path(".env.local").exists():
    config = Config(repository=RepositoryEnv(".env.local"))
elif Path(".env").exists():
    config = Config(repository=RepositoryEnv(".env"))
else:
    config = Config(repository=os.environ)

ENV = config("ENV", default="local")

# =====================================================
# BASE SETTINGS
# =====================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# =====================================================
# SECURITY SETTINGS
# =====================================================
SECRET_KEY = config(
    "SECRET_KEY",
    default="unsafe-secret-key" if ENV == "local" else None
)

DEBUG = config("DEBUG", default=False, cast=bool)

ALLOWED_HOSTS = [
    host.strip()
    for host in config(
        "ALLOWED_HOSTS",
        default="localhost,127.0.0.1,0.0.0.0"
    ).split(",")
]
# =====================================================
# REDIS CONFIGURATION
# =====================================================
REDIS_URL = config("REDIS_URL", default="").strip()

if not REDIS_URL and DEBUG:
    REDIS_URL = "redis://127.0.0.1:6379/1"

# =====================================================
# INSTALLED APPLICATIONS
# =====================================================
INSTALLED_APPS = [
    # ASGI server
    "daphne",

    # Django core apps
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party apps
    "corsheaders",
    "rest_framework",
    "drf_spectacular",
    "rest_framework_simplejwt.token_blacklist",
    "channels",

    # Local apps
    "accounts",
    "todo",
    "social",
    "shop",
    "chat",
    "public",
    "commands",
    "kitchen",
]

# =====================================================
# MIDDLEWARE CONFIGURATION
# =====================================================
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",

    "whitenoise.middleware.WhiteNoiseMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# =====================================================
# APPLICATION URL CONFIGURATION
# =====================================================
FRONTEND_URL = config("FRONTEND_URL", default="")
BACKEND_URL = config("BACKEND_URL", default="")

# =====================================================
# CORS SETTINGS
# =====================================================
CORS_ALLOW_CREDENTIALS = True

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
else:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://freeapi-auth-demo-rest-api.vercel.app",
    ]

# =====================================================
# AUTHENTICATION
# =====================================================
AUTH_USER_MODEL = "accounts.User"

# =====================================================
# DATABASE CONFIGURATION
# =====================================================
DATABASE_URL = config("DATABASE_URL", default="sqlite:///db.sqlite3")

print("DATABASE_URL:", DATABASE_URL) 

DATABASES = {
    "default": dj_database_url.parse(
        DATABASE_URL,
        conn_max_age=600,
        ssl_require=not DEBUG,
    )
}

# =====================================================
# CACHE CONFIGURATION (REDIS)
# =====================================================
if DEBUG:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            }
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {
                "ssl_cert_reqs": None  
                }
            }
        }
    }

# =====================================================
# SESSION CONFIGURATION
# =====================================================
SESSION_ENGINE = (
    "django.contrib.sessions.backends.db"
    if ENV == "local"
    else "django.contrib.sessions.backends.cached_db"
)

SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_AGE = 86400  

# =====================================================
# CHANNELS (WEBSOCKETS)
# =====================================================
ASGI_APPLICATION = "config.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{
                "address": REDIS_URL,
                "ssl": True,
            }],
        },
    },
}

# =====================================================
# DJANGO REST FRAMEWORK
# =====================================================
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "user": "1000/day",
    },
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# =====================================================
# JWT CONFIGURATION
# =====================================================
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# =====================================================
# EMAIL CONFIGURATION
# =====================================================
EMAIL_BACKEND = config("EMAIL_BACKEND", default="core.emails.SendGridBackend")
SENDGRID_API_KEY = config("SENDGRID_API_KEY", default="")
EMAIL_FROM = config("EMAIL_FROM", default="")

# =====================================================
# URL CONFIGURATION
# =====================================================
ROOT_URLCONF = "config.urls"

# =====================================================
# STATIC & MEDIA FILES
# =====================================================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# =====================================================
# DEFAULT PRIMARY KEY FIELD
# =====================================================
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# =====================================================
# CELERY CONFIGURATION (ASYNC TASKS)
# =====================================================
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL

CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"

if REDIS_URL.startswith("rediss://"):
    CELERY_BROKER_USE_SSL = {
        "ssl_cert_reqs": ssl.CERT_NONE
    }

    CELERY_REDIS_BACKEND_USE_SSL = {
        "ssl_cert_reqs": ssl.CERT_NONE
    }

if CELERY_BROKER_URL and CELERY_BROKER_URL.startswith("rediss://"):
    CELERY_BROKER_USE_SSL = {
        "ssl_cert_reqs": ssl.CERT_NONE
    }
    CELERY_RESULT_BACKEND_USE_SSL = {
        "ssl_cert_reqs": ssl.CERT_NONE
    }
    

# =====================================================
# CLOUDINARY CONFIGURATION (MEDIA STORAGE)
# =====================================================
CLOUDINARY_CLOUD_NAME = config("CLOUDINARY_CLOUD_NAME",  default="")
CLOUDINARY_API_KEY = config("CLOUDINARY_API_KEY",  default="")
CLOUDINARY_API_SECRET = config("CLOUDINARY_API_SECRET",  default="")

# =====================================================
# OAUTH CONFIGURATION 
# =====================================================
GOOGLE_CLIENT_ID=config("GOOGLE_CLIENT_ID",  default="")
GOOGLE_CLIENT_SECRET=config("GOOGLE_CLIENT_SECRET",  default="")
GOOGLE_REDIRECT_URI=config("GOOGLE_REDIRECT_URI",  default="")
GITHUB_CLIENT_ID=config("GITHUB_CLIENT_ID",  default="")
GITHUB_CLIENT_SECRET=config("GITHUB_CLIENT_SECRET",  default="")
GITHUB_REDIRECT_URI=config("GITHUB_REDIRECT_URI",  default="")

# =====================================================
# PAYMENT CONFIGURATION
# =====================================================
STRIPE_SECRET_KEY = config("STRIPE_SECRET_KEY",  default="")
STRIPE_PUBLIC_KEY = config("STRIPE_PUBLIC_KEY",  default="")

RAZORPAY_KEY_ID = config("RAZORPAY_KEY_ID",  default="")
RAZORPAY_KEY_SECRET = config("RAZORPAY_KEY_SECRET",  default="")

# =====================================================
# TEMPLATES CONFIGURATION
# =====================================================
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
# =====================================================
# TOTP (2FA) CONFIGURATION
# =====================================================
TOTP_ISSUER_NAME = config("TOTP_ISSUER_NAME", default="freeapi")