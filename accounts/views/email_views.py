# -------------------------
# Standard Library Imports
# -------------------------
import secrets
import hashlib
from datetime import timedelta

# -------------------------
# Django / DRF Imports
# -------------------------
from django.utils import timezone
from django.conf import settings
from rest_framework import generics, status, permissions

# -------------------------
# App Imports
# -------------------------
from accounts.models import User
from accounts.serializers import VerifyEmailSerializer, ResendEmailVerificationSerializer
from core.utils import api_response, get_client_ip, send_email
from core.logger import get_logger
from core.tasks import send_email_async, log_security_event
from core.redis_client import redis_client

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# Constants
# -------------------------
EMAIL_VERIFICATION_EXPIRY_MINUTES = 10
RESEND_COOLDOWN_SECONDS = 60 

# -------------------------
# Helpers
# -------------------------
def generate_email_token():
    """Generate raw + hashed email verification token"""
    raw_token = secrets.token_hex(20)
    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, hashed_token

def is_rate_limited(user_id):
    """Check Redis rate limit for resend"""
    key = f"resend_email:{str(user_id)}"
    if redis_client.get(key):
        return True
    redis_client.set(key, "1", ex=RESEND_COOLDOWN_SECONDS)
    return False

# -------------------------
# Verify Email
# -------------------------
class VerifyEmailView(generics.GenericAPIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        user = User.objects.filter(
            email_verification_token=hashed_token,
            email_verification_expiry__gt=timezone.now()
        ).first()

        if not user:
            return api_response(
                False,
                "Invalid or expired token",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expiry = None
        user.save(update_fields=[
            "is_verified",
            "email_verification_token",
            "email_verification_expiry"
        ])

        log_security_event.delay(
            user.id,
            "EMAIL_VERIFIED",
            ip_address=get_client_ip(request)
        )

        logger.info(f"Email verified for {user.email}")

        return api_response(True, "Email verified successfully")


# -------------------------
# Resend Email Verification
# -------------------------
class ResendEmailView(generics.GenericAPIView):
    serializer_class = ResendEmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        if not user.is_active:
            return api_response(
                False,
                "Account is inactive",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        if user.is_verified:
            return api_response(
                False,
                "Email already verified",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        if is_rate_limited(user.id):
            return api_response(
                False,
                "Too many requests. Please wait before retrying.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS
            )

        if (
            user.email_verification_expiry and
            user.email_verification_expiry > timezone.now()
        ):
            return api_response(
                False,
                "Verification email already sent. Please wait.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        raw_token, hashed_token = generate_email_token()

        user.email_verification_token = hashed_token
        user.email_verification_expiry = timezone.now() + timedelta(
            minutes=EMAIL_VERIFICATION_EXPIRY_MINUTES
        )
        user.save(update_fields=[
            "email_verification_token",
            "email_verification_expiry"
        ])

        verify_link = f"{settings.FRONTEND_URL}/verify-email/{raw_token}"
        
        send_email(
            user.email,
            "Verify your email",
            "email_verification",
            {"username": user.username, "verify_link": verify_link},
        )

        log_security_event.delay(
            user.id,
            "EMAIL_VERIFICATION_RESENT",
            ip_address=get_client_ip(request)
        )

        logger.info(f"Verification email resent to {user.email}")

        return api_response(True, "Verification email resent successfully.")
    