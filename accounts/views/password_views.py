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
from accounts.serializers import (
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    ChangePasswordSerializer,
)
from core.utils import api_response, get_client_ip, send_email
from core.logger import get_logger
from core.tasks import send_email_async, log_security_event
from core.redis_client import redis_client

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# Forgot Password
# -------------------------
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        rate_key = f"forgot_password:{email}"
        if redis_client.get(rate_key):
            return api_response(False, "Too many requests. Try again later.", status_code=429)
        redis_client.set(rate_key, "1", ex=60)

        user = User.objects.filter(email=email).first()

        if user and user.is_active:
            raw_token = secrets.token_hex(20)
            hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()

            user.forgot_password_token = hashed_token
            user.forgot_password_expiry = timezone.now() + timedelta(minutes=10)
            user.save(update_fields=["forgot_password_token", "forgot_password_expiry"])

            reset_link = f"{settings.FRONTEND_URL}/reset-password/{raw_token}"

            send_email(
                user.email,
                "Reset Password",
                "reset_password",
                {"username": user.username, "reset_link": reset_link},
            )

            log_security_event.delay(
                user_id=user.id,
                event_type="PASSWORD_RESET_REQUESTED",
                ip_address=get_client_ip(request),
            )

            logger.info(f"Password reset email sent to {user.email}")
        else:
            logger.warning(f"Password reset requested for invalid email: {email}")

        return api_response(True, "Reset link sent successfully.")

# -------------------------
# Reset Password
# -------------------------
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        user = User.objects.filter(
            forgot_password_token=hashed_token,
            forgot_password_expiry__gt=timezone.now()
        ).first()

        if not user:
            return api_response(False, "Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            return api_response(False, "Account inactive", status_code=status.HTTP_403_FORBIDDEN)

        user.set_password(new_password)

        redis_client.delete(f"auth:refresh:{str(user.id)}")

        user.forgot_password_token = None
        user.forgot_password_expiry = None

        user.save(update_fields=["password", "forgot_password_token", "forgot_password_expiry"])

        log_security_event.delay(
            user_id=user.id,
            event_type="PASSWORD_RESET_SUCCESS",
            ip_address=get_client_ip(request),
        )

        logger.info(f"Password reset successfully for {user.email}")

        return api_response(True, "Password reset successful")

# -------------------------
# Change Password
# -------------------------
class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        rate_key = f"change_password:{str(user.id)}"
        if redis_client.get(rate_key):
            return api_response(False, "Too many attempts. Try again later.", status_code=429)
        redis_client.set(rate_key, "1", ex=60)

        if not user.check_password(old_password):
            return api_response(False, "Old password is incorrect", status_code=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=["password"])

        redis_client.delete(f"auth:refresh:{str(user.id)}")

        log_security_event.delay(
            user_id=user.id,
            event_type="PASSWORD_CHANGED",
            ip_address=get_client_ip(request),
        )

        logger.info(f"Password changed for {user.email}")

        return api_response(True, "Password changed successfully")