# -------------------------
# Standard Library Imports
# -------------------------
import secrets
import hashlib
from datetime import timedelta

# -------------------------
# Django / DRF Imports
# -------------------------
from django.conf import settings
from django.utils import timezone
from rest_framework import generics, status, permissions
from rest_framework.views import APIView

# -------------------------
# JWT Imports
# -------------------------
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

# -------------------------
# App Imports
# -------------------------
from accounts.models import User, UserSession
from accounts.serializers import (
    RegisterSerializer,
    LoginSerializer,
    EmptySerializer,
    UserSerializer,
)
from accounts.utils import get_client_ip
from core.utils import api_response
from core.logger import get_logger
from core.utils import send_email
from core.redis_client import redis_client
from core.tasks import log_security_event, send_email_async

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# JWT Helpers
# -------------------------
def generate_jwt_tokens(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)

# -------------------------
# Register
# -------------------------
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()
        ip = get_client_ip(request)
        device = request.META.get("HTTP_USER_AGENT", "")

        log_security_event.delay(
            user_id=user.id,
            event_type="REGISTER",
            ip_address=ip,
            device=device
        )

        raw_token = secrets.token_hex(20)
        hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()

        user.email_verification_token = hashed_token
        user.email_verification_expiry = timezone.now() + timedelta(minutes=10)
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        verify_link = f"{settings.FRONTEND_URL}/verify-email/{raw_token}"

        logger.debug(f"Verification link generated for {user.email}")

        send_email(
            user.email,
            "Verify your email",
            "email_verification",
            {"username": user.username, "verify_link": verify_link},
        )

        return api_response(
            True,
            "User registered successfully. Please verify your email.",
            data={"user": UserSerializer(user).data},
            status_code=status.HTTP_201_CREATED,
        )

# -------------------------
# Login
# -------------------------
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        token = serializer.validated_data.get("token")

        ip = get_client_ip(request)
        device = request.META.get("HTTP_USER_AGENT", "")

        user = User.objects.filter(email=email).first()

        if not user or not user.check_password(password):
            if user:
                user_id = str(user.id)

                key = f"auth:login_fail:{user_id}"
                attempts = redis_client.incr(key)
                redis_client.expire(key, 300)

                if attempts >= 5:
                    redis_client.set(f"auth:locked:{str(user_id)}", "1", ex=300)

                log_security_event.delay(
                    user_id=user_id,
                    event_type="FAILED_LOGIN",
                    ip_address=ip,
                    device=device
                )

            return api_response(False, "Invalid credentials", status_code=status.HTTP_401_UNAUTHORIZED)

        user_id = str(user.id)

        if redis_client.get(f"auth:locked:{user_id}"):
            return api_response(False, "Account temporarily locked", status_code=status.HTTP_403_FORBIDDEN)

        if not user.is_active:
            return api_response(False, "Account is inactive", status_code=status.HTTP_403_FORBIDDEN)

        if not user.is_verified:
            return api_response(False, "Email not verified", status_code=status.HTTP_403_FORBIDDEN)

        if user.is_2fa_enabled:
            if not token or not user.verify_totp(token):
                return api_response(False, "Invalid or missing 2FA token", status_code=status.HTTP_400_BAD_REQUEST)

        redis_client.delete(f"auth:login_fail:{str(user_id)}")

        access_token, refresh_token = generate_jwt_tokens(user)

        redis_client.set(f"auth:refresh:{(str(user_id))}", refresh_token, ex=7 * 24 * 3600)
        redis_client.set(f"auth:refresh_map:{refresh_token}", user_id, ex=7 * 24 * 3600)

        session_token, session = UserSession.create_session(
            user=user,
            device=device,
            ip=ip
        )

        redis_client.set(f"session:{session.id}", session_token, ex=7 * 24 * 3600)

        log_security_event.delay(
            user_id=user_id,
            event_type="LOGIN_SUCCESS",
            ip_address=ip,
            device=device
        )

        return api_response(
            True,
            "Login successful",
            data={
                "user": UserSerializer(user).data,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "session_token": session_token,
            },
        )

# -------------------------
# Refresh Token
# -------------------------
class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return api_response(False, "Refresh token required", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            user_id = str(token["user_id"])
        except TokenError:
            return api_response(False, "Invalid or expired refresh token", status_code=status.HTTP_401_UNAUTHORIZED)

        stored_user = redis_client.get(f"auth:refresh_map:{refresh_token}")

        if not stored_user or stored_user != user_id:
            return api_response(False, "Token revoked or invalid", status_code=status.HTTP_401_UNAUTHORIZED)

        user = User.objects.filter(id=user_id).first()

        if not user:
            return api_response(False, "User not found", status_code=status.HTTP_404_NOT_FOUND)

        access_token = str(AccessToken.for_user(user))

        return api_response(
            True,
            "Token refreshed successfully",
            data={"access_token": access_token}
        )

# -------------------------
# Logout
# -------------------------
class LogoutView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        refresh_token = request.data.get("refresh_token")

        if refresh_token:
            redis_client.delete(f"auth:refresh_map:{refresh_token}")

        redis_client.delete(f"auth:refresh:{str(user.id)}")

        log_security_event.delay(
            user_id=user.id,
            event_type="LOGOUT",
            ip_address=get_client_ip(request)
        )

        return api_response(True, "Logged out successfully")

# -------------------------
# Current User
# -------------------------
class CurrentUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user