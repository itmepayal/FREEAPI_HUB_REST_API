# -------------------------
# Django / DRF Imports
# -------------------------
from rest_framework import generics, status, permissions
from rest_framework.views import APIView

# -------------------------
# App Imports
# -------------------------
from accounts.models import User
from accounts.serializers import Enable2FASerializer, Disable2FASerializer
from accounts.utils import generate_totp_qr_code
from core.utils import api_response, get_client_ip
from core.logger import get_logger
from core.tasks import log_security_event

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# Setup 2fa
# -------------------------
class Setup2FAView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return api_response(
                False,
                "2FA already enabled",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        totp_uri = user.generate_2fa_setup()
        qr_code = generate_totp_qr_code(totp_uri)

        logger.info(f"2FA setup initiated for user {user.id}")

        return api_response(
            True,
            "Scan QR code with Google Authenticator",
            data={"qr_code": qr_code}
        )

# -------------------------
# Enable 2fa
# -------------------------
class Enable2FAView(generics.GenericAPIView):
    serializer_class = Enable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]

        if user.verify_2fa_setup(token):
            logger.info(f"2FA enabled for user {user.id}")

            log_security_event.delay(
                user_id=user.id,
                event_type="2FA_ENABLED",
                ip_address=get_client_ip(request),
            )

            return api_response(True, "2FA enabled successfully")

        return api_response(
            False,
            "Invalid or expired TOTP",
            status_code=status.HTTP_400_BAD_REQUEST
        )


# -------------------------
# Disable 2fa
# -------------------------
class Disable2FAView(generics.GenericAPIView):
    serializer_class = Disable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.is_2fa_enabled:
            return api_response(
                False,
                "2FA not enabled",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]

        if user.verify_totp(token):
            user.is_2fa_enabled = False
            user.totp_secret = None

            user.save(update_fields=["is_2fa_enabled", "totp_secret"])

            logger.info(f"2FA disabled for user {user.id}")

            log_security_event.delay(
                user_id=user.id,
                event_type="2FA_DISABLED",
                ip_address=get_client_ip(request),
            )

            return api_response(True, "2FA disabled successfully")

        return api_response(
            False,
            "Invalid TOTP token",
            status_code=status.HTTP_400_BAD_REQUEST
        )
        