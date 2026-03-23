# -------------------------
# Standard Library Imports
# -------------------------
from django.utils import timezone

# -------------------------
# Django / DRF Imports
# -------------------------
from rest_framework import generics, permissions, status

# -------------------------
# App Imports
# -------------------------
from accounts.models import UserSession
from accounts.serializers import UserSessionSerializer
from core.utils import api_response, get_client_ip
from core.logger import get_logger
from core.tasks import log_security_event

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -----------------------------
# List all active sessions
# -----------------------------
class ListUserSessionsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSessionSerializer

    def get_queryset(self):
        return self.request.user.sessions.filter(expiry__gt=timezone.now())

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        return api_response(
            True,
            "Active sessions fetched successfully.",
            serializer.data,
        )


# -----------------------------
# Revoke a single session
# -----------------------------
class RevokeUserSessionView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSessionSerializer
    lookup_field = "id"

    def get_queryset(self):
        return self.request.user.sessions.filter(expiry__gt=timezone.now())

    def destroy(self, request, *args, **kwargs):
        session = self.get_object()

        session_id = session.id
        session.delete()

        logger.info(f"Session revoked: {session_id} by user {request.user.id}")

        log_security_event.delay(
            user_id=request.user.id,
            event_type="SESSION_REVOKED",
            ip_address=get_client_ip(request),
            metadata={"session_id": str(session_id)},
        )

        return api_response(True, "Session revoked successfully.")


# -----------------------------
# Revoke all other sessions
# -----------------------------
class RevokeOtherSessionsView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return api_response(
                False,
                "Invalid or missing token",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        current_token = auth_header.split(" ")[1]
        hashed_token = UserSession.hash_token(current_token)

        queryset = request.user.sessions.filter(expiry__gt=timezone.now())
        deleted_count = queryset.exclude(token_hash=hashed_token).delete()[0]

        logger.info(
            f"{deleted_count} sessions revoked (others) for user {request.user.id}"
        )

        log_security_event.delay(
            user_id=request.user.id,
            event_type="OTHER_SESSIONS_REVOKED",
            ip_address=get_client_ip(request),
            metadata={"revoked_count": deleted_count},
        )

        return api_response(
            True,
            f"{deleted_count} other sessions revoked successfully.",
        )


# -----------------------------
# Revoke all sessions
# -----------------------------
class RevokeAllSessionsView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        queryset = request.user.sessions.filter(expiry__gt=timezone.now())
        deleted_count = queryset.delete()[0]

        logger.info(
            f"All sessions revoked for user {request.user.id} (count={deleted_count})"
        )

        log_security_event.delay(
            user_id=request.user.id,
            event_type="ALL_SESSIONS_REVOKED",
            ip_address=get_client_ip(request),
            metadata={"revoked_count": deleted_count},
        )

        return api_response(
            True,
            f"All {deleted_count} sessions revoked. Please login again.",
        )
    