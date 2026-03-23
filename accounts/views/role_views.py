# -------------------------
# Django / DRF Imports
# -------------------------
from rest_framework import generics, status, permissions
from django.db import transaction

# -------------------------
# App Imports
# -------------------------
from accounts.models import User
from accounts.serializers import ChangeRoleSerializer
from core.utils import api_response
from core.logger import get_logger
from core.permissions import IsSuperAdmin
from core.tasks import log_security_event
from accounts.utils import get_client_ip

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# Constants
# -------------------------
ALLOWED_ROLES = ["USER", "ADMIN", "SUPERADMIN"]


# -------------------------
# Change Role View
# -------------------------
class ChangeRoleView(generics.GenericAPIView):
    serializer_class = ChangeRoleSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def patch(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = serializer.validated_data["user_id"]
        new_role = serializer.validated_data["role"]
        
        if str(request.user.id) == str(user_id):
            return api_response(
                False,
                "SuperAdmin cannot change their own role.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if new_role not in ALLOWED_ROLES:
            return api_response(
                False,
                "Invalid role",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
            
        user = User.objects.filter(id=user_id, is_active=True).first()
        if not user:
            return api_response(
                False,
                "User not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        if user.role == "SUPERADMIN":
            return api_response(
                False,
                "Cannot change role of another SuperAdmin.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if user.role == new_role:
            return api_response(
                False,
                "User already has this role",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        old_role = user.role

        with transaction.atomic():
            user.role = new_role
            user.save(update_fields=["role"])

        log_security_event.delay(
            user_id=user.id,
            event_type="ROLE_CHANGED",
            ip_address=get_client_ip(request),
            metadata={
                "old_role": old_role,
                "new_role": new_role,
                "changed_by": str(request.user.id),
            },
        )

        logger.info(
            f"Role changed: {user.id} {old_role} to {new_role} by {request.user.id}"
        )

        return api_response(
            True,
            "Role updated successfully",
            data={"user_id": str(user.id), "role": user.role},
        )
