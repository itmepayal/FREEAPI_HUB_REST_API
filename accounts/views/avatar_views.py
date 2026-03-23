# -------------------------
# Django / DRF Imports
# -------------------------
from rest_framework import generics, status, permissions
from rest_framework.parsers import MultiPartParser, FormParser

# -------------------------
# App Imports
# -------------------------
from accounts.serializers import UpdateAvatarSerializer
from core.utils import api_response, get_client_ip
from core.logger import get_logger
from core.cloudinary import upload_to_cloudinary

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# Update Avatar
# -------------------------
class UpdateAvatarView(generics.GenericAPIView):
    serializer_class = UpdateAvatarSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file = serializer.validated_data["avatar"]
        user = request.user

        try:
            avatar_url = upload_to_cloudinary(file, folder="avatars")

            user.avatar = avatar_url
            user.save(update_fields=["avatar"])

            logger.info(
                f"Avatar updated | user_id={user.id} | email={user.email} | ip={get_client_ip(request)}"
            )

            return api_response(
                True,
                "Avatar updated successfully",
                data={"avatar": avatar_url}
            )

        except Exception as e:
            logger.error(
                f"Avatar upload failed | user_id={user.id} | error={str(e)}",
                exc_info=True
            )

            return api_response(
                False,
                "Error uploading avatar",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )