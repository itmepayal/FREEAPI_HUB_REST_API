from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.generics import GenericAPIView
from health.swagger import health_check_schema
from health.serializers import HealthCheckSerializer
from core.logger import get_logger

# =============================================================
# Logger
# =============================================================
logger = get_logger(__name__)

# ----------------------
# Health
# ----------------------
@health_check_schema
class HealthCheckView(GenericAPIView):
    serializer_class = HealthCheckSerializer
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        data = {"status": "ok", "message": "API is running"}
        serializer = self.get_serializer(data)
        logger.info("Health check successful")
        return Response(serializer.data, status=status.HTTP_200_OK)

