from rest_framework import serializers

# ----------------------------
# Health Serializer
# ----------------------------
class HealthCheckSerializer(serializers.Serializer):
    status = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)
