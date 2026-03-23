from rest_framework import serializers
from django.utils import timezone
from drf_spectacular.utils import extend_schema_field
from todo.models import Todo

# =============================================================
# Status Mixin
# =============================================================
class TodoStatusMixin(serializers.ModelSerializer):
    """Provides a computed 'status' field for Todos"""
    status = serializers.SerializerMethodField()

    @extend_schema_field(serializers.CharField())
    def get_status(self, obj) -> str:
        return "Completed" if obj.completed else "Pending"


# =============================================================
# List / Retrieve
# =============================================================
class TodoSerializer(TodoStatusMixin):
    """Serializer for listing and retrieving Todos"""
    class Meta:
        model = Todo
        fields = [
            "id", "title", "description", "completed", "due_date", "priority",
            "status", "created_at", "updated_at"
        ]
        read_only_fields = fields


# =============================================================
# Create / Update
# =============================================================
class TodoCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating Todos"""

    class Meta:
        model = Todo
        fields = ["title", "description", "completed", "due_date", "priority"]

    def validate_due_date(self, value):
        """Ensure due date is not in the past"""
        if value and value < timezone.now():
            raise serializers.ValidationError("Due date cannot be in the past.")
        return value


class TodoUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating Todos"""

    class Meta:
        model = Todo
        fields = ["title", "description", "completed", "due_date", "priority"]


class TodoPartialUpdateSerializer(serializers.ModelSerializer):
    """Serializer for partially updating Todos"""

    class Meta:
        model = Todo
        fields = ["title", "description", "completed", "due_date", "priority"]
        extra_kwargs = {field: {"required": False} for field in fields}


# =============================================================
# Responses for Soft Delete / Restore / Toggle
# =============================================================
class TodoSoftDeleteResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField(help_text="Todo ID")
    message = serializers.CharField(help_text="Soft delete confirmation")


class TodoRestoreResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField(help_text="Todo ID")
    message = serializers.CharField(help_text="Restore confirmation")


class ToggleStatusResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField(help_text="Todo ID")
    completed = serializers.BooleanField(help_text="Current completion status")
