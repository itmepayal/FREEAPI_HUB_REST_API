import pytest
from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers
from todo.serializers import (
    TodoSerializer,
    TodoCreateSerializer,
    TodoUpdateSerializer,
    TodoPartialUpdateSerializer,
)
from .factories import TodoFactory, UserFactory

@pytest.mark.django_db
class TestTodoSerializers:
    """Integration tests for all Todo serializers"""

    # =============================================================
    # List / Retrieve Serializer (TodoSerializer)
    # =============================================================
    def test_todo_serializer_output(self):
        """TodoSerializer should contain all required fields"""
        todo = TodoFactory(completed=False)
        serializer = TodoSerializer(todo)
        data = serializer.data

        expected_fields = [
            "id", "title", "description", "completed", "due_date",
            "priority", "status", "created_at", "updated_at"
        ]
        for field in expected_fields:
            assert field in data

        assert data["status"] == "Pending"

    def test_todo_serializer_status_completed(self):
        """TodoSerializer should show 'Completed' if completed=True"""
        todo = TodoFactory(completed=True)
        serializer = TodoSerializer(todo)
        assert serializer.data["status"] == "Completed"

    # =============================================================
    # Create Serializer (TodoCreateSerializer)
    # =============================================================
    def test_todo_create_serializer_valid_data(self):
        """TodoCreateSerializer accepts valid input"""
        payload = {
            "title": "New Todo Task",
            "description": "This is a test todo item",
            "completed": False,
            "priority": "Medium",
            "due_date": timezone.now() + timedelta(days=1),
        }
        serializer = TodoCreateSerializer(data=payload)
        assert serializer.is_valid(), serializer.errors

    def test_todo_create_serializer_invalid_data(self):
        """TodoCreateSerializer rejects invalid input"""
        payload = {"title": "", "priority": "Invalid"}
        serializer = TodoCreateSerializer(data=payload)
        assert not serializer.is_valid()
        assert "title" in serializer.errors

    def test_todo_create_serializer_due_date_in_past(self):
        """TodoCreateSerializer should reject past due_date"""
        payload = {
            "title": "Old Todo",
            "description": "Test past due date",
            "completed": False,
            "priority": "Medium",
            "due_date": timezone.now() - timedelta(days=1),
        }
        serializer = TodoCreateSerializer(data=payload)
        assert not serializer.is_valid()
        assert "due_date" in serializer.errors

    # =============================================================
    # Update Serializer (TodoUpdateSerializer)
    # =============================================================
    def test_todo_update_serializer(self):
        """TodoUpdateSerializer allows valid updates"""
        todo = TodoFactory()
        payload = {
            "title": "Updated Title",
            "description": "Updated description",
            "completed": True,
            "priority": "High",
        }
        serializer = TodoUpdateSerializer(instance=todo, data=payload)
        assert serializer.is_valid(), serializer.errors

    # =============================================================
    # Partial Update Serializer (TodoPartialUpdateSerializer)
    # =============================================================
    def test_todo_partial_update_serializer(self):
        """TodoPartialUpdateSerializer allows partial updates"""
        todo = TodoFactory()
        payload = {"title": "Partial Update"}
        serializer = TodoPartialUpdateSerializer(instance=todo, data=payload, partial=True)
        assert serializer.is_valid(), serializer.errors
