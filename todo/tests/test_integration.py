import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from todo.models import Todo
from .factories import UserFactory, TodoFactory

@pytest.mark.django_db
class TestTodoAPIWorkflow(APITestCase):
    """End-to-end API workflow tests for TodoViewSet"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.client.force_authenticate(user=self.user)
        self.base_url = reverse("todo:todo-list")

    # =============================================================
    # CREATE
    # =============================================================
    def test_create_todo(self):
        payload = {
            "title": "New Test Todo",
            "description": "This is a new test todo",
            "priority": "Medium",
        }
        response = self.client.post(self.base_url, payload, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["message"] == "Todo created successfully"
        assert "id" in response.data["data"]
        assert response.data["data"]["title"] == payload["title"]

    # =============================================================
    # LIST
    # =============================================================
    def test_list_todos(self):
        TodoFactory.create_batch(3, owner=self.user)
        response = self.client.get(self.base_url)

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data["results"], list)
        assert len(response.data["results"]) == 3

    # =============================================================
    # RETRIEVE
    # =============================================================
    def test_retrieve_todo(self):
        todo = TodoFactory(owner=self.user)
        detail_url = reverse("todo:todo-detail", kwargs={"pk": todo.id})

        response = self.client.get(detail_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["data"]["id"] == str(todo.id)
        assert response.data["data"]["title"] == todo.title

    # =============================================================
    # UPDATE
    # =============================================================
    def test_update_todo(self):
        todo = TodoFactory(owner=self.user)
        detail_url = reverse("todo:todo-detail", kwargs={"pk": todo.id})
        payload = {"title": "Updated Title", "priority": "High"}

        response = self.client.put(detail_url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo updated successfully"
        assert response.data["data"]["title"] == "Updated Title"

    # =============================================================
    # PARTIAL UPDATE
    # =============================================================
    def test_partial_update_todo(self):
        todo = TodoFactory(owner=self.user)
        detail_url = reverse("todo:todo-detail", kwargs={"pk": todo.id})
        payload = {"completed": True}

        response = self.client.patch(detail_url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo partially updated successfully"
        assert response.data["data"]["completed"] is True

    # =============================================================
    # TOGGLE STATUS
    # =============================================================
    def test_toggle_status(self):
        todo = TodoFactory(owner=self.user, completed=False)
        toggle_url = reverse("todo:todo-toggle-status", kwargs={"pk": todo.id})

        response = self.client.patch(toggle_url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo status toggled successfully"
        assert response.data["data"]["completed"] is True  # flipped to True

    # =============================================================
    # SOFT DELETE
    # =============================================================
    def test_soft_delete_todo(self):
        todo = TodoFactory(owner=self.user)
        delete_url = reverse("todo:todo-soft-delete", kwargs={"pk": todo.id})

        response = self.client.delete(delete_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo deleted successfully"

        # Ensure soft-deleted
        todo.refresh_from_db()
        assert todo.deleted_at is not None

    # =============================================================
    # RESTORE
    # =============================================================
    def test_restore_todo(self):
        todo = TodoFactory(owner=self.user)
        todo.soft_delete()
        restore_url = reverse("todo:todo-restore", kwargs={"pk": todo.id})

        response = self.client.post(restore_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo restored successfully"

        todo.refresh_from_db()
        assert todo.deleted_at is None

    # =============================================================
    # COMPLETE CRUD WORKFLOW
    # =============================================================
    def test_complete_todo_workflow(self):
        """Full workflow: create → retrieve → update → toggle → delete → restore"""
        payload = {
            "title": "Workflow Test Todo",
            "description": "Testing full CRUD workflow",
            "priority": "Medium",
        }

        # Create
        create_res = self.client.post(self.base_url, payload, format="json")
        assert create_res.status_code == status.HTTP_201_CREATED
        todo_id = create_res.data["data"]["id"]

        # Retrieve
        detail_url = reverse("todo:todo-detail", kwargs={"pk": todo_id})
        get_res = self.client.get(detail_url)
        assert get_res.status_code == status.HTTP_200_OK

        # Update
        update_res = self.client.put(detail_url, {"title": "Updated Workflow"}, format="json")
        assert update_res.status_code == status.HTTP_200_OK

        # Toggle
        toggle_url = reverse("todo:todo-toggle-status", kwargs={"pk": todo_id})
        toggle_res = self.client.patch(toggle_url, format="json")
        assert toggle_res.status_code == status.HTTP_200_OK

        # Soft Delete
        delete_url = reverse("todo:todo-soft-delete", kwargs={"pk": todo_id})
        del_res = self.client.delete(delete_url)
        assert del_res.status_code == status.HTTP_200_OK

        # Restore
        restore_url = reverse("todo:todo-restore", kwargs={"pk": todo_id})
        restore_res = self.client.post(restore_url)
        assert restore_res.status_code == status.HTTP_200_OK
