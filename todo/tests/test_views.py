import pytest
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from todo.models import Todo
from .factories import TodoFactory, UserFactory

@pytest.mark.django_db
class TestTodoViewSet(APITestCase):
    """Integration tests for TodoViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.client.force_authenticate(user=self.user)
        self.todo = TodoFactory(owner=self.user)
        self.list_url = reverse("todo:todo-list")
        self.detail_url = reverse("todo:todo-detail", kwargs={"pk": self.todo.id})

    # =============================================================
    # LIST
    # =============================================================
    def test_list_todos(self):
        """Test listing todos"""
        response = self.client.get(self.list_url)

        assert response.status_code == status.HTTP_200_OK
        assert "results" in response.data

    # =============================================================
    # RETRIEVE
    # =============================================================
    def test_retrieve_todo(self):
        """Test retrieving a single todo"""
        response = self.client.get(self.detail_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo retrieved successfully"
        assert "data" in response.data
        assert response.data["data"]["id"] == str(self.todo.id)

    # =============================================================
    # CREATE
    # =============================================================
    def test_create_todo(self):
        """Test creating a new todo"""
        payload = {
            "title": "New Test Todo",
            "description": "New description",
            "completed": False,
            "priority": "Medium"
        }
        response = self.client.post(self.list_url, payload, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["message"] == "Todo created successfully"
        assert "data" in response.data
        assert response.data["data"]["title"] == "New Test Todo"

    # =============================================================
    # UPDATE
    # =============================================================
    def test_update_todo(self):
        """Test updating a todo"""
        payload = {
            "title": "Updated Title",
            "description": "Updated description",
            "completed": True,
            "priority": "High"
        }
        response = self.client.put(self.detail_url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo updated successfully"
        assert response.data["data"]["title"] == "Updated Title"
        self.todo.refresh_from_db()
        assert self.todo.title == "Updated Title"

    # =============================================================
    # PARTIAL UPDATE
    # =============================================================
    def test_partial_update_todo(self):
        """Test partially updating a todo"""
        payload = {"title": "Partially Updated Title"}
        response = self.client.patch(self.detail_url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo partially updated successfully"
        self.todo.refresh_from_db()
        assert self.todo.title == "Partially Updated Title"

    # =============================================================
    # SOFT DELETE
    # =============================================================
    def test_soft_delete_todo(self):
        """Test soft deleting a todo"""
        soft_delete_url = reverse("todo:todo-soft-delete", kwargs={"pk": self.todo.id})
        response = self.client.delete(soft_delete_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo deleted successfully"
        self.todo.refresh_from_db()
        assert self.todo.deleted_at is not None

    # =============================================================
    # RESTORE
    # =============================================================
    def test_restore_todo(self):
        """Test restoring a soft-deleted todo"""
        self.todo.soft_delete()
        restore_url = reverse("todo:todo-restore", kwargs={"pk": self.todo.id})
        response = self.client.post(restore_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo restored successfully"
        self.todo.refresh_from_db()
        assert self.todo.deleted_at is None

    # =============================================================
    # TOGGLE STATUS
    # =============================================================
    def test_toggle_status(self):
        """Test toggling todo status"""
        toggle_url = reverse("todo:todo-toggle-status", kwargs={"pk": self.todo.id})
        response = self.client.patch(toggle_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "Todo status toggled successfully"
        self.todo.refresh_from_db()
        assert self.todo.completed is True

    # =============================================================
    # AUTH REQUIRED
    # =============================================================
    def test_authentication_required(self):
        """Test that authentication is required"""
        self.client.force_authenticate(user=None)
        response = self.client.get(self.list_url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # =============================================================
    # ACCESS CONTROL
    # =============================================================
    def test_user_can_only_see_own_todos(self):
        """Test user can only access their own todos"""
        other_user = UserFactory()
        other_todo = TodoFactory(owner=other_user)

        response = self.client.get(self.list_url)
        todo_ids = [todo["id"] for todo in response.data["results"]]

        assert str(other_todo.id) not in todo_ids
        assert str(self.todo.id) in todo_ids


# =============================================================
# FILTERS & SEARCH
# =============================================================
@pytest.mark.django_db
class TestTodoViewSetFilters(APITestCase):
    """Test filtering and searching functionality"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.client.force_authenticate(user=self.user)

        self.todo1 = TodoFactory(owner=self.user, completed=True, priority="High")
        self.todo2 = TodoFactory(owner=self.user, completed=False, priority="Medium")
        self.todo3 = TodoFactory(owner=self.user, completed=False, priority="Low")

        self.list_url = reverse("todo:todo-list")

    def test_filter_by_completed(self):
        """Test filtering by completed status"""
        response = self.client.get(self.list_url, {"completed": "true"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1

    def test_filter_by_priority(self):
        """Test filtering by priority"""
        response = self.client.get(self.list_url, {"priority": "High"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1

    def test_search_by_title(self):
        """Test searching by title"""
        unique_title = "Unique Searchable Title"
        TodoFactory(owner=self.user, title=unique_title)

        response = self.client.get(self.list_url, {"search": "Unique"})
        assert response.status_code == status.HTTP_200_OK
        assert any("Unique" in todo["title"] for todo in response.data["results"])

    def test_ordering(self):
        """Test ordering functionality"""
        response = self.client.get(self.list_url, {"ordering": "created_at"})
        assert response.status_code == status.HTTP_200_OK
