import pytest
from django.utils import timezone
from todo.models import Todo
from .factories import TodoFactory, UserFactory
from core.constants import PRIORITY_MEDIUM

@pytest.mark.django_db
class TestTodoModel:
    """Unit tests for Todo model"""
    def test_todo_creation(self):
        todo = TodoFactory()
        assert todo.title.startswith("Test Todo")
        assert todo.completed is False
        assert todo.owner is not None
        assert todo.priority == PRIORITY_MEDIUM
    
    def test_soft_delete(self):
        todo = TodoFactory()
        assert todo.deleted_at is None
        todo.soft_delete()
        assert todo.deleted_at is not None
    
    def test_restore_method(self):
        todo = TodoFactory()
        todo.soft_delete()
        todo.deleted_at = None
        todo.save()
        assert todo.deleted_at is None
    
    def test_status_property(self):
        todo = TodoFactory(completed=False)
        assert todo.status == "Pending"
        todo.completed = True
        assert todo.status == "Completed"
        
    def test_save_method_sets_expire_at(self):
        todo = TodoFactory(expire_at=None)
        todo.save()
        assert todo.expire_at is not None
        assert todo.expire_at > timezone.now()
    
    def test_string_representation(self):
        todo = TodoFactory(title="Test Task", priority="high")
        s = str(todo)
        assert "Test Task" in s
        assert "high" in s
    
    def test_meta_ordering(self):
        todo1 = TodoFactory()
        todo2 = TodoFactory()
        
        todos = Todo.objects.all()
        assert todos[0] == todo2  
        assert todos[1] == todo1
    