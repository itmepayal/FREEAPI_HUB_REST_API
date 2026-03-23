import random
from rest_framework.views import APIView
from rest_framework import status, permissions
from todos.models import Todo
from core.utils import api_response
from django.utils import timezone
from datetime import timedelta


class SeedTodosView(APIView):
    permission_classes = [permissions.AllowAny]
    """
    Create sample todos for testing or demo purposes.
    """

    def post(self, request):
        count = int(request.data.get("count", 10)) 

        sample_titles = [
            "Buy groceries", "Walk the dog", "Finish project", "Read a book",
            "Exercise", "Call friend", "Clean room", "Write blog post", "Cook dinner"
        ]
        priorities = ["Low", "Medium", "High"]

        todos_created = []
        for _ in range(count):
            todo = Todo.objects.create(
                title=random.choice(sample_titles),
                description="This is a sample todo",
                priority=random.choice(priorities),
                due_date=timezone.now() + timedelta(days=random.randint(1, 10))  
            )
            todos_created.append({
                "id": str(todo.id),
                "title": todo.title,
                "priority": todo.priority,
                "completed": todo.completed,
            })

        return api_response(
            True,
            f"{count} todos inserted successfully",
            todos_created,
            status.HTTP_201_CREATED
        )
