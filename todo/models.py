from django.db import models
from core.models import BaseModel  
from django.utils import timezone
from core.constants import PRIORITY_CHOICES, PRIORITY_MEDIUM
from datetime import timedelta
from accounts.models import User

# =============================================================
# TODO MODEL
# =============================================================
class Todo(BaseModel):
    # =============================================================
    # Basic Fields
    # =============================================================
    title = models.CharField(max_length=200, help_text="Title of the task")
    description = models.TextField(blank=True, null=True, help_text="Optional task description")
    completed = models.BooleanField(default=False, help_text="Whether the task is completed")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="todos")
    due_date = models.DateTimeField(blank=True, null=True, help_text="Optional task due date")
    priority = models.CharField(
        max_length=10, 
        choices=PRIORITY_CHOICES, 
        default=PRIORITY_MEDIUM, 
        help_text="Task priority"
    )
    expire_at = models.DateTimeField(null=True, blank=True, help_text="Auto-expiry timestamp for cleanup")  

    # =============================================================
    # Soft Delete Methods
    # =============================================================
    def soft_delete(self):
        """
        Marks the todo as deleted by setting deleted_at timestamp.
        """
        self.deleted_at = timezone.now()
        self.save()

    # =============================================================
    # Status Property
    # =============================================================
    @property
    def status(self):
        """
        Returns human-readable status of the todo.
        """
        return "Completed" if self.completed else "Pending"

    # =============================================================
    # Save Override
    # =============================================================
    def save(self, *args, **kwargs):
        """
        Sets expire_at to 7 days from now if not already set.
        """
        if self.expire_at is None:
            self.expire_at = timezone.now() + timedelta(days=7)  
        super().save(*args, **kwargs)
        
    # =============================================================
    # String Representation
    # =============================================================
    def __str__(self):
        return f"{self.title} ({self.priority})"

    # =============================================================
    # Meta Configuration
    # =============================================================
    class Meta:
        verbose_name = "Todo"
        verbose_name_plural = "Todos"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['due_date']),
            models.Index(fields=['priority']),
            models.Index(fields=['completed']),
        ]
