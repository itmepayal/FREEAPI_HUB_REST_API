from django.db import models
from django.utils import timezone
from core.models import BaseModel
from core.constants import ACTION_CHOICES

class SecurityLog(BaseModel):
    # =====================================================
    # FIELDS
    # =====================================================
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField()
    device = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    # =====================================================
    # STRING REPRESENTATION
    # =====================================================
    def __str__(self):
        return f"{self.user.email} - {self.action}"

    # =====================================================
    # META / INDEXES
    # =====================================================
    class Meta:
        indexes = [
            models.Index(fields=["user"]),      
            models.Index(fields=["timestamp"]), 
            models.Index(fields=["action"]), 
        ]
        ordering = ["-timestamp"] 
        