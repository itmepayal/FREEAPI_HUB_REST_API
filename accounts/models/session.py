import secrets
import hashlib
from datetime import timedelta
from django.db import models
from django.utils import timezone
from core.models import BaseModel

class UserSession(BaseModel):
    user = models.ForeignKey("User", on_delete=models.CASCADE, related_name="sessions")
    token_hash = models.CharField(max_length=64)
    expiry = models.DateTimeField()
    device = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    # =====================================================
    # TOKEN HASHING
    # =====================================================
    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    # =====================================================
    # CREATE SESSION
    # =====================================================
    @classmethod
    def create_session(cls, user, device=None, ip=None):
        token = secrets.token_urlsafe(64)
        session = cls.objects.create(
            user=user,
            token_hash=cls.hash_token(token),
            expiry=timezone.now() + timedelta(days=7),
            device=device,
            ip_address=ip,
        )
        return token, session

    # =====================================================
    # VERIFY TOKEN
    # =====================================================
    def verify(self, token):
        if timezone.now() > self.expiry:
            return False
        return self.token_hash == self.hash_token(token)

    class Meta:
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["expiry"]),
        ]
        ordering = ["-expiry"]
        