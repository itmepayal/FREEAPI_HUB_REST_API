import uuid
from django.db import models
from django.utils import timezone
from accounts.models import User
from core.models import BaseModel
from core.constants import (
    CHAT_TYPE_CHOICES,
    PARTICIPANT_ROLE_CHOICES,
    MESSAGE_TYPE_CHOICES,
    MESSAGE_STATUS_CHOICES,
)

# =============================================================
# CHAT MODEL
# =============================================================
class Chat(BaseModel):
    """
    Represents a private or group chat.
    """

    name = models.CharField(max_length=255, blank=True, null=True)
    chat_type = models.CharField(
        max_length=10, choices=CHAT_TYPE_CHOICES, default="private"
    )
    owner = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_chats",
    )
    participants = models.ManyToManyField(User, through="Participant", related_name="chats")
    last_message = models.ForeignKey(
        "Message", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    def __str__(self):
        if self.chat_type == "private":
            return f"Private Chat ({self.id})"
        return self.name or f"Group Chat ({self.id})"

    # -------------------------------
    # HELPER METHODS
    # -------------------------------
    def has_participant(self, user):
        return self.participants.filter(id=user.id).exists()

    def add_participant(self, user, role="member"):
        Participant.objects.get_or_create(chat=self, user=user, defaults={"role": role})

    def remove_participant(self, user):
        Participant.objects.filter(chat=self, user=user).delete()

    @property
    def total_participants(self):
        return self.participants.count()


# =============================================================
# PARTICIPANT MODEL
# =============================================================
class Participant(BaseModel):
    """
    Links users to chats with specific roles.
    """

    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="participations")
    role = models.CharField(
        max_length=20, choices=PARTICIPANT_ROLE_CHOICES, default="member"
    )
    joined_at = models.DateTimeField(default=timezone.now)
    is_muted = models.BooleanField(default=False)
    is_pinned = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)

    class Meta:
        unique_together = ("chat", "user")
        ordering = ["joined_at"]

    def __str__(self):
        return f"{self.user.username} in {self.chat}"

    # -------------------------------
    # HELPER METHODS
    # -------------------------------
    def promote_to_admin(self):
        self.role = "admin"
        self.save(update_fields=["role"])

    def demote_to_member(self):
        self.role = "member"
        self.save(update_fields=["role"])


# =============================================================
# GROUP META MODEL
# =============================================================
class GroupMeta(BaseModel):
    """
    Stores additional metadata for group chats.
    """

    chat = models.OneToOneField(Chat, on_delete=models.CASCADE, related_name="group_meta")
    description = models.TextField(blank=True, null=True)
    group_icon = models.ImageField(upload_to="group_icons/", blank=True, null=True)

    def __str__(self):
        return f"GroupMeta for {self.chat.name or self.chat.id}"


# =============================================================
# MESSAGE MODEL
# =============================================================
class Message(BaseModel):
    """
    Represents a message sent within a chat.
    """

    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    message_type = models.CharField(
        max_length=20, choices=MESSAGE_TYPE_CHOICES, default="text"
    )
    content = models.TextField(blank=True, null=True)
    attachment = models.FileField(upload_to="chat_attachments/", blank=True, null=True)
    status = models.CharField(
        max_length=20, choices=MESSAGE_STATUS_CHOICES, default="sent"
    )
    is_deleted = models.BooleanField(default=False)
    read_by = models.ManyToManyField(User, blank=True, related_name="read_messages")
    read_at = models.DateTimeField(blank=True, null=True)
    delivered_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Message from {self.sender.username} in {self.chat}"

    # -------------------------------
    # HELPER METHODS
    # -------------------------------
    @property
    def short_content(self):
        return (
            (self.content[:30] + "...")
            if self.content and len(self.content) > 30
            else self.content
        )

    def mark_as_read(self, user):
        """Mark message as read by a specific user."""
        self.read_by.add(user)
        self.status = "read"
        self.read_at = timezone.now()
        self.save(update_fields=["status", "read_at"])

    def mark_as_delivered(self):
        """Mark message as delivered."""
        self.status = "delivered"
        self.delivered_at = timezone.now()
        self.save(update_fields=["status", "delivered_at"])
