from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from drf_spectacular.utils import extend_schema, OpenApiParameter

from accounts.models import User
from .models import Chat, Message, Participant, GroupMeta
from .serializers import (
    ChatSerializer, MessageSerializer, 
    ParticipantSerializer, UserSerializer, 
    GroupMetaSerializer
)
from core.utils import api_response
from core.permissions import IsOwnerOrAdmin

# =============================================================
# CHAT VIEWSET
# =============================================================
class ChatViewSet(viewsets.GenericViewSet):
    """
    Handles all private and group chat operations.
    """
    queryset = Chat.objects.all()
    serializer_class = ChatSerializer
    permission_classes = [permissions.IsAuthenticated]

    # =========================================================
    # LIST USER CHATS
    # =========================================================
    @extend_schema(
        responses={200: ChatSerializer(many=True)},
        description="List all chats the authenticated user is part of."
    )
    def list(self, request):
        chats = (
            Chat.objects.filter(participants=request.user)
            .select_related("last_message", "owner")
            .prefetch_related("members__user")
        )
        serializer = self.get_serializer(chats, many=True)
        return api_response(True, "Chats fetched successfully", serializer.data)

    # =========================================================
    # AVAILABLE USERS FOR PRIVATE CHAT
    # =========================================================
    @extend_schema(
        responses={200: UserSerializer(many=True)},
        description="List all available users for starting private chats."
    )
    @action(detail=False, methods=["get"], url_path="users")
    def users(self, request):
        users = User.objects.filter(is_active=True).exclude(id=request.user.id)
        serializer = UserSerializer(users, many=True)
        return api_response(True, "Available users fetched successfully", serializer.data)

    # =========================================================
    # CREATE OR FETCH PRIVATE CHAT
    # =========================================================
    @extend_schema(
        request=ChatSerializer,
        responses={200: ChatSerializer},
        description="Create a new private chat or fetch an existing one."
    )
    @action(detail=False, methods=["post"], url_path="private")
    @transaction.atomic
    def create_private_chat(self, request):
        target_id = request.data.get("user_id")
        target = get_object_or_404(User, id=target_id, is_active=True)

        chat = (
            Chat.objects.filter(chat_type="private", participants=request.user)
            .filter(participants=target)
            .first()
        )

        if not chat:
            chat = Chat.objects.create(
                chat_type="private",
                name=f"Chat with {target.username}",
                owner=request.user
            )
            Participant.objects.bulk_create([
                Participant(chat=chat, user=request.user),
                Participant(chat=chat, user=target)
            ])

        serializer = self.get_serializer(chat)
        return api_response(True, "Private chat fetched successfully", serializer.data)

    # =========================================================
    # DELETE PRIVATE CHAT
    # =========================================================
    @extend_schema(
        parameters=[OpenApiParameter("pk", type=str, location=OpenApiParameter.PATH)],
        description="Delete a private chat."
    )
    @action(detail=True, methods=["delete"], url_path="private")
    @transaction.atomic
    def delete_private_chat(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="private", participants=request.user)
        chat.delete()
        return api_response(True, "Private chat deleted successfully")

    # =========================================================
    # CREATE GROUP CHAT
    # =========================================================
    @extend_schema(
        request=ChatSerializer,
        responses={201: ChatSerializer},
        description="Create a new group chat with multiple participants."
    )
    @action(detail=False, methods=["post"], url_path="group")
    @transaction.atomic
    def create_group_chat(self, request):
        name = request.data.get("name")
        user_ids = request.data.get("user_ids", [])

        if not name:
            return api_response(False, "Group name required", status.HTTP_400_BAD_REQUEST)

        chat = Chat.objects.create(name=name, chat_type="group", owner=request.user)
        Participant.objects.create(chat=chat, user=request.user, role="admin")

        for uid in user_ids:
            if uid != request.user.id:
                Participant.objects.get_or_create(chat=chat, user_id=uid)

        GroupMeta.objects.create(chat=chat)
        serializer = self.get_serializer(chat)
        return api_response(True, "Group chat created successfully", serializer.data)

    # =========================================================
    # FETCH GROUP DETAILS
    # =========================================================
    @extend_schema(
        parameters=[OpenApiParameter("pk", type=str, location=OpenApiParameter.PATH)],
        responses={200: ChatSerializer},
        description="Fetch detailed information about a group chat."
    )
    @action(detail=True, methods=["get"], url_path="group/details")
    def group_details(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group")
        serializer = self.get_serializer(chat)
        return api_response(True, "Group details fetched successfully", serializer.data)

    # =========================================================
    # UPDATE GROUP NAME
    # =========================================================
    @extend_schema(
        request=ChatSerializer,
        responses={200: ChatSerializer},
        description="Update the name of a group chat."
    )
    @action(detail=True, methods=["patch"], url_path="group/name")
    @transaction.atomic
    def update_group_name(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group", owner=request.user)
        chat.name = request.data.get("name", chat.name)
        chat.save(update_fields=["name"])
        return api_response(True, "Group name updated successfully")

    # =========================================================
    # UPDATE GROUP META
    # =========================================================
    @extend_schema(
        request=GroupMetaSerializer,
        responses={200: GroupMetaSerializer},
        description="Update group description or icon."
    )
    @action(detail=True, methods=["patch"], url_path="group/meta")
    @transaction.atomic
    def update_group_meta(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group", owner=request.user)
        group_meta, _ = GroupMeta.objects.get_or_create(chat=chat)

        description = request.data.get("description")
        group_icon = request.FILES.get("group_icon")

        if description is not None:
            group_meta.description = description
        if group_icon is not None:
            group_meta.group_icon = group_icon

        group_meta.save()
        serializer = GroupMetaSerializer(group_meta)
        return api_response(True, "Group meta updated successfully", serializer.data)

    # =========================================================
    # ADD / REMOVE / LEAVE PARTICIPANTS
    # =========================================================
    @extend_schema(description="Add a user to the group.")
    @action(detail=True, methods=["post"], url_path="group/add")
    @transaction.atomic
    def add_participant(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group")
        user_id = request.data.get("user_id")
        user = get_object_or_404(User, id=user_id)
        Participant.objects.get_or_create(chat=chat, user=user)
        return api_response(True, f"{user.username} added to group successfully")

    @extend_schema(description="Remove a user from the group.")
    @action(detail=True, methods=["delete"], url_path="group/remove")
    @transaction.atomic
    def remove_participant(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group")
        user_id = request.data.get("user_id")
        Participant.objects.filter(chat=chat, user_id=user_id).delete()
        return api_response(True, "Participant removed successfully")

    @extend_schema(description="Leave the group as a participant.")
    @action(detail=True, methods=["delete"], url_path="group/leave")
    @transaction.atomic
    def leave_group(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, chat_type="group")
        Participant.objects.filter(chat=chat, user=request.user).delete()
        return api_response(True, "You left the group successfully")

    # =========================================================
    # MESSAGES: LIST, SEND, DELETE
    # =========================================================
    @extend_schema(description="Fetch all messages from a chat.")
    @action(detail=True, methods=["get"], url_path="messages/all")
    def get_messages(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, participants=request.user)
        messages = chat.messages.filter(is_deleted=False).select_related("sender")
        serializer = MessageSerializer(messages, many=True)
        return api_response(True, "Messages fetched successfully", serializer.data)

    @extend_schema(description="Send a message (text or file) in a chat.")
    @action(detail=True, methods=["post"], url_path="messages/send")
    @transaction.atomic
    def send_message(self, request, pk=None):
        chat = get_object_or_404(Chat, id=pk, participants=request.user)
        content = request.data.get("content")
        attachment = request.FILES.get("attachment")

        if not content and not attachment:
            return api_response(False, "Message content or attachment required", status.HTTP_400_BAD_REQUEST)

        message = Message.objects.create(
            chat=chat,
            sender=request.user,
            content=content,
            attachment=attachment,
            message_type="file" if attachment else "text"
        )
        chat.last_message = message
        chat.save(update_fields=["last_message"])

        serializer = MessageSerializer(message)
        return api_response(True, "Message sent successfully", serializer.data)

    @extend_schema(description="Soft delete a message sent by the user.")
    @action(detail=True, methods=["delete"], url_path="messages/delete")
    @transaction.atomic
    def delete_message(self, request, pk=None):
        message_id = request.data.get("message_id")
        if not message_id:
            return api_response(False, "Message ID required", status.HTTP_400_BAD_REQUEST)

        message = get_object_or_404(
            Message, id=message_id, sender=request.user, chat_id=pk, is_deleted=False
        )
        message.delete()
        return api_response(True, "Message deleted successfully")
