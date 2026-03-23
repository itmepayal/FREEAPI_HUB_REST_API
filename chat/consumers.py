import json
import uuid
import logging
from django.db import transaction
from django.utils import timezone
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from accounts.models import User
from chat.models import Chat, Message, Participant

logger = logging.getLogger(__name__)


class ChatConsumer(AsyncJsonWebsocketConsumer):
    """Handles connection, messaging, typing, read receipts, and user status updates."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.chat_id = None
        self.group_name = None

    # =========================================================
    # ---------------------- CONNECTION -----------------------
    # =========================================================
    async def connect(self):
        """Handle WebSocket connection and user authentication."""
        user = self.scope.get("user")

        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        self.user = user
        target_user_id = self.scope["url_route"]["kwargs"].get("user_id")

        # Validate UUID
        try:
            target_user_id = uuid.UUID(target_user_id)
        except (TypeError, ValueError):
            await self.close(code=4002)
            return

        # Get or create private chat
        self.chat_id = await self.get_or_create_private_chat(self.user.id, target_user_id)
        if not self.chat_id:
            await self.close(code=4003)
            return

        self.group_name = f"chat_{self.chat_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        await self.set_user_status(self.user.id, True)
        await self.broadcast_status("user.online", self.user.id)

        logger.info(f"[CONNECT] {user.email} connected to chat {self.chat_id}")

    # =========================================================
    # ---------------------- DISCONNECTION --------------------
    # =========================================================
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        user = getattr(self, "user", None)

        if self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

        if user and user.is_authenticated:
            await self.set_user_status(user.id, False)
            await self.broadcast_status("user.offline", user.id)

        logger.info(f"[DISCONNECT] {getattr(user, 'email', 'Anonymous')} left chat {self.chat_id}")

    # =========================================================
    # ---------------------- RECEIVE EVENTS -------------------
    # =========================================================
    async def receive_json(self, content, **kwargs):
        """Handle incoming WebSocket messages and events."""
        event_type = content.get("type")

        try:
            if event_type == "message.send":
                await self.handle_message_send(content)

            elif event_type == "user.typing":
                await self.broadcast_typing(self.user.username, True)

            elif event_type == "user.stop_typing":
                await self.broadcast_typing(self.user.username, False)

            elif event_type == "message.read":
                await self.handle_message_read(content)

            elif event_type == "user.status":
                await self.handle_user_status(content)

        except Exception as e:
            logger.exception(f"[ERROR] receive_json failed: {e}")
            await self.send_json({
                "type": "error",
                "message": "Internal error while processing your request."
            })

    # =========================================================
    # ---------------------- EVENT HANDLERS -------------------
    # =========================================================
    async def handle_message_send(self, content):
        """Handle sending of a chat message."""
        text = content.get("text", "")
        attachment = content.get("attachment")

        message = await self.create_message(text, attachment)
        if not message:
            await self.send_json({"type": "error", "message": "Message could not be sent."})
            return

        payload = self.build_message_payload(message)
        await self.channel_layer.group_send(self.group_name, {
            "type": "chat_message",
            "payload": payload
        })

    async def handle_message_read(self, content):
        """Handle message read receipts."""
        message_id = content.get("message_id")
        read_data = await self.mark_message_read(message_id)

        if read_data:
            await self.channel_layer.group_send(self.group_name, {
                "type": "chat_message",
                "payload": {
                    "type": "message.read",
                    "chat_id": str(self.chat_id),
                    **read_data,
                },
            })

    async def handle_user_status(self, content):
        """Handle custom user status message updates."""
        status_message = content.get("status_message", "")
        await self.update_status_message(self.user.id, status_message)
        await self.broadcast_status("user.status.update", self.user.id)

    # =========================================================
    # ---------------------- BROADCAST HELPERS ----------------
    # =========================================================
    async def chat_message(self, event):
        """Send payload to WebSocket client."""
        await self.send_json(event["payload"])

    async def broadcast_status(self, event_type, user_id, message_id=None):
        """Broadcast online/offline/read/status updates."""
        if not self.group_name:
            return

        payload = {
            "type": event_type,
            "user_id": str(user_id),
            "chat_id": str(self.chat_id),
            "message_id": str(message_id) if message_id else None,
            "timestamp": timezone.now().isoformat(),
        }

        await self.channel_layer.group_send(
            self.group_name, {"type": "chat_message", "payload": payload}
        )

    async def broadcast_typing(self, username, is_typing):
        """Broadcast typing indicator event."""
        payload = {
            "type": "user.typing",
            "username": username,
            "user_id": str(self.user.id),
            "is_typing": is_typing,
            "chat_id": str(self.chat_id),
        }

        await self.channel_layer.group_send(
            self.group_name, {"type": "chat_message", "payload": payload}
        )

    # =========================================================
    # ---------------------- DATABASE HELPERS -----------------
    # =========================================================
    @database_sync_to_async
    def get_or_create_private_chat(self, user1_id, user2_id):
        """Get or create a private chat between two users."""
        try:
            with transaction.atomic():
                chat = (
                    Chat.objects.filter(chat_type="private", members__user_id=user1_id)
                    .filter(members__user_id=user2_id)
                    .select_for_update()
                    .first()
                )
                if chat:
                    return chat.id

                chat = Chat.objects.create(chat_type="private")
                Participant.objects.bulk_create([
                    Participant(chat=chat, user_id=user1_id),
                    Participant(chat=chat, user_id=user2_id),
                ])
                return chat.id
        except Exception as e:
            logger.exception(f"[ERROR] Failed to get/create chat: {e}")
            return None

    @database_sync_to_async
    def create_message(self, text, attachment=None):
        """Create and save a new message in the database."""
        try:
            chat = Chat.objects.get(id=self.chat_id)
            message = Message.objects.create(
                chat=chat,
                sender=self.user,
                content=text,
                attachment=attachment,
                message_type="text" if text else "file",
                status="sent",
            )
            chat.last_message = message
            chat.save(update_fields=["last_message"])
            return message
        except Exception as e:
            logger.exception(f"[ERROR] Failed to create message: {e}")
            return None

    @database_sync_to_async
    def mark_message_read(self, message_id):
        """Mark message as read and return read event data."""
        try:
            message = Message.objects.select_related("sender").get(id=message_id)
            message.mark_as_read(self.user)
            return {
                "message_id": str(message.id),
                "reader_id": str(self.user.id),
                "reader_username": self.user.username,
                "read_at": timezone.now().isoformat(),
            }
        except Message.DoesNotExist:
            return None

    @database_sync_to_async
    def set_user_status(self, user_id, online):
        """Update user's online/offline status."""
        try:
            user = User.objects.filter(id=user_id).first()
            if user:
                user.is_online = online
                user.last_seen = timezone.now()
                user.save(update_fields=["is_online", "last_seen"])
        except Exception as e:
            logger.exception(f"[ERROR] Failed to set user status: {e}")

    @database_sync_to_async
    def update_status_message(self, user_id, message):
        """Update user's custom status message."""
        try:
            User.objects.filter(id=user_id).update(status_message=message)
        except Exception as e:
            logger.exception(f"[ERROR] Failed to update status message: {e}")

    # =========================================================
    # ---------------------- UTILITIES ------------------------
    # =========================================================
    def build_message_payload(self, message):
        """Build a clean message payload for sending to clients."""
        return {
            "type": "message.receive",
            "chat_id": str(self.chat_id),
            "message_id": str(message.id),
            "sender": self.user.username,
            "sender_id": str(self.user.id),
            "content": message.content,
            "message_type": message.message_type,
            "status": message.status,
            "created_at": message.created_at.isoformat(),
        }

    async def encode_json(self, content):
        """Convert UUIDs and datetime objects for safe JSON serialization."""
        def default_encoder(o):
            if isinstance(o, uuid.UUID):
                return str(o)
            if hasattr(o, "isoformat"):
                return o.isoformat()
            raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")
        return json.dumps(content, default=default_encoder)