from rest_framework import serializers
from .models import Chat, Participant, Message, GroupMeta
from accounts.models import User

# =============================================================
# USER SERIALIZER 
# =============================================================
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'avatar_url']


# =============================================================
# MESSAGE SERIALIZER
# =============================================================
class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = Message
        fields = [
            'id', 'chat', 'sender', 'message_type', 'content',
            'attachment', 'status', 'is_deleted', 'created_at'
        ]
        read_only_fields = ['id', 'sender', 'status', 'created_at']


# =============================================================
# PARTICIPANT SERIALIZER
# =============================================================
class ParticipantSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Participant
        fields = ['id', 'user', 'role', 'joined_at']


# =============================================================
# GROUP META SERIALIZER
# =============================================================
class GroupMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMeta
        fields = ['description', 'group_icon']


# =============================================================
# CHAT SERIALIZER
# =============================================================
class ChatSerializer(serializers.ModelSerializer):
    participants = ParticipantSerializer(source='members', many=True, read_only=True)
    last_message = MessageSerializer(read_only=True)
    group_meta = GroupMetaSerializer(read_only=True)

    class Meta:
        model = Chat
        fields = [
            'id', 'name', 'chat_type', 'owner',
            'participants', 'last_message', 'group_meta',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'owner', 'created_at', 'updated_at']
