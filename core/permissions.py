from rest_framework import permissions
from chat.models import Chat, Participant, Message

# ===============================
# Role-based Permission Base
# ===============================
class RolePermission(permissions.BasePermission):
    """
    Base permission for role-based access control.
    Example usage:
        permission_classes = [RolePermission(roles=["ADMIN", "SUPERADMIN"])]
    """
    def __init__(self, roles=None):
        self.roles = roles or []

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "role", None) in self.roles
        )


# ===============================
# SUPERADMIN Only
# ===============================
class IsSuperAdmin(RolePermission):
    def __init__(self):
        super().__init__(roles=["SUPERADMIN"])
        self.message = "Only SUPERADMIN can perform this action."


# ===============================
# ADMIN or SUPERADMIN
# ===============================
class IsAdminOrSuperAdmin(RolePermission):
    def __init__(self):
        super().__init__(roles=["ADMIN", "SUPERADMIN"])
        self.message = "Only ADMIN or SUPERADMIN can perform this action."


# ===============================
# Any Authenticated User
# ===============================
class IsAuthenticatedUser(permissions.BasePermission):
    """
    Allow only authenticated users.
    """
    message = "Authentication required."

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


# ===============================
# Owner or Admin/SUPERADMIN
# ===============================
class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Allow only resource owner or admin/superadmin.
    Checks for 'author' or 'user' field dynamically.
    """
    message = "You must be the owner or an admin to perform this action."

    def has_object_permission(self, request, view, obj):
        owner = getattr(obj, "author", None) or getattr(obj, "user", None)
        return bool(
            owner == request.user or getattr(request.user, "role", None) in ["ADMIN", "SUPERADMIN"]
        )


# ===============================
# Chat Permissions
# ===============================
class IsChatParticipant(permissions.BasePermission):
    """
    Allow access only to participants of the chat.
    Works for both private and group chats.
    """
    message = "You must be a participant of this chat."

    def has_object_permission(self, request, view, obj):
        if isinstance(obj, Chat):
            return obj.has_participant(request.user)
        return False


class IsChatOwnerOrAdmin(permissions.BasePermission):
    """
    Allow access only to chat owner or system admin.
    Useful for renaming or deleting group chats.
    """
    message = "You must be the group owner or admin."

    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Chat):
            return False
        user = request.user
        return bool(
            obj.owner == user or getattr(user, "role", None) in ["ADMIN", "SUPERADMIN"]
        )


class IsGroupAdminOrOwner(permissions.BasePermission):
    """
    Allow access only to group admins or the group owner.
    Useful for adding/removing participants.
    """
    message = "Only group admins or owner can manage members."

    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Chat) or obj.chat_type != "group":
            return False

        user = request.user
        if obj.owner == user:
            return True

        return Participant.objects.filter(chat=obj, user=user, role="admin").exists()


# ===============================
# Message Permissions
# ===============================
class IsMessageSenderOrAdmin(permissions.BasePermission):
    """
    Allow only the sender or an admin to delete/update a message.
    """
    message = "You can only modify your own messages."

    def has_object_permission(self, request, view, obj):
        if not isinstance(obj, Message):
            return False

        user = request.user
        return bool(
            obj.sender == user or getattr(user, "role", None) in ["ADMIN", "SUPERADMIN"]
        )
