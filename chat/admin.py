from django.contrib import admin
from .models import Chat, Participant, Message, GroupMeta

# =============================================================
# PARTICIPANT INLINE 
# =============================================================
class ParticipantInline(admin.TabularInline):
    model = Participant
    extra = 0
    autocomplete_fields = ['user']
    readonly_fields = ['joined_at']
    ordering = ['joined_at']
    show_change_link = True


# =============================================================
# GROUP META INLINE 
# =============================================================
class GroupMetaInline(admin.StackedInline):
    model = GroupMeta
    extra = 0
    can_delete = True


# =============================================================
# CHAT ADMIN
# =============================================================
@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'name', 'chat_type', 'owner', 'total_participants', 'created_at', 'updated_at'
    )
    list_filter = ('chat_type', 'created_at')
    search_fields = ('name', 'owner__email', 'owner__username')
    readonly_fields = ('created_at', 'updated_at')
    inlines = [ParticipantInline, GroupMetaInline]
    ordering = ['-created_at']

    fieldsets = (
        ("Chat Details", {
            'fields': ('name', 'chat_type', 'owner', 'last_message')
        }),
        ("Timestamps", {
            'fields': ('created_at', 'updated_at'),
        }),
    )


# =============================================================
# PARTICIPANT ADMIN
# =============================================================
@admin.register(Participant)
class ParticipantAdmin(admin.ModelAdmin):
    list_display = ('id', 'chat', 'user', 'role', 'joined_at')
    list_filter = ('role', 'joined_at')
    search_fields = ('chat__name', 'user__email', 'user__username')
    autocomplete_fields = ['chat', 'user']
    readonly_fields = ('joined_at',)
    ordering = ['-joined_at']


# =============================================================
# GROUP META ADMIN
# =============================================================
@admin.register(GroupMeta)
class GroupMetaAdmin(admin.ModelAdmin):
    list_display = ('id', 'chat', 'description')
    search_fields = ('chat__name', 'description')
    autocomplete_fields = ['chat']
    ordering = ['-created_at']


# =============================================================
# MESSAGE ADMIN
# =============================================================
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'chat', 'sender', 'message_type', 'short_content',
        'status', 'is_deleted', 'created_at'
    )
    list_filter = ('message_type', 'status', 'is_deleted', 'created_at')
    search_fields = ('content', 'sender__email', 'chat__name')
    autocomplete_fields = ['chat', 'sender', 'read_by']
    readonly_fields = ('created_at', 'updated_at')
    ordering = ['-created_at']

    fieldsets = (
        ("Message Info", {
            'fields': ('chat', 'sender', 'message_type', 'content', 'attachment')
        }),
        ("Status", {
            'fields': ('status', 'is_deleted', 'read_by')
        }),
        ("Timestamps", {
            'fields': ('created_at', 'updated_at')
        }),
    )

