from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from accounts.models import User, UserSession, SecurityLog


# -------------------------
# User Admin
# -------------------------
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    model = User

    # Fields displayed in the list view
    list_display = (
        "email",
        "username",
        "role",
        "is_verified",
        "is_active",
        "is_staff",
        "is_2fa_enabled",
    )

    # Filters in the right sidebar
    list_filter = (
        "role",
        "is_verified",
        "is_active",
        "is_staff",
        "is_2fa_enabled",
    )

    # Searchable fields
    search_fields = ("email", "username")

    # Default ordering
    ordering = ("email",)

    # Read-only fields
    readonly_fields = ("last_login", "date_joined", "avatar_url")

    # Field layout in the detail view
    fieldsets = (
        (None, {"fields": ("email", "username", "password")}),
        (
            "Permissions",
            {
                "fields": (
                    "role",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Verification & Security",
            {
                "fields": (
                    "is_verified",
                    "is_2fa_enabled",
                    "totp_secret",
                    "temp_totp_secret",
                )
            },
        ),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )

    # Fields used when adding a new user via admin
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "username", "password1", "password2"),
            },
        ),
    )


# -------------------------
# UserSession Admin
# -------------------------
@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ("user", "device", "ip_address", "expiry")
    search_fields = ("user__email", "device", "ip_address")
    readonly_fields = ("token_hash", "expiry")


# -------------------------
# SecurityLog Admin
# -------------------------
@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "ip_address", "device", "timestamp")
    search_fields = ("user__email", "action", "ip_address", "device")
    readonly_fields = ("user", "action", "ip_address", "device", "timestamp")
    