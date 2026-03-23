from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from accounts.validators import validate_strong_password, validate_totp_token, validate_username
from core.constants import ROLE_CHOICES
from accounts.models import UserSession

User = get_user_model()

# =====================================================
# User Serializer
# =====================================================
class UserSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField()
    status_message = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "email", "username", "role", "is_verified",
            "is_online", "last_seen", "status_message",
            "is_2fa_enabled", "avatar_url",
        ]
        read_only_fields = [
            "id", "email", "is_verified", "is_online",
            "last_seen", "is_2fa_enabled", "avatar_url",
        ]

    def get_avatar_url(self, obj):
        return obj.avatar_url

    def get_status_message(self, obj):
        return getattr(obj, "status_message", "Hey there! I am using FreeAPI")

# =====================================================
# Register Serializer
# =====================================================
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "username", "password"]

    def validate_email(self, value):
        validate_email(value)
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value

    def validate_username(self, value):
        validate_username(value)
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate_password(self, value):
        return validate_strong_password(value)

    def create(self, validated_data):
        user = User(
            email=validated_data["email"],
            username=validated_data["username"],
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


# =====================================================
# Login Serializer
# =====================================================
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        default="",
        help_text="TOTP token if 2FA enabled",
    )


# =====================================================
# Verify Email Serializer
# =====================================================
class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()


# =====================================================
# Resend Email Verification
# =====================================================
class ResendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No account found with this email."})

        if user.is_verified:
            raise serializers.ValidationError({"email": "Email is already verified."})

        attrs["user"] = user
        return attrs


# =====================================================
# Forgot Password
# =====================================================
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email.")
        return value


# =====================================================
# Reset Password
# =====================================================
class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        return validate_strong_password(value)


# =====================================================
# Change Password
# =====================================================
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context["request"].user
        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError({"old_password": "Old password is incorrect."})
        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError({"new_password": "New password must be different."})
        return attrs

    def validate_new_password(self, value):
        return validate_strong_password(value)


# =====================================================
# Update Avatar
# =====================================================
class UpdateAvatarSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField()

    class Meta:
        model = User
        fields = ["avatar"]


# =====================================================
# Change Role
# =====================================================
class ChangeRoleSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)
    role = serializers.ChoiceField(choices=ROLE_CHOICES)

    def validate_user_id(self, value):
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User not found.")
        return value


# =====================================================
# Refresh Token Input
# =====================================================
class RefreshTokenInputSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)


# =====================================================
# Enable 2FA
# =====================================================
class Enable2FASerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True, help_text="TOTP token generated by authenticator app")

    def validate_token(self, value):
        return validate_totp_token(value)


# =====================================================
# Disable 2FA
# =====================================================
class Disable2FASerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True, help_text="TOTP token to confirm disabling 2FA")

    def validate_token(self, value):
        return validate_totp_token(value)


# =====================================================
# Setup 2FA (Response Serializer)
# =====================================================
class Setup2FASerializer(serializers.Serializer):
    totp_uri = serializers.CharField(read_only=True)
    qr_code = serializers.CharField(read_only=True)


# =====================================================
# OAuth Callback
# =====================================================
class OAuthCallbackSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)


# =====================================================
# Empty Serializer
# =====================================================
class EmptySerializer(serializers.Serializer):
    pass

# =====================================================
# User Serializer
# =====================================================
class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ["id", "device", "ip_address", "expiry"]