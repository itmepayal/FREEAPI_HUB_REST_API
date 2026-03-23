import pyotp
import hashlib
import secrets
import urllib.parse
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from urllib.parse import quote

from accounts.managers import UserManager
from core.models import BaseModel
from core.constants import (
    ROLE_CHOICES,
    ROLE_USER,
    LOGIN_TYPE_CHOICES,
    LOGIN_EMAIL_PASSWORD,
)

class User(BaseModel, AbstractBaseUser, PermissionsMixin):

    # =====================================================
    # BASIC USER INFO
    # =====================================================
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=150, unique=True, db_index=True)
    avatar = models.URLField(blank=True, null=True)

    # =====================================================
    # ROLE
    # =====================================================
    role = models.CharField(
        max_length=50,
        choices=ROLE_CHOICES,
        default=ROLE_USER
    )

    # =====================================================
    # ACCOUNT STATUS
    # =====================================================
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    # =====================================================
    # LOGIN TYPE
    # =====================================================
    login_type = models.CharField(
        max_length=50,
        choices=LOGIN_TYPE_CHOICES,
        default=LOGIN_EMAIL_PASSWORD
    )

    # =====================================================
    # SECURITY (RATE LIMITING / LOCK)
    # =====================================================
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(blank=True, null=True)

    # =====================================================
    # PASSWORD RESET / EMAIL VERIFICATION
    # =====================================================
    forgot_password_token = models.CharField(max_length=255, blank=True, null=True)
    forgot_password_expiry = models.DateTimeField(blank=True, null=True)

    email_verification_token = models.CharField(max_length=255, blank=True, null=True)
    email_verification_expiry = models.DateTimeField(blank=True, null=True)

    # =====================================================
    # TWO FACTOR AUTHENTICATION (TOTP)
    # =====================================================
    is_2fa_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    temp_totp_secret = models.CharField(max_length=32, blank=True, null=True)
    temp_totp_created_at = models.DateTimeField(null=True, blank=True)

    # =====================================================
    # REALTIME PRESENCE
    # =====================================================
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    # =====================================================
    # DJANGO CONFIG
    # =====================================================
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    # =====================================================
    # AVATAR
    # =====================================================
    @property
    def avatar_url(self):
        if self.avatar and self.avatar.startswith("http"):
            return self.avatar
        return f"https://ui-avatars.com/api/?name={quote(self.username)}&size=200"

    # =====================================================
    # 2FA SETUP FLOW
    # =====================================================
    def generate_2fa_setup(self):
        """Generate temporary TOTP secret + QR URI"""
        self.temp_totp_secret = pyotp.random_base32()
        self.temp_totp_created_at = timezone.now()

        self.save(update_fields=["temp_totp_secret", "temp_totp_created_at"])

        totp = pyotp.TOTP(self.temp_totp_secret)

        return totp.provisioning_uri(
            name=self.email,
            issuer_name=settings.TOTP_ISSUER_NAME
        )

    def verify_2fa_setup(self, token):
        """Verify setup token and enable 2FA"""
        if not self.temp_totp_secret:
            return False

        if self.temp_totp_created_at and (
            timezone.now() - self.temp_totp_created_at > timedelta(minutes=10)
        ):
            self.temp_totp_secret = None
            self.temp_totp_created_at = None
            self.save(update_fields=["temp_totp_secret", "temp_totp_created_at"])
            return False

        totp = pyotp.TOTP(self.temp_totp_secret)

        if totp.verify(token, valid_window=1):
            self.totp_secret = self.temp_totp_secret
            self.temp_totp_secret = None
            self.temp_totp_created_at = None
            self.is_2fa_enabled = True

            self.save(update_fields=[
                "totp_secret",
                "temp_totp_secret",
                "temp_totp_created_at",
                "is_2fa_enabled"
            ])
            return True

        return False

    def verify_totp(self, token):
        """Verify login TOTP"""
        if not self.totp_secret:
            return False

        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def get_totp_uri(self):
        """Get QR URI if already enabled"""
        if not self.totp_secret:
            return None

        totp = pyotp.TOTP(self.totp_secret)

        return totp.provisioning_uri(
            name=self.email,
            issuer_name=settings.TOTP_ISSUER_NAME
        )
    # =====================================================
    # SECURITY HELPERS
    # =====================================================
    def is_account_locked(self):
        return self.account_locked_until and timezone.now() < self.account_locked_until

    def register_failed_login(self):
        self.failed_login_attempts += 1

        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timedelta(minutes=15)

        self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    def reset_login_attempts(self):
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    # =====================================================
    # PRESENCE
    # =====================================================
    def mark_online(self):
        self.is_online = True
        self.last_seen = timezone.now()
        self.save(update_fields=["is_online", "last_seen"])

    def mark_offline(self):
        self.is_online = False
        self.last_seen = timezone.now()
        self.save(update_fields=["is_online", "last_seen"])

    def __str__(self):
        return self.email
    
    # =====================================================
    # INDEX
    # =====================================================
    class Meta:
        indexes = [
            models.Index(fields=["role"]),          
            models.Index(fields=["is_active"]),      
            models.Index(fields=["is_verified"]),    
            models.Index(fields=["is_2fa_enabled"]), 
        ]