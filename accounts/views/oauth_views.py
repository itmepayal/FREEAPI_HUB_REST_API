# -------------------------
# Standard Library Imports
# -------------------------
import secrets
from urllib.parse import urlencode
import requests

# -------------------------
# Django / DRF Imports
# -------------------------
from django.conf import settings
from django.shortcuts import redirect
from rest_framework import generics, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.exceptions import ValidationError

# -------------------------
# App Imports
# -------------------------
from accounts.models import User
from accounts.serializers import EmptySerializer, OAuthCallbackSerializer
from core.utils import api_response
from core.logger import get_logger
from core.redis_client import redis_client
from core.constants import LOGIN_GOOGLE, LOGIN_GITHUB

# -------------------------
# Logger
# -------------------------
logger = get_logger(__name__)

# -------------------------
# JWT Helpers
# -------------------------
def generate_jwt_tokens(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)

# -------------------------
# OAuth Helpers
# -------------------------
def generate_state():
    """Generate and store OAuth state """
    state = secrets.token_urlsafe(32)
    redis_client.set(f"oauth_state:{state}", "1", ex=300)  
    return state

def validate_state(state):
    """Validate OAuth state"""
    if not state or not redis_client.get(f"oauth_state:{state}"):
        return False
    redis_client.delete(f"oauth_state:{state}")
    return True

def store_refresh_token(user_id, refresh_token):
    """Store refresh token in Redis"""
    redis_client.set(f"refresh_token:{str(user_id)}", refresh_token, ex=7*24*3600)
    redis_client.set(f"refresh_token_user:{refresh_token}", str(user_id), ex=7*24*3600)

def handle_oauth_user(email, username, login_type):
    """
    Create or update user safely
    Prevent account takeover via different login methods
    """
    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": username,
            "is_verified": True,
            "login_type": login_type,
        },
    )

    if not created:
        if user.login_type != login_type:
            raise ValidationError("Account exists with different login method")

        user.username = username
        user.is_verified = True
        user.save(update_fields=["username", "is_verified"])

    return user

# -------------------------
# Google OAuth
# -------------------------
class GoogleLoginView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        state = generate_state()

        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth"
            f"?response_type=code"
            f"&client_id={settings.GOOGLE_CLIENT_ID}"
            f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
            f"&scope=openid%20email%20profile"
            f"&access_type=offline&prompt=consent"
            f"&state={state}"
        )

        return api_response(True, "Google login URL generated", data={"auth_url": auth_url})

# -------------------------
# Google Callback
# -------------------------
class GoogleLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        state = request.GET.get("state")

        if not validate_state(state):
            return api_response(False, "Invalid or expired state", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            token_res = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                timeout=10,
            )
            token_res.raise_for_status()
            token_data = token_res.json()

            google_access_token = token_data.get("access_token")
            if not google_access_token:
                logger.error(f"Google token error: {token_data}")
                return api_response(False, "Failed to get access token", status_code=status.HTTP_400_BAD_REQUEST)

            user_res = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {google_access_token}"},
                timeout=10,
            )
            user_res.raise_for_status()
            user_info = user_res.json()

            email = user_info.get("email")
            if not email:
                return api_response(False, "Failed to get email", status_code=status.HTTP_400_BAD_REQUEST)

            username = user_info.get("name") or email.split("@")[0]

            user = handle_oauth_user(email, username, LOGIN_GOOGLE)

            access_token, refresh_token = generate_jwt_tokens(user)
            store_refresh_token(user.id, refresh_token)

            params = urlencode({
                "access": access_token,
                "refresh": refresh_token,
                "username": username
            })

            return redirect(f"{settings.FRONTEND_URL}/google/callback?{params}")

        except Exception as e:
            logger.error(f"Google OAuth error: {str(e)}", exc_info=True)
            return api_response(False, str(e), status_code=500)

# -------------------------
# GitHub OAuth
# -------------------------
class GitHubLoginView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        state = generate_state()

        auth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={settings.GITHUB_CLIENT_ID}"
            f"&redirect_uri={settings.GITHUB_REDIRECT_URI}"
            f"&scope=user:email"
            f"&state={state}"
        )

        return api_response(True, "GitHub login URL generated", data={"auth_url": auth_url})

# -------------------------
# GitHub Callback
# -------------------------
class GitHubLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        state = request.GET.get("state")

        if not validate_state(state):
            return api_response(False, "Invalid or expired state", status_code=status.HTTP_400_BAD_REQUEST)

        try:
            token_res = requests.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            token_res.raise_for_status()
            token_data = token_res.json()

            access_token = token_data.get("access_token")
            if not access_token:
                return api_response(False, "Failed to get token", status_code=status.HTTP_400_BAD_REQUEST)

            user_res = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {access_token}"},
                timeout=10,
            )
            user_res.raise_for_status()
            user_info = user_res.json()

            email_res = requests.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"},
                timeout=10,
            )
            email_res.raise_for_status()
            emails = email_res.json()

            primary_email = next((e["email"] for e in emails if e["primary"]), None)
            email = primary_email or f"{user_info.get('id')}@github.com"

            username = user_info.get("login") or f"github_{user_info.get('id')}"

            user = handle_oauth_user(email, username, LOGIN_GITHUB)

            access_jwt, refresh_jwt = generate_jwt_tokens(user)
            store_refresh_token(user.id, refresh_jwt)

            params = urlencode({
                "access": access_jwt,
                "refresh": refresh_jwt,
                "username": username
            })

            return redirect(f"{settings.FRONTEND_URL}/github/callback?{params}")

        except Exception as e:
            logger.error(f"GitHub OAuth error: {str(e)}", exc_info=True)
            return api_response(False, str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
