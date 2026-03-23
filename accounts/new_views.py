import secrets
import hashlib
import requests
from urllib.parse import urlencode
from datetime import timedelta
from django.shortcuts import redirect
from django.contrib.auth import login as django_login
from django.utils import timezone
from django.conf import settings
from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from accounts.models import User
from accounts.serializers import *
from accounts.utils import get_client_ip, generate_totp_qr_code
from core.utils import send_email, api_response
from core.constants import LOGIN_GOOGLE, LOGIN_GITHUB
from core.logger import get_logger
from core.cloudinary import upload_to_cloudinary
from core.permissions import IsSuperAdmin
from core.redis_client import redis_client
from core.tasks import send_email_async, log_security_event

logger = get_logger(__name__)

# -------------------------
# JWT Helpers
# -------------------------
def generate_access_token(user):
    return str(AccessToken.for_user(user))

def generate_jwt_tokens(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)

# -------------------------
# Register
# -------------------------
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        ip = get_client_ip(request)
        device = request.META.get("HTTP_USER_AGENT")

        log_security_event.delay(user.id, "REGISTER", ip_address=ip, device=device)

        # Email verification
        raw_token = secrets.token_hex(20)
        hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
        expiry = timezone.now() + timedelta(minutes=10)
        user.email_verification_token = hashed_token
        user.email_verification_expiry = expiry
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        verify_link = f"{settings.FRONTEND_URL}/verify-email/{raw_token}"
        send_email_async.delay(user.email, "Verify your email", "email_verification", {"username": user.username, "verify_link": verify_link})

        return api_response(True, "User registered successfully. Please verify your email.", data={"user": UserSerializer(user).data}, status_code=status.HTTP_201_CREATED)

# -------------------------
# Verify Email
# -------------------------
class VerifyEmailView(generics.GenericAPIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        user = User.objects.filter(email_verification_token=hashed_token, email_verification_expiry__gt=timezone.now()).first()
        if not user:
            return api_response(False, "Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expiry = None
        user.save(update_fields=["is_verified", "email_verification_token", "email_verification_expiry"])

        log_security_event.delay(user.id, "EMAIL_VERIFIED", ip_address=get_client_ip(request))
        return api_response(True, "Email verified successfully")

# -------------------------
# Login
# -------------------------
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        token = serializer.validated_data.get("token")
        ip = get_client_ip(request)
        device = request.META.get("HTTP_USER_AGENT")

        user = User.objects.filter(email=email).first()
        if not user or not user.check_password(password):
            if user:
                key = f"login_fail:{user.id}"
                attempts = redis_client.incr(key)
                redis_client.expire(key, 300)
                if attempts >= 5:
                    redis_client.set(f"account_locked:{user.id}", True, ex=300)
                log_security_event.delay(user.id, "FAILED_LOGIN", ip_address=ip, device=device)
            return api_response(False, "Invalid credentials", status_code=status.HTTP_401_UNAUTHORIZED)

        if redis_client.get(f"account_locked:{user.id}"):
            return api_response(False, "Account temporarily locked", status_code=status.HTTP_403_FORBIDDEN)

        if not user.is_verified:
            return api_response(False, "Email not verified", status_code=status.HTTP_403_FORBIDDEN)

        if user.is_2fa_enabled:
            if not token or not user.verify_totp(token):
                return api_response(False, "Invalid or missing 2FA token", status_code=status.HTTP_400_BAD_REQUEST)

        redis_client.delete(f"login_fail:{user.id}")
        django_login(request, user)
        request.session["ip"] = ip
        request.session["user_agent"] = device

        access_token, refresh_token = generate_jwt_tokens(user)
        redis_client.set(f"refresh_token:{user.id}", refresh_token, ex=7*24*3600)
        redis_client.set(f"refresh_token_user:{refresh_token}", user.id, ex=7*24*3600)

        log_security_event.delay(user.id, "LOGIN_SUCCESS", ip_address=ip, device=device)
        return api_response(True, "Login successful", data={"user": UserSerializer(user).data, "access_token": access_token, "refresh_token": refresh_token})

# -------------------------
# Refresh Token
# -------------------------
class RefreshTokenView(generics.GenericAPIView):
    serializer_class = RefreshTokenInputSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data.get("refresh_token")

        user_id = redis_client.get(f"refresh_token_user:{refresh_token}")
        if not user_id:
            return api_response(False, "Invalid or expired refresh token", status_code=status.HTTP_401_UNAUTHORIZED)

        user = User.objects.filter(id=user_id).first()
        if not user:
            return api_response(False, "User not found", status_code=status.HTTP_404_NOT_FOUND)

        access_token = generate_access_token(user)
        return api_response(True, "Token refreshed successfully", data={"access_token": access_token})

# -------------------------
# Logout
# -------------------------
class LogoutView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        refresh_token = request.data.get("refresh_token")

        if refresh_token:
            redis_client.delete(f"refresh_token_user:{refresh_token}")
        redis_client.delete(f"refresh_token:{user.id}")

        request.session.flush()

        log_security_event.delay(user.id, "LOGOUT")

        return api_response(True, "Logged out successfully")

# -------------------------
# Forgot Password
# -------------------------
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()

        if user:
            un_hashed = secrets.token_hex(20)
            hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
            expiry = timezone.now() + timedelta(minutes=10)
            user.forgot_password_token = hashed
            user.forgot_password_expiry = expiry
            user.save(update_fields=["forgot_password_token", "forgot_password_expiry"])

            reset_link = f"{settings.FRONTEND_URL}/reset-password/{un_hashed}"
            send_email_async.delay(user.email, "Reset Password", "reset_password", {"username": user.username, "reset_link": reset_link})
            logger.info(f"Password reset email sent to {user.email}")
        else:
            logger.warning(f"Password reset requested for non-existing email: {email}")

        return api_response(True, "Reset link sent successfully.")

# -------------------------
# Reset Password
# -------------------------
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        user = User.objects.filter(forgot_password_token=hashed_token, forgot_password_expiry__gt=timezone.now()).first()
        if not user:
            return api_response(False, "Invalid or expired token", status_code=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.forgot_password_token = None
        user.forgot_password_expiry = None
        user.save(update_fields=["password", "forgot_password_token", "forgot_password_expiry"])
        logger.info(f"Password reset successfully for {user.email}")
        return api_response(True, "Password reset successful")

# -------------------------
# Resend Email Verification
# -------------------------
class ResendEmailView(generics.GenericAPIView):
    serializer_class = ResendEmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        if not user.is_active:
            return api_response(False, "Account is inactive", status_code=400)
        if user.is_verified:
            return api_response(False, "Email already verified", status_code=400)
        if user.email_verification_expiry and user.email_verification_expiry > timezone.now():
            return api_response(False, "Verification email already sent. Please wait.", status_code=400)

        un_hashed = secrets.token_hex(20)
        hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
        user.email_verification_token = hashed
        user.email_verification_expiry = timezone.now() + timedelta(minutes=10)
        user.save(update_fields=["email_verification_token", "email_verification_expiry"])

        verify_link = f"{settings.FRONTEND_URL}/verify-email/{un_hashed}"
        send_email_async.delay(user.email, "Verify your email", "email_verification", {"username": user.username, "verify_link": verify_link})
        logger.info(f"Verification email resent to {user.email}")

        return api_response(True, "Verification email resent successfully.")

# -------------------------
# Update Avatar
# -------------------------
class UpdateAvatarView(generics.UpdateAPIView):
    serializer_class = UpdateAvatarSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    http_method_names = ['patch']

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        file = request.FILES.get("avatar")
        user = request.user
        if not file:
            return api_response(False, "No file provided", status_code=status.HTTP_400_BAD_REQUEST)
        try:
            avatar_url = upload_to_cloudinary(file, folder="avatars")
            user.avatar = avatar_url
            user.save(update_fields=["avatar"])
            logger.info(f"Avatar updated for {user.email}")
            return api_response(True, "Avatar updated successfully", data={"avatar": avatar_url})
        except Exception as e:
            logger.error(f"Error uploading avatar for {user.email}: {str(e)}", exc_info=True)
            return api_response(False, "Error uploading avatar", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# -------------------------
# OAuth (Google)
# -------------------------
class GoogleLoginView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={settings.GOOGLE_CLIENT_ID}&redirect_uri={settings.GOOGLE_REDIRECT_URI}&scope=openid%20email%20profile&access_type=offline&prompt=consent"
        return api_response(True, "Google login URL generated", data={"auth_url": auth_url})

class GoogleLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]
        try:
            token_res = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code"
                }
            )
            token_res_json = token_res.json()
            if token_res.status_code != 200 or "access_token" not in token_res_json:
                logger.error(
                    f"Google token error: status={token_res.status_code}, response={token_res_json}, code={code}, headers={request.headers}"
                )
                return api_response(False, "Failed to get access token from Google", status_code=status.HTTP_400_BAD_REQUEST)

            google_access_token = token_res_json["access_token"]

            user_info_res = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {google_access_token}"}
            )
            user_info = user_info_res.json()
            if user_info_res.status_code != 200 or "email" not in user_info:
                logger.error(
                    f"Google user info error: status={user_info_res.status_code}, response={user_info}, code={code}, headers={request.headers}"
                )
                return api_response(False, "Failed to get user info from Google", status_code=status.HTTP_400_BAD_REQUEST)

            email = user_info.get("email")
            username = user_info.get("name")
            user, created = User.objects.get_or_create(
                email=email, 
                defaults={"username": username, "is_verified": True, "login_type": LOGIN_GOOGLE}
            )
            if not created:
                user.username = username
                user.is_verified = True
                user.save(update_fields=["username", "is_verified"])

            access_token, refresh_token = generate_jwt_tokens(user)
            redis_client.set(f"refresh_token:{user.id}", refresh_token, ex=7*24*3600)
            redis_client.set(f"refresh_token_user:{refresh_token}", user.id, ex=7*24*3600)

            redirect_url = f"{settings.FRONTEND_URL}/google/callback?{urlencode({'access': access_token, 'refresh': refresh_token})}"
            return redirect(redirect_url)

        except Exception as e:
            logger.error(
                f"Google OAuth exception: {str(e)}, code={request.GET.get('code')}, headers={request.headers}",
                exc_info=True
            )
            return api_response(False, "Internal server error during Google OAuth", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# -------------------------
# OAuth (GitHub)
# -------------------------
class GitHubLoginView(generics.GenericAPIView):
    serializer_class = EmptySerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        auth_url = f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&redirect_uri={settings.GITHUB_REDIRECT_URI}&scope=user:email"
        return api_response(True, "GitHub login URL generated", data={"auth_url": auth_url})

class GitHubLoginCallbackView(generics.GenericAPIView):
    serializer_class = OAuthCallbackSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        serializer = self.get_serializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]
        try:
            token_res = requests.post("https://github.com/login/oauth/access_token", data={"client_id": settings.GITHUB_CLIENT_ID, "client_secret": settings.GITHUB_CLIENT_SECRET, "code": code}, headers={"Accept": "application/json"}).json()
            access_token = token_res.get("access_token")
            if not access_token:
                return api_response(False, "Failed to get access token from GitHub", status_code=status.HTTP_400_BAD_REQUEST)

            user_info = requests.get("https://api.github.com/user", headers={"Authorization": f"token {access_token}"}).json()
            email = user_info.get("email") or f"{user_info.get('id')}@github.com"
            username = user_info.get("login")

            user, created = User.objects.get_or_create(email=email, defaults={"username": username, "is_verified": True, "login_type": LOGIN_GITHUB})
            if not created:
                user.username = username
                user.is_verified = True
                user.save(update_fields=["username", "is_verified"])

            access_token, refresh_token = generate_jwt_tokens(user)
            redis_client.set(f"refresh_token:{user.id}", refresh_token, ex=7*24*3600)
            redis_client.set(f"refresh_token_user:{refresh_token}", user.id, ex=7*24*3600)

            params = urlencode({"access": access_token, "refresh": refresh_token, "username": username})
            redirect_url = f"{settings.FRONTEND_URL}/github/callback?{params}"
            return redirect(redirect_url)
        except Exception as e:
            logger.error(f"GitHub OAuth error: {str(e)}", exc_info=True)
            return api_response(False, "Internal server error during GitHub OAuth", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# -------------------------
# Role Management
# -------------------------
class ChangeRoleView(generics.GenericAPIView):
    serializer_class = ChangeRoleSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def patch(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.validated_data["user_id"]
        new_role = serializer.validated_data["role"]

        if str(request.user.id) == str(user_id):
            return api_response(False, "SuperAdmin cannot change their own role.", status_code=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(id=user_id, is_active=True).first()
        if not user:
            return api_response(False, "User not found.", status_code=status.HTTP_404_NOT_FOUND)
        if user.role == "SUPERADMIN":
            return api_response(False, "Cannot change role of another SuperAdmin.", status_code=status.HTTP_400_BAD_REQUEST)

        user.role = new_role
        user.save(update_fields=["role"])
        return api_response(True, "Role updated successfully", data={"user_id": str(user.id), "role": user.role})

# -------------------------
# 2FA Management
# -------------------------
class Setup2FAView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_2fa_enabled:
            return api_response(False, "2FA already enabled", status_code=status.HTTP_400_BAD_REQUEST)
        if not user.totp_secret:
            user.generate_2fa_setup()
        totp_uri = user.get_totp_uri()
        qr_code_base64 = generate_totp_qr_code(totp_uri)
        return api_response(True, "TOTP secret generated", data={"totp_uri": totp_uri, "qr_code": qr_code_base64})

class Enable2FAView(generics.GenericAPIView):
    serializer_class = Enable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        if user.verify_totp(token):
            user.is_2fa_enabled = True
            user.save(update_fields=["is_2fa_enabled"])
            return api_response(True, "2FA enabled successfully")
        return api_response(False, "Invalid TOTP token", status_code=status.HTTP_400_BAD_REQUEST)

class Disable2FAView(generics.GenericAPIView):
    serializer_class = Disable2FASerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        if not user.is_2fa_enabled:
            return api_response(False, "2FA not enabled", status_code=status.HTTP_400_BAD_REQUEST)
        if user.verify_totp(token):
            user.is_2fa_enabled = False
            user.totp_secret = None
            user.save(update_fields=["is_2fa_enabled", "totp_secret"])
            return api_response(True, "2FA disabled successfully")
        return api_response(False, "Invalid TOTP token", status_code=status.HTTP_400_BAD_REQUEST)
    
# -------------------------
# Change Password (for logged-in users)
# -------------------------
class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer  # create this serializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        old_password = serializer.validated_data.get("old_password")
        new_password = serializer.validated_data.get("new_password")

        if not user.check_password(old_password):
            return api_response(False, "Old password is incorrect", status_code=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=["password"])

        log_security_event.delay(user.id, "PASSWORD_CHANGED", ip_address=get_client_ip(request))
        return api_response(True, "Password changed successfully")
# -------------------------
# Current User
# -------------------------
class CurrentUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer 
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user