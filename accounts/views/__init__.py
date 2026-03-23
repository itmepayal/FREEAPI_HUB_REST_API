# accounts/views/__init__.py

# -------------------------
# 2FA Views
# -------------------------
from .twofa_views import Setup2FAView, Enable2FAView, Disable2FAView

# -------------------------
# Avatar Views
# -------------------------
from .avatar_views import UpdateAvatarView

# -------------------------
# OAuth Views
# -------------------------
from .oauth_views import GoogleLoginView, GoogleLoginCallbackView, GitHubLoginView, GitHubLoginCallbackView

# -------------------------
# Role Views
# -------------------------
from .role_views import ChangeRoleView

# -------------------------
# Auth Views
# -------------------------
from .auth_views import RegisterView, LoginView, LogoutView, CurrentUserView, RefreshTokenView

# -------------------------
# Email Views
# -------------------------
from .email_views import VerifyEmailView, ResendEmailView

# -------------------------
# Password Views
# -------------------------
from .password_views import ForgotPasswordView, ResetPasswordView, ChangePasswordView

# -------------------------
# Session Views
# -------------------------
from .session_views import ListUserSessionsView,RevokeUserSessionView,RevokeOtherSessionsView, RevokeAllSessionsView

