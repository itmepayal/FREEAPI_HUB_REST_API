from drf_spectacular.utils import OpenApiExample, extend_schema, OpenApiResponse
from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    ChangePasswordSerializer,
    ChangeRoleSerializer,
    UpdateAvatarSerializer,
    RefreshTokenInputSerializer,
    Setup2FASerializer,
    Enable2FASerializer,
    OAuthCallbackSerializer,
    ResendEmailVerificationSerializer,
    VerifyEmailSerializer
)

# =============================================================
# Register Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
register_request_example = OpenApiExample(
    name="User Registration Request",
    summary="Example payload for registering a new user",
    value={
        "email": "tarun@gmail.com",
        "username": "tarun",
        "password": "strongpassword123"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
register_success_example = OpenApiExample(
    name="User Registration Success Response",
    summary="Example response after successful user registration",
    value={
        "success": True,
        "message": "User registered successfully. Please verify your email.",
        "data": {
            "user": {
                "id": "771832e0-c5f8-4e19-92d1-c370953e4039",
                "email": "tarun@gmail.com",
                "username": "tarun",
                "role": "USER",
                "is_verified": False,
                "avatar_url": "https://ui-avatars.com/api/?name=tarun&size=200",
                "is_2fa_enabled": False
            }
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Registration View
# ----------------------------
register_schema = extend_schema(
    request=RegisterSerializer,
    examples=[register_request_example],
    responses={
        201: OpenApiResponse(
            response=RegisterSerializer,
            description="User registered successfully",
            examples=[register_success_example]
        )
    },
    description=(
        "Register a new user account, trigger email verification, "
        "and return the user details wrapped in a standardized success response."
    )
)

# =============================================================
# Login Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
login_request_example = OpenApiExample(
    name="User Login Request",
    summary="Example payload for user login",
    value={
        "email": "tarun@gmail.com",
        "password": "strongpassword123"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
login_success_example = OpenApiExample(
    name="User Login Success Response",
    summary="Example response after successful login",
    value={
        "success": True,
        "message": "Login successful",
        "data": {
            "user": {
                "id": "fdd611a1-83ac-4ecb-b06d-22c9512b82b9",
                "email": "tarun@gmail.com",
                "username": "tarun",
                "role": "SUPERADMIN",
                "is_verified": True,
                "avatar_url": "App_download_banner (1).png",
                "is_2fa_enabled": False
            },
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Login View
# ----------------------------
login_schema = extend_schema(
    request=LoginSerializer,
    examples=[login_request_example],
    responses={
        200: OpenApiResponse(
            response=LoginSerializer, 
            description="Login successful, returns user info with JWT tokens",
            examples=[login_success_example]
        )
    },
    description=(
        "Authenticate a user with email and password, and return the user details "
        "along with access and refresh JWT tokens."
    )
)


# =============================================================
# Resend Verification Email Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
resend_email_request_example = OpenApiExample(
    name="Resend Verification Email Request",
    summary="Example payload to request a verification email resend",
    value={
        "email": "tarun@gmail.com"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
resend_email_success_example = OpenApiExample(
    name="Resend Verification Email Success Response",
    summary="Example response after successfully resending verification email",
    value={
        "success": True,
        "message": "Verification email resent successfully.",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Resend Verification Email View
# ----------------------------
resend_verification_email_schema = extend_schema(
    request=ResendEmailVerificationSerializer, 
    examples=[resend_email_request_example],
    responses={
        200: OpenApiResponse(
            response=ResendEmailVerificationSerializer, 
            description="Verification email resent successfully",
            examples=[resend_email_success_example]
        )
    },
    description=(
        "Resend the email verification link to the user's email address. "
        "Returns a standardized success response."
    )
)

# =============================================================
# Verify Email Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
verify_email_request_example = OpenApiExample(
    name="Verify Email Request",
    summary="Example payload for verifying a user's email",
    value={
        "token": "d474f4c21c2634e3b8a0f212fbcfcb01e7c105cc"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
verify_email_success_example = OpenApiExample(
    name="Verify Email Success Response",
    summary="Example response after successful email verification",
    value={
        "success": True,
        "message": "Email verified successfully",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Verify Email View
# ----------------------------
verify_email_schema = extend_schema(
    request=VerifyEmailSerializer,
    examples=[verify_email_request_example],
    responses={
        200: OpenApiResponse(
            response=VerifyEmailSerializer,  
            description="Email verified successfully",
            examples=[verify_email_success_example]
        )
    },
    description=(
        "Verify a user's email using the token sent to their email address. "
        "Returns a standardized success response upon successful verification."
    )
)

# =============================================================
# Forgot Password Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
forgot_password_request_example = OpenApiExample(
    name="Forgot Password Request",
    summary="Payload for requesting a password reset link",
    value={
        "email": "tarun@gmail.com"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
forgot_password_success_example = OpenApiExample(
    name="Forgot Password Success Response",
    summary="Example response after successfully sending reset link",
    value={
        "success": True,
        "message": "Reset link sent successfully.",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Forgot Password View
# ----------------------------
forgot_password_schema = extend_schema(
    request=ForgotPasswordSerializer,
    examples=[forgot_password_request_example],
    responses={
        200: OpenApiResponse(
            response=ForgotPasswordSerializer,  
            description="Password reset link sent successfully",
            examples=[forgot_password_success_example]
        )
    },
    description=(
        "Request a password reset link to be sent to the user's email. "
        "Returns a standardized success response confirming the link was sent."
    )
)

# =============================================================
# Reset Password Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
reset_password_request_example = OpenApiExample(
    name="Reset Password Request",
    summary="Example payload for resetting a user's password",
    value={
        "token": "2ccca0017b38a3f37575311878e02b0ca249e6e7",
        "new_password": "Tarun@123"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
reset_password_success_example = OpenApiExample(
    name="Reset Password Success Response",
    summary="Example response after successfully resetting password",
    value={
        "success": True,
        "message": "Password reset successful",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Reset Password View
# ----------------------------
reset_password_schema = extend_schema(
    request=ResetPasswordSerializer,
    examples=[reset_password_request_example],
    responses={
        200: OpenApiResponse(
            response=ResetPasswordSerializer,
            description="Password reset successful",
            examples=[reset_password_success_example]
        )
    },
    description=(
        "Reset a user's password using the provided token and new password. "
        "Returns a standardized success response upon successful reset."
    )
)

# =============================================================
# Refresh Token Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
refresh_request_example = OpenApiExample(
    name="Refresh Token Request",
    summary="Example payload to refresh the JWT access token",
    value={
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
refresh_response_example = OpenApiExample(
    name="Refresh Token Response",
    summary="Example response after successful token refresh",
    value={
        "success": True,
        "message": "Token refreshed successfully",
        "data": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
    },
    response_only=True
)


# ----------------------------
# Extend Schema for Refresh Token View
# ----------------------------
refresh_token_schema = extend_schema(
    request=RefreshTokenInputSerializer,
    examples=[refresh_request_example],
    responses={
        200: OpenApiResponse(
            response=RefreshTokenInputSerializer,  
            description="Refresh the JWT access token using a valid refresh token",
            examples=[refresh_response_example]
        )
    },
    description=(
        "Refresh the JWT access token using a valid refresh token. "
        "Returns the new access token wrapped in a standardized success response."
    )
)

# =============================================================
# Change Password Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
change_password_request_example = OpenApiExample(
    name="Change Password Request",
    summary="Example payload for changing a user's password",
    value={
        "old_password": "currentPassword123",
        "new_password": "newStrongPassword@123"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
change_password_success_example = OpenApiExample(
    name="Change Password Success Response",
    summary="Example response after successfully changing the password",
    value={
        "success": True,
        "message": "Password changed successfully",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Change Password View
# ----------------------------
change_password_schema = extend_schema(
    request=ChangePasswordSerializer,
    examples=[change_password_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Password changed successfully",
            examples=[change_password_success_example]
        )
    },
    description=(
        "Allows an authenticated user to change their password. "
        "Requires the current (old) password and a new password. "
        "Returns a standardized success or error response."
    )
)

# =============================================================
# Logout Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
logout_request_example = OpenApiExample(
    name="Logout Request",
    summary="Example payload to logout a user using the refresh token",
    value={
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
logout_success_example = OpenApiExample(
    name="Logout Success Response",
    summary="Example response after successful logout",
    value={
        "success": True,
        "message": "Logged out successfully",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Logout View
# ----------------------------
logout_schema = extend_schema(
    request=RefreshTokenInputSerializer,  
    examples=[logout_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="User logged out successfully",
            examples=[logout_success_example]
        )
    },
    description=(
        "Logout the user by invalidating the refresh token. "
        "Returns a standardized success response upon successful logout."
    )
)

# =============================================================
# Change Role Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
change_role_request_example = OpenApiExample(
    name="Change Role Request",
    summary="Example payload to change a user's role",
    value={
        "user_id": "47d87650-bfc9-4fd5-bab7-ef30f681bd25",
        "role": "ADMIN"
    },
    request_only=True
)

# ----------------------------
# Response Example 
# ----------------------------
change_role_success_example = OpenApiExample(
    name="Change Role Success Response",
    summary="Example response after successfully changing a user's role",
    value={
        "success": True,
        "message": "Role updated successfully to ADMIN",
        "data": {
            "user_id": "47d87650-bfc9-4fd5-bab7-ef30f681bd25",
            "role": "ADMIN"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Change Role View
# ----------------------------
change_role_schema = extend_schema(
    request=ChangeRoleSerializer,
    examples=[change_role_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Role updated successfully",
            examples=[change_role_success_example]
        )
    },
    description=(
        "Change the role of a user by providing their user ID and the new role. "
        "Returns a standardized success or error response."
    )
)

# =============================================================
# Setup 2fa Swagger
# =============================================================

# ----------------------------
# Request Example 
# ----------------------------
setup_2fa_request_example = OpenApiExample(
    name="Setup 2FA Request",
    summary="Request to initialize 2FA for an authenticated user",
    value={},  
    request_only=True
)

# ----------------------------
# Response Example 
# ----------------------------
setup_2fa_success_example = OpenApiExample(
    name="Setup 2FA Success Response (200)",
    summary="TOTP secret generated successfully",
    value={
        "success": True,
        "message": "TOTP secret generated successfully.",
        "data": {
            "totp_uri": "otpauth://totp/freeapi@gmail.com?secret=E6FLAALTNTDNXWUMXPQW3IRQ7VDTWP6U&issuer=config",
            "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAcIAAAHCAQAAAABUY/ToAAADu0lEQVR4nO2cQW7jOBBFXw0JeCkBOUAfhbpBHymYI+UG4lF8gADScgAafxYkZcndMwMEDuxkqhaJKetBFEAUq34VbeJjlv/4IAhOOumkk0466aSTz0daswissQ7J48VgNSPXL/pd04Nn6+RTkkmStIBNgGbAXs8RmwYJuJhNBEmSjuTHn+nkNyFj+7+OkN5AUDCG96j8Q5AtFEvLWO8yCOWBs3XyGcl4M66rJL3VzQvS8gJ5DAXWez3Tye9F3q4h5Z8LghKrM4KCWF+w9HavZzr5vci+hgYBKxjDJZLmIPIUAS4Rhr8MgL0g+bXe08lPJ7OZmY1AOp9Uk7PXJcim9aR2jUtNyx4/Wyefiqx+6OpflEdMrEAeAzAU6rC6qns808nvRbJL19MCddG0a0GkJdRPmodC/SNJmr/Wezr5eWRbL235SFJdNCCpoHmQSJJIKu2aryEnf0sGNU36R2kao9lJNq22F6vz2GTIL/ueTt6dbF6lupahVMW6bmgzIC1AWoLaUO0W90NO/kJejHSO6E+LkM4RIMgmglrljKBWUnv8bJ18IrLHQyrAILWgqA81D81J1Xho7oT7ISc3aznYIZzuJdiWl7VsbAl1k/O9zMmjNa9COHiapQ1bNnZI8H0NOXmwGt4Yw7uRbbs8FGB9EXlcZBBQni5GOp9kj5utk89IbvFQi326qEiVhq5uqWmMvYnI/ZCTm+3bygh1V9MM9BgJ9vEQ+F7m5I1d/VDbwYaDPtR06lIrIVfZ2teQk91azTVbKGKNkN5i70EjFFhjUbYg8hiKQfQ+RidvTEfb6UNNM+radcvQXB9y8tb2NVcO1YyW4Leg6Lqh+V7m5NGupbIeOrPpif2LGlgDNVryNeTk3rZzHRGDU8/QhoLyZKgJQqEAoRjrpiF9rfd08vPIbS8L6oLQtX+ohUdVM0pLkMdDTv4raVPtou77Vh5BOkc0c7H9ffd7ppPfgNydDVL++V5bqY3hPbId6RBDib2pukQ9brZOPjV5MVgjLZk/t5P30vmk2r1o48VsWr1/yMlb+0d9aJflz7CJRN08HnKy2029rHd89HD6ergjef+Qk7+3a72sluc3fejmi6sf8jXk5NF2OnXqnWd1G4Nesp+Hst3vvR9O/heZxyAzO9WVUoPo7VzHtSbyJLN18hnJVAUh6hl8zfVwB9hr75S16d7PdPJLk7e/+wH01tgksLSMVn/hKluPqR83WyefkfwlL2vFjTbcBdZb9dVjaicPZv4b50466aSTTjrp5P+c/Btk6ztNLR1/RQAAAABJRU5ErkJggg=="
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Setup 2fa View
# ----------------------------
setup_2fa_schema = extend_schema(
    request=Setup2FASerializer,
    examples=[setup_2fa_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="TOTP secret generated successfully",
            examples=[setup_2fa_success_example]
        )
    },
    description="Setup Two-Factor Authentication (2FA) for an authenticated user."
)

# =============================================================
# Enable 2fa Swagger
# =============================================================
# ----------------------------
# Request Example
# ----------------------------
enable_2fa_request_example = OpenApiExample(
    name="Enable 2FA Request",
    summary="Payload to enable 2FA by submitting the TOTP token",
    value={
        "token": "005118"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
enable_2fa_success_example = OpenApiExample(
    name="Enable 2FA Success Response",
    summary="Response after 2FA is successfully enabled",
    value={
        "success": True,
        "message": "2FA enabled successfully.",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Setup 2FA View
# ----------------------------
enable_2fa_schema = extend_schema(
    request=Enable2FASerializer,
    examples=[enable_2fa_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="2FA enabled successfully",
            examples=[enable_2fa_success_example]
        )
    },
    description=(
        "Enable Two-Factor Authentication (2FA) for an authenticated user. "
        "User must submit the TOTP token generated by their authenticator app. "
        "Returns a standardized success response upon enabling 2FA."
    )
)

# =============================================================
# Disable 2fa Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
disable_2fa_request_example = OpenApiExample(
    name="Disable 2FA Request",
    summary="Payload to disable 2FA by submitting the TOTP token",
    value={
        "token": "495369"
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
disable_2fa_success_example = OpenApiExample(
    name="Disable 2FA Success Response",
    summary="Response after 2FA is successfully disabled",
    value={
        "success": True,
        "message": "2FA disabled successfully.",
        "data": {}
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Disable 2FA View
# ----------------------------
disable_2fa_schema = extend_schema(
    request=Enable2FASerializer, 
    examples=[disable_2fa_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="2FA disabled successfully",
            examples=[disable_2fa_success_example]
        )
    },
    description=(
        "Disable Two-Factor Authentication (2FA) for an authenticated user. "
        "User must submit the current TOTP token to confirm disabling. "
        "Returns a standardized success response upon disabling 2FA."
    )
)

# =============================================================
# Get Current User Swagger
# =============================================================

# ----------------------------
# Response Example
# ----------------------------
get_current_user_success_example = OpenApiExample(
    name="Get Current User Success Response",
    summary="Example response for retrieving the current authenticated user",
    value={
        "success": True,
        "message": "Current user retrieved successfully",
        "data": {
            "id": "fdd611a1-83ac-4ecb-b06d-22c9512b82b9",
            "email": "freeapi@gmail.com",
            "username": "freeapi",
            "role": "SUPERADMIN",
            "is_verified": True,
            "avatar_url": "https://res.cloudinary.com/demo/image/upload/v1730999999/App_download_banner_1.png",
            "is_2fa_enabled": False
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Get Current User View
# ----------------------------
get_current_user_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Current user retrieved successfully",
            examples=[get_current_user_success_example]
        )
    },
    description=(
        "Retrieve details of the currently authenticated user. "
        "Returns user information such as ID, email, username, role, "
        "verification status, avatar URL, and 2FA status."
    )
)

# =============================================================
# Update Avatar Swagger
# =============================================================

# ----------------------------
# Request Example
# ----------------------------
update_avatar_request_example = OpenApiExample(
    name="Update Avatar Request",
    summary="Example payload for updating a user's avatar",
    value={
        "avatar": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
    },
    request_only=True
)

# ----------------------------
# Response Example
# ----------------------------
update_avatar_success_example = OpenApiExample(
    name="Update Avatar Success Response",
    summary="Example response after successfully updating the avatar",
    value={
        "success": True,
        "message": "Avatar updated successfully",
        "data": {
            "avatar": "https://res.cloudinary.com/doqb7czvi/image/upload/v1762587476/avatars/App_download_banner_1_ac3azk.png"
        }
    },
    response_only=True
)

# ----------------------------
# Extend Schema for Update Avatar View
# ----------------------------
update_avatar_schema = extend_schema(
    request=UpdateAvatarSerializer,
    examples=[update_avatar_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Avatar updated successfully",
            examples=[update_avatar_success_example]
        )
    },
    description=(
        "Upload or update the profile avatar of the authenticated user. "
        "Accepts an image file or base64-encoded image, uploads it to Cloudinary, "
        "and returns the new avatar URL in a standardized success response."
    )
)

# =============================================================
# GOOGLE Swagger
# =============================================================
# ----------------------------
# Google Login URL
# ----------------------------
google_login_success_example = OpenApiExample(
    name="Google Login URL Response",
    summary="Response after generating Google OAuth login URL",
    value={
        "success": True,
        "message": "Google login URL generated successfully",
        "data": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=YOUR_CLIENT_ID&redirect_uri=..."
        }
    },
    response_only=True
)

google_login_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=dict,
            description="Google login URL generated successfully",
            examples=[google_login_success_example]
        )
    },
    description="Generates Google OAuth login URL for client-side redirection."
)

# ----------------------------
# Google OAuth Callback
# ----------------------------
google_callback_request_example = OpenApiExample(
    name="Google OAuth Callback Request",
    summary="Example callback payload from Google OAuth",
    value={"code": "4/0AX4XfWhEJSk..."},
    request_only=True
)

google_callback_success_example = OpenApiExample(
    name="Google OAuth Callback Success Response",
    summary="Example successful login/registration via Google OAuth",
    value={
        "success": True,
        "message": "Google login successful",
        "data": {
            "user": {
                "email": "testuser@gmail.com",
                "username": "Test User",
                "is_verified": True,
                "login_type": "GOOGLE"
            },
            "access": "eyJhbGciOiJIUzI1NiIs...",
            "refresh": "eyJhbGciOiJIUzI1NiIs..."
        }
    },
    response_only=True
)

google_callback_schema = extend_schema(
    request=OAuthCallbackSerializer,
    examples=[google_callback_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="User authenticated successfully via Google OAuth",
            examples=[google_callback_success_example]
        )
    },
    description="Handles Google OAuth callback, exchanges code for tokens, and authenticates the user."
)

# =============================================================
# GITHUB Swagger
# =============================================================

# ----------------------------
# GitHub Login URL
# ----------------------------
github_login_success_example = OpenApiExample(
    name="GitHub Login URL Response",
    summary="Response after generating GitHub OAuth login URL",
    value={
        "success": True,
        "message": "GitHub login URL generated successfully",
        "data": {
            "auth_url": "https://github.com/login/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=..."
        }
    },
    response_only=True
)

github_login_schema = extend_schema(
    request=None,
    responses={
        200: OpenApiResponse(
            response=dict,
            description="GitHub login URL generated successfully",
            examples=[github_login_success_example]
        )
    },
    description="Generates GitHub OAuth login URL for client-side redirection."
)

# ----------------------------
# GitHub OAuth Callback
# ----------------------------
github_callback_request_example = OpenApiExample(
    name="GitHub OAuth Callback Request",
    summary="Example callback payload from GitHub OAuth",
    value={"code": "df8a49eaccc3a8df"},
    request_only=True
)

github_callback_success_example = OpenApiExample(
    name="GitHub OAuth Callback Success Response",
    summary="Example successful login/registration via GitHub OAuth",
    value={
        "success": True,
        "message": "GitHub login successful",
        "data": {
            "user": {
                "email": "testuser@github.com",
                "username": "testuser",
                "is_verified": True,
                "login_type": "GITHUB"
            },
            "access": "eyJhbGciOiJIUzI1NiIs...",
            "refresh": "eyJhbGciOiJIUzI1NiIs..."
        }
    },
    response_only=True
)

github_callback_schema = extend_schema(
    request=OAuthCallbackSerializer,
    examples=[github_callback_request_example],
    responses={
        200: OpenApiResponse(
            response=dict,
            description="User authenticated successfully via GitHub OAuth",
            examples=[github_callback_success_example]
        )
    },
    description="Handles GitHub OAuth callback, exchanges code for tokens, and authenticates the user."
)
