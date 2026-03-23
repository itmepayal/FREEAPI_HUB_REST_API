# ============================================================
# Imports
# ============================================================
import secrets
import hashlib
import logging
from datetime import timedelta
from threading import Thread
from smtplib import SMTPException
from typing import Optional, Union

from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import status, serializers
from rest_framework.response import Response

from accounts.emails import EMAIL_TEMPLATES

# ============================================================
# Logger Configuration
# ============================================================
logger = logging.getLogger(__name__)

# ============================================================
# Helper Functions
# ============================================================
def get_client_ip(req):
    """
    Extracts the client IP address from the Django request object.
    """
    xff = req.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return req.META.get("REMOTE_ADDR")

# ============================================================
# Temporary Token Generator
# ============================================================
def generate_temporary_token(expiry_minutes: int = 20):
    """
    Generates a secure temporary token with an expiry time.

    Returns:
        tuple:
            un_hashed (str): Token to send to the user.
            hashed (str): Hashed token for database storage.
            expiry (datetime): Expiry timestamp.
    """
    un_hashed = secrets.token_hex(20)
    hashed = hashlib.sha256(un_hashed.encode()).hexdigest()
    expiry = timezone.now() + timedelta(minutes=expiry_minutes)
    return un_hashed, hashed, expiry

# ============================================================
# Standardized API Response
# ============================================================
def api_response(
    success: bool,
    message: str,
    data: Optional[Union[dict, list]] = None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """
    Returns a standardized API response for DRF views.

    Args:
        success (bool): True/False indicator.
        message (str): Human-readable message.
        data (dict | list, optional): Payload data.
        status_code (int, optional): HTTP status code (default: 200).

    Returns:
        Response: DRF Response object.
    """
    response = {
        "success": success,
        "message": message,
        "data": data or {},
    }
    return Response(response, status=status_code)

# ============================================================
# Email Sending Utilities
# ============================================================
def _send_email_sync(to_email: str, subject: str, template_name: str = "generic", context: dict = None):
    """
    Sends an email synchronously using the specified template.
    Raises an exception if the email fails to send.
    """
    from_email = getattr(settings, "EMAIL_FROM", None)
    if not from_email:
        raise ValueError("EMAIL_FROM is not configured in settings.")

    template = EMAIL_TEMPLATES.get(template_name, EMAIL_TEMPLATES["generic"])
    context = context or {}

    try:
        message = template.format(**context)
    except KeyError as e:
        raise ValueError(f"Missing context key for email template: {e}")

    try:
        send_mail(subject, message, from_email, [to_email], fail_silently=False)
        logger.info(f"Email sent to {to_email}")
    except SMTPException as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        raise Exception("Failed to send email.")

# ============================================================
# Asynchronous Email Sender
# ============================================================
def send_email(to_email: str, subject: str, template_name: str = "generic", context: dict = None):
    """
    Sends an email asynchronously using a background thread.

    Examples:
        send_email("user@example.com", "Welcome!", "welcome", {"username": "John"})
        send_email("user@example.com", "Reset Password", "reset_password", {"username": "John", "reset_link": "link"})
    """
    Thread(
        target=_send_email_sync,
        args=(to_email, subject, template_name, context),
        daemon=True
    ).start()
