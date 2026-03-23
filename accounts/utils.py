import qrcode
import io
import base64
from django.contrib.sessions.models import Session
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

def get_user_sessions(user):
    """
    Return all active sessions for the given user.
    """
    sessions = []
    all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    for session in all_sessions:
        data = session.get_decoded()
        if str(user.id) == str(data.get("_auth_user_id")):
            sessions.append({
                "session_key": session.session_key,
                "ip": data.get("ip", "Unknown"),
                "user_agent": data.get("user_agent", ""),
                "last_activity": session.expire_date - timezone.timedelta(seconds=1800),
                "expire_date": session.expire_date,
            })
    return sessions

def revoke_session(session_key):
    """
    Revoke a single session by session_key.
    """
    try:
        Session.objects.get(session_key=session_key).delete()
    except Session.DoesNotExist:
        pass

def revoke_all_sessions(user):
    """
    Revoke all sessions for the user.
    """
    all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    for session in all_sessions:
        data = session.get_decoded()
        if str(user.id) == str(data.get("_auth_user_id")):
            session.delete()


def get_client_ip(request):
    """Get client IP address from request headers"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def generate_totp_qr_code(uri):
    """
    Generate QR code for TOTP URI and return as base64 image.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"
