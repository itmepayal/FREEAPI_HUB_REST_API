from celery import shared_task
from core.logger import get_logger
from core.utils import send_email as send_email_sync
from accounts.models import SecurityLog, User


logger = get_logger(__name__)

# ------------------------
# Send email async
# ------------------------
@shared_task
def send_email_async(to_email, subject, template_name, context):
    try:
        send_email_sync(to_email, subject, template_name, context)
        logger.info(f"Async email sent to {to_email} | template: {template_name}")
    except Exception as e:
        logger.error(f"Error sending async email to {to_email}: {str(e)}", exc_info=True)

# ------------------------
# Log security event async
# ------------------------
@shared_task
def log_security_event(user_id, event_type, **kwargs):
    """
    Logs security events for a user.
    
    Required:
        user_id: int
        event_type: str
    
    Optional (via kwargs):
        device: str
        ip: str
        additional_data: dict
    """
    device = kwargs.get("device")
    ip = kwargs.get("ip")
    additional_data = kwargs.get("additional_data", {})

    user = User.objects.filter(id=user_id).first()
    if not user:
        return f"User {user_id} not found"

    SecurityLog.objects.create(
        user=user,
        event_type=event_type,
        device=device,
        ip_address=ip,
        metadata=additional_data,
    )

    return f"Security event logged for user {user_id}"