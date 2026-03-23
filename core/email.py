import sendgrid
from sendgrid.helpers.mail import Mail, Email
from django.core.mail.backends.base import BaseEmailBackend
from django.conf import settings
from decouple import config
import logging

logger = logging.getLogger(__name__)

# ----------------------------
# SendGrid Email Backend
# ----------------------------
class SendGridBackend(BaseEmailBackend):
    """
    Django email backend for SendGrid API.

    Usage:
        send_mail(
            "Subject",
            "Body",
            settings.EMAIL_FROM,
            ["recipient@example.com"]
        )
    """

    # ----------------------------
    # Initialization
    # ----------------------------
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        api_key = config("SENDGRID_API_KEY", default=None)
        if not api_key:
            raise ValueError("SENDGRID_API_KEY is not set in environment variables.")
        self.sg = sendgrid.SendGridAPIClient(api_key=api_key)

        self.from_email = getattr(settings, "EMAIL_FROM", None)
        if not self.from_email:
            raise ValueError("EMAIL_FROM is not set in settings.")

    # ----------------------------
    # Send Emails
    # ----------------------------
    def send_messages(self, email_messages):
        """
        Sends one or more EmailMessage objects and returns the number of emails sent.
        """
        num_sent = 0

        for message in email_messages:
            try:
                mail = Mail(
                    from_email=Email(self.from_email),
                    to_emails=message.to,
                    subject=message.subject,
                    plain_text_content=message.body
                )

                response = self.sg.send(mail)

                if 200 <= response.status_code < 300:
                    num_sent += 1
                else:
                    logger.error(
                        f"SendGrid API failed with status {response.status_code}, body={response.body}"
                    )

            except Exception as e:
                logger.error(f"Failed to send email to {message.to}: {str(e)}")
                if not self.fail_silently:
                    raise e

        return num_sent

