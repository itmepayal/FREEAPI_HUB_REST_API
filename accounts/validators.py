import re
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password as django_validate_password

def validate_strong_password(value: str):
    django_validate_password(value) 

    if len(value) < 8:
        raise ValidationError("Password must be at least 8 characters.")
    if not re.search(r'[A-Z]', value):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'\d', value):
        raise ValidationError("Password must contain at least one digit.")

    return value


def validate_totp_token(value: str):
    if not value.isdigit() or len(value) != 6:
        raise ValidationError("TOTP token must be a 6-digit number.")
    return value


def validate_username(value: str):
    if not re.match(r'^[A-Za-z0-9_]{3,30}$', value):
        raise ValidationError("Username must be 3-30 characters, alphanumeric or underscores only.")
    return value