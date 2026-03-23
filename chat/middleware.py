import jwt
from django.conf import settings
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from accounts.models import User
from urllib.parse import parse_qs

@database_sync_to_async
def get_user_from_token(token):
    """Decode JWT and return a user if valid."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user = User.objects.get(id=payload.get("user_id"))
        return user
    except Exception:
        return None

class JWTAuthMiddleware(BaseMiddleware):
    """Custom Channels middleware for JWT authentication."""
    async def __call__(self, scope, receive, send):
        query_string = scope.get("query_string", b"").decode()
        query_params = parse_qs(query_string)
        token_list = query_params.get("token", [])

        if token_list:
            token = token_list[0]
            user = await get_user_from_token(token)
            if user:
                scope["user"] = user

        return await super().__call__(scope, receive, send)
