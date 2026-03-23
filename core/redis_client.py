import redis
from django.conf import settings

def get_redis_client():
    if getattr(settings, "REDIS_URL", None):
        return redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            ssl_cert_reqs=None
        )

    return redis.Redis(
        host=getattr(settings, "REDIS_HOST", "127.0.0.1"),
        port=getattr(settings, "REDIS_PORT", 6379),
        db=getattr(settings, "REDIS_DB", 0),
        password=getattr(settings, "REDIS_PASSWORD", None),
        decode_responses=True
    )

redis_client = get_redis_client()
