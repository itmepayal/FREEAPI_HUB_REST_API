import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_asgi_application()

# import os
# from django.core.asgi import get_asgi_application
# from channels.routing import ProtocolTypeRouter, URLRouter

# # -------------------------------
# # Django setup
# # -------------------------------
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
# django_asgi_app = get_asgi_application()

# # -------------------------------
# # Import after settings are loaded
# # -------------------------------
# # from chat.middleware import JWTAuthMiddleware
# # from chat import routing

# # -------------------------------
# # Main ASGI application
# # -------------------------------
# # application = ProtocolTypeRouter({
# #     "http": django_asgi_app,
# #     "websocket": JWTAuthMiddleware(
# #         URLRouter(routing.websocket_urlpatterns)
# #     ),
# # })
