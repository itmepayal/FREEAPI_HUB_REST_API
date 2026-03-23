from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),

    # OpenAPI Schema
    path("api/v1/schema/", SpectacularAPIView.as_view(), name="schema"),

    # Swagger UI
    path("", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),

    # ReDoc UI
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),

    # Apps
    path("api/v1/accounts/", include(("accounts.urls", "accounts"), namespace="accounts")),
    path("api/v1/todo/", include(("todo.urls", "todo"), namespace="todo")),
    path("api/v1/social/", include(("social.urls", "social"), namespace="social")),
    path("api/v1/shop/", include(("shop.urls", "shop"), namespace="shop")),
    path("api/v1/chats/", include(("chat.urls", "chat"), namespace="chat")),
    path("api/v1/public/", include(("public.urls", "public"), namespace="public")),
    path("api/v1/kitchen/", include(("kitchen.urls", "kitchen"), namespace="kitchen")),

    # Health check
    path("api/v1/health/", include(("health.urls", "health"), namespace="health")),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
