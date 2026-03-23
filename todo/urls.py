from django.urls import path, include
from rest_framework.routers import DefaultRouter
from todo.views import TodoViewSet

# =============================================================
# TODO ROUTER
# =============================================================
router = DefaultRouter()
router.register(r'', TodoViewSet, basename='todo')

# =============================================================
# TODO URLPATTERNS
# =============================================================
urlpatterns = [
    path('', include(router.urls)),
]
