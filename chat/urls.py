from rest_framework.routers import DefaultRouter
from chat.views import ChatViewSet

router = DefaultRouter()
router.register(r"", ChatViewSet, basename="chats")

urlpatterns = router.urls