from django.urls import path, include
from rest_framework_nested import routers
from social.views import (
    PostViewSet, CommentViewSet, 
    ProfileViewSet, FollowViewSet, 
    BookmarkViewSet
)

# -----------------------------
# Main router
# -----------------------------
router = routers.DefaultRouter()
router.register(r'posts', PostViewSet, basename='post')
router.register(r'profiles', ProfileViewSet, basename='profile')
router.register(r'users', FollowViewSet, basename='follow') 
router.register(r'bookmarks', BookmarkViewSet, basename='bookmark')

# -----------------------------
# Nested router for comments under posts
# -----------------------------
comments_router = routers.NestedDefaultRouter(router, r'posts', lookup='post')
comments_router.register(r'comments', CommentViewSet, basename='post-comments')

# -----------------------------
# URL patterns
# -----------------------------
urlpatterns = [
    path('', include(router.urls)),
    path('', include(comments_router.urls)),
]
