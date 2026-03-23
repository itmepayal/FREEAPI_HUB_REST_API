from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from social.models import (
    Post, PostImage, Like, Bookmark, 
    Profile, Comment, Follow
)
from social.serializers import (
    PostSerializer, PostImageSerializer, 
    PostFilter, ProfileFilter, ProfileSerializer, 
    CommentSerializer, FollowSerializer
)
from core.utils import api_response
from core.throttles import FreeAnonThrottle, FreeUserThrottle
from core.permissions import IsOwnerOrAdmin
from core.constants import LIKE_POST, COMMENT, LIKE_COMMENT, FOLLOW
from accounts.models import User

# =============================================================
# POST VIEWSET
# =============================================================
class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.filter(deleted_at__isnull=True, is_active=True)  
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    throttle_classes = [FreeUserThrottle, FreeAnonThrottle]

    filterset_class = PostFilter
    search_fields = ['title', 'content']
    ordering_fields = ['created_at', 'updated_at', 'title']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        with transaction.atomic():
            serializer.save(author=self.request.user)

    def get_queryset(self):
        user = self.request.user
        queryset = super().get_queryset()
        if not user.is_staff:
            queryset = queryset.filter(Q(is_public=True) | Q(author=user))
        return queryset.select_related('author').prefetch_related('images', 'likes', 'comments')

    # -----------------------------
    # My posts
    # -----------------------------
    @action(detail=False, methods=["get"])
    def me(self, request):
        posts = self.get_queryset().filter(author=request.user, is_active=True)
        serializer = self.get_serializer(posts, many=True)
        return api_response(True, "My posts fetched successfully", serializer.data)

    # -----------------------------
    # Update post
    # -----------------------------
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        post = self.get_object()
        serializer = self.get_serializer(post, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Post updated successfully", serializer.data)

    # -----------------------------
    # Soft delete post
    # -----------------------------
    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        post = self.get_object()
        post.soft_delete()
        return api_response(True, "Post deleted successfully")

    # -----------------------------
    # Upload images
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def images(self, request, pk=None):
        post = self.get_object()
        if post.author != request.user:
            return api_response(False, "Not allowed", status.HTTP_403_FORBIDDEN)
        files = request.FILES.getlist("images")
        if not files:
            return api_response(False, "No images uploaded", status.HTTP_400_BAD_REQUEST)

        images_data = []
        for f in files:
            if f.size > 5 * 1024 * 1024 or not f.content_type.startswith("image/"):
                return api_response(False, "Invalid image file", status.HTTP_400_BAD_REQUEST)
            post_image = PostImage(post=post)
            post_image._image_file = f
            post_image.save()
            images_data.append(PostImageSerializer(post_image).data)

        return api_response(True, f"{len(images_data)} images uploaded successfully", images_data)

    # -----------------------------
    # Feed 
    # -----------------------------
    @action(detail=False, methods=["get"])
    def feed(self, request):
        user = request.user
        followees = user.following.filter(followee__is_active=True).values('followee')
        posts = self.get_queryset().filter(author__in=followees)
        page = self.paginate_queryset(posts)
        serializer = self.get_serializer(page or posts, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return api_response(True, "Feed fetched successfully", serializer.data)

    # -----------------------------
    # Like post 
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def like(self, request, pk=None):
        post = self.get_object()
        if Like.objects.filter(post=post, liked_by=request.user, is_active=True).exists():
            return api_response(False, "Already liked", status.HTTP_400_BAD_REQUEST)

        like = Like.objects.create(post=post, liked_by=request.user)
        return api_response(True, "Post liked successfully")

    # -----------------------------
    # Unlike post
    # -----------------------------
    @action(detail=True, methods=["delete"])
    @transaction.atomic
    def unlike(self, request, pk=None):
        post = self.get_object()
        like = Like.objects.filter(post=post, liked_by=request.user, is_active=True).first()
        if not like:
            return api_response(False, "You haven't liked this post", status.HTTP_400_BAD_REQUEST)
        like.delete()
        return api_response(True, "Post unliked successfully")

    # -----------------------------
    # Bookmark post
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def bookmark(self, request, pk=None):
        post = self.get_object()
        bookmark = Bookmark.objects.filter(post=post, bookmarked_by=request.user, is_active=True).first()
        if bookmark:
            bookmark.is_active = not bookmark.is_active
            bookmark.save(update_fields=["is_active"])
            message = "Bookmark removed" if not bookmark.is_active else "Bookmark added"
        else:
            Bookmark.objects.create(post=post, bookmarked_by=request.user)
            message = "Post bookmarked successfully"

        bookmarks_count = Bookmark.objects.filter(post=post, is_active=True).count()
        return api_response(
            True,
            message,
            data={
                "bookmarked": bookmark.is_active if bookmark else True,
                "bookmarks_count": bookmarks_count,
            }
        )

    # -----------------------------
    # Check bookmark status
    # -----------------------------
    @action(detail=True, methods=["get"])
    def check_bookmark(self, request, pk=None):
        post = self.get_object()
        is_bookmarked = Bookmark.objects.filter(
            post=post,
            bookmarked_by=request.user,
            is_active=True
        ).exists()
        bookmarks_count = Bookmark.objects.filter(post=post, is_active=True).count()
        return api_response(True, "Bookmark status fetched successfully", {
            "bookmarked": is_bookmarked,
            "bookmarks_count": bookmarks_count
        })

# =============================================================
# PROFILE VIEWSET
# =============================================================
class ProfileViewSet(viewsets.GenericViewSet):
    queryset = Profile.objects.filter(owner__is_active=True)  
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    throttle_classes = [FreeUserThrottle, FreeAnonThrottle]
    
    filterset_class = ProfileFilter
    search_fields = ['first_name', 'last_name', 'bio', 'location']
    ordering_fields = ['first_name', 'last_name', 'posts_count', 'followers_count', 'following_count', 'created_at']
    ordering = ['-created_at']

    def get_object(self, user_id=None):
        user = get_object_or_404(User, id=user_id, is_active=True) if user_id else self.request.user
        profile, _ = Profile.objects.get_or_create(owner=user)
        return profile

    # -----------------------------
    # Retrieve profile
    # -----------------------------
    def retrieve(self, request, pk=None):
        profile = self.get_object(pk)
        serializer = self.get_serializer(profile)
        return api_response(True, "Profile fetched successfully", serializer.data)

    # -----------------------------
    # Update profile
    # -----------------------------
    @transaction.atomic
    def update(self, request, pk=None):
        profile = self.get_object(pk)
        serializer = self.get_serializer(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Profile updated successfully", serializer.data)

    # -----------------------------
    # Current user's profile
    # -----------------------------
    @action(detail=False, methods=["get"])
    def me(self, request):
        profile = self.get_object()
        serializer = self.get_serializer(profile)
        return api_response(True, "My profile fetched successfully", serializer.data)

    # -----------------------------
    # Upload avatar
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def avatar(self, request, pk=None):
        profile = self.get_object(pk)
        avatar_file = request.FILES.get("avatar")
        if not avatar_file or not avatar_file.content_type.startswith("image/") or avatar_file.size > 5*1024*1024:
            return api_response(False, "Invalid avatar file", status.HTTP_400_BAD_REQUEST)
        profile._avatar_file = avatar_file
        profile.save()
        return api_response(True, "Avatar uploaded successfully", {"avatar_url": profile.avatar_url})

    # -----------------------------
    # Upload cover
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def cover(self, request, pk=None):
        profile = self.get_object(pk)
        cover_file = request.FILES.get("cover")
        if not cover_file or not cover_file.content_type.startswith("image/") or cover_file.size > 5*1024*1024:
            return api_response(False, "Invalid cover file", status.HTTP_400_BAD_REQUEST)
        profile._cover_file = cover_file
        profile.save()
        return api_response(True, "Cover uploaded successfully", {"cover_image_url": profile.cover_image_url})

# =============================================================
# COMMENT VIEWSET
# =============================================================
class CommentViewSet(viewsets.GenericViewSet):
    queryset = Comment.objects.filter(is_active=True)
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    throttle_classes = [FreeUserThrottle, FreeAnonThrottle]

    # -----------------------------
    # List comments for a post
    # -----------------------------
    def list(self, request, post_pk=None):
        post = get_object_or_404(Post, id=post_pk, is_active=True)
        comments = post.comments.filter(parent__isnull=True, is_active=True)
        serializer = self.get_serializer(comments, many=True)
        return api_response(True, "Comments fetched successfully", serializer.data)

    # -----------------------------
    # Create comment for a post
    # -----------------------------
    @transaction.atomic
    def create(self, request, post_pk=None):
        post = get_object_or_404(Post, id=post_pk, is_active=True)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = serializer.save(author=request.user, post=post)
        return api_response(True, "Comment created successfully", serializer.data)
    
    # -----------------------------
    # Retrieve a single comment
    # -----------------------------
    def retrieve(self, request, post_pk=None, pk=None):
        comment = get_object_or_404(Comment, id=pk, post_id=post_pk, is_active=True)
        serializer = self.get_serializer(comment)
        return api_response(True, "Comment fetched successfully", serializer.data)

    # -----------------------------
    # Update a comment
    # -----------------------------
    @transaction.atomic
    def update(self, request, post_pk=None, pk=None):
        comment = get_object_or_404(Comment, id=pk, post_id=post_pk, is_active=True)
        serializer = self.get_serializer(comment, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Comment updated successfully", serializer.data)

    # -----------------------------
    # Soft delete a comment
    # -----------------------------
    @transaction.atomic
    def destroy(self, request,  post_pk=None, pk=None):
        comment = get_object_or_404(Comment, id=pk, post_id=post_pk, is_active=True)
        comment.soft_delete()
        return api_response(True, "Comment deleted successfully")

    # -----------------------------
    # Replies for a comment
    # -----------------------------
    @action(detail=True, methods=["get"])
    def replies(self, request, post_pk=None, pk=None):
        parent_comment = get_object_or_404(Comment, id=pk, post_id=post_pk, is_active=True)
        replies = parent_comment.replies.filter(is_active=True)
        serializer = self.get_serializer(replies, many=True)
        return api_response(True, "Replies fetched successfully", serializer.data)
    
        # -----------------------------
    # Add a reply to a comment
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def reply(self, request, post_pk=None, pk=None):
        parent_comment = get_object_or_404(
            Comment, id=pk, post_id=post_pk, is_active=True
        )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reply_comment = serializer.save(
            author=request.user,
            post_id=post_pk,
            parent=parent_comment
        )
        return api_response(True, "Reply added successfully", serializer.data)

    # -----------------------------
    # Toggle like for a comment
    # -----------------------------
    @action(detail=True, methods=["post"])
    @transaction.atomic
    def toggle_like(self, request, post_pk=None, pk=None):
        comment = get_object_or_404(Comment, id=pk, post_id=post_pk, is_active=True)
        like = Like.objects.filter(comment=comment, liked_by=request.user, is_active=True).first()
        if like and like.is_active:
            like.soft_delete()
            message = "Comment unliked successfully"
            liked = False
        elif like and not like.is_active:
            like.is_active = True
            like.save(update_fields=["is_active"])
            message = "Comment liked successfully"
            liked = True
        else:
            Like.objects.create(comment=comment, liked_by=request.user, is_active=True)
            message = "Comment liked successfully"
            liked = True
        return api_response(True, message, {"liked": liked})

# =============================================================
# FOLLOW VIEWSET
# =============================================================
class FollowViewSet(viewsets.GenericViewSet):
    queryset = Follow.objects.all()
    serializer_class = FollowSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    throttle_classes = [FreeUserThrottle, FreeAnonThrottle]

    # -----------------------------
    # Follow a user 
    # -----------------------------
    @action(detail=True, methods=["post"], url_path="follow")
    @transaction.atomic
    def follow_user(self, request, pk: str = None):
        followee = get_object_or_404(User, id=pk)
        if followee == request.user:
            return api_response(False, "You cannot follow yourself", status.HTTP_400_BAD_REQUEST)

        follow, created = Follow.objects.get_or_create(
            follower=request.user,
            followee=followee,
            defaults={"is_active": True}
        )
        if not created and follow.is_active:
            return api_response(False, "Already following", status.HTTP_400_BAD_REQUEST)
        elif not created:
            follow.is_active = True
            follow.save(update_fields=["is_active"])
            
        serializer = self.get_serializer(follow)
        return api_response(True, "User followed successfully", serializer.data)

    # -----------------------------
    # Unfollow a user 
    # -----------------------------
    @action(detail=True, methods=["delete"], url_path="unfollow")
    @transaction.atomic
    def unfollow_user(self, request, pk: str = None):
        followee = get_object_or_404(User, id=pk)
        follow = Follow.objects.filter(follower=request.user, followee=followee, is_active=True).first()
        if not follow:
            return api_response(False, "You are not following this user", status.HTTP_400_BAD_REQUEST)
        follow.soft_delete()
        return api_response(True, "User unfollowed successfully")

    # -----------------------------
    # Get my followers
    # -----------------------------
    @action(detail=False, methods=["get"], url_path="my_followers")
    def my_followers(self, request):
        followers = Follow.objects.filter(followee=request.user, is_active=True).select_related("follower__social_profile")
        profiles = [f.follower.social_profile for f in followers if hasattr(f.follower, "social_profile")]
        serializer = ProfileSerializer(profiles, many=True)
        return api_response(True, "My followers fetched successfully", serializer.data)

    # -----------------------------
    # Get my following
    # -----------------------------
    @action(detail=False, methods=["get"], url_path="my_following")
    def my_following(self, request):
        following = Follow.objects.filter(follower=request.user, is_active=True).select_related("followee__social_profile")
        profiles = [f.followee.social_profile for f in following if hasattr(f.followee, "social_profile")]
        serializer = ProfileSerializer(profiles, many=True)
        return api_response(True, "My following fetched successfully", serializer.data)

    # -----------------------------
    # Get followers of a user
    # -----------------------------
    @action(detail=True, methods=["get"], url_path="followers")
    def user_followers(self, request, pk=None):
        user = get_object_or_404(User, id=pk)
        followers = Follow.objects.filter(followee=user, is_active=True).select_related("follower__social_profile")
        profiles = [f.follower.social_profile for f in followers if hasattr(f.follower, "social_profile")]
        serializer = ProfileSerializer(profiles, many=True)
        return api_response(True, f"{user.username}'s followers fetched successfully", serializer.data)

    # -----------------------------
    # Get following of a user
    # -----------------------------
    @action(detail=True, methods=["get"], url_path="following")
    def user_following(self, request, pk=None):
        user = get_object_or_404(User, id=pk)
        following = Follow.objects.filter(follower=user, is_active=True).select_related("followee__social_profile")
        profiles = [f.followee.social_profile for f in following if hasattr(f.followee, "social_profile")]
        serializer = ProfileSerializer(profiles, many=True)
        return api_response(True, f"{user.username}'s following fetched successfully", serializer.data)

# =============================================================
# BOOKMARK VIEWSET
# =============================================================
class BookmarkViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PostSerializer
    throttle_classes = [FreeUserThrottle, FreeAnonThrottle]
    queryset = Bookmark.objects.none()

    def get_queryset(self):
        return Bookmark.objects.filter(bookmarked_by=self.request.user, is_active=True).select_related('post')

    def list(self, request):
        posts = Post.objects.filter(bookmarks__bookmarked_by=request.user, bookmarks__is_active=True).distinct()
        serializer = self.get_serializer(posts, many=True)
        return api_response(True, "Bookmarked posts fetched successfully", serializer.data)
