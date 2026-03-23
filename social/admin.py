from django.contrib import admin
from .models import (
    Post,
    PostImage,
    Comment,
    Like,
    Bookmark,
    Follow,
    Profile
)

# =============================================================
# INLINE ADMIN CLASSES
# =============================================================
class PostImageInline(admin.TabularInline):
    model = PostImage
    extra = 1
    readonly_fields = ('created_at', 'updated_at')
    fields = ('image',)

# =============================================================
# POST ADMIN
# =============================================================
@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'author', 'is_public', 'likes_count', 'comments_count', 'bookmarks_count', 'created_at')
    list_filter = ('is_public', 'created_at')
    search_fields = ('title', 'content', 'author__username')
    inlines = [PostImageInline]
    readonly_fields = ('likes_count', 'comments_count', 'bookmarks_count', 'created_at', 'updated_at')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('author').prefetch_related('likes', 'comments', 'bookmarks')


# =============================================================
# COMMENT ADMIN
# =============================================================
@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post', 'content', 'parent', 'likes_count', 'replies_count', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('content', 'author__username', 'post__title')
    readonly_fields = ('likes_count', 'replies_count', 'created_at', 'updated_at')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('author', 'post', 'parent').prefetch_related('likes', 'replies')


# =============================================================
# LIKE ADMIN
# =============================================================
@admin.register(Like)
class LikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'liked_by', 'post', 'comment', 'created_at')
    search_fields = ('liked_by__username',)
    list_filter = ('created_at',)
    autocomplete_fields = ('liked_by', 'post', 'comment')


# =============================================================
# BOOKMARK ADMIN
# =============================================================
@admin.register(Bookmark)
class BookmarkAdmin(admin.ModelAdmin):
    list_display = ('id', 'bookmarked_by', 'post', 'created_at')
    search_fields = ('bookmarked_by__username', 'post__title')
    list_filter = ('created_at',)
    autocomplete_fields = ('bookmarked_by', 'post')


# =============================================================
# FOLLOW ADMIN
# =============================================================
@admin.register(Follow)
class FollowAdmin(admin.ModelAdmin):
    list_display = ('id', 'follower', 'followee', 'created_at')
    search_fields = ('follower__username', 'followee__username')
    list_filter = ('created_at',)
    autocomplete_fields = ('follower', 'followee')


# =============================================================
# PROFILE ADMIN
# =============================================================
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'full_name', 'is_verified', 'is_private', 'followers_count', 'following_count', 'posts_count')
    list_filter = ('is_verified', 'is_private')
    search_fields = ('owner__username', 'first_name', 'last_name', 'bio')
    readonly_fields = ('followers_count', 'following_count', 'posts_count', 'created_at', 'updated_at')
    autocomplete_fields = ('owner',)


# =============================================================
# POST IMAGE ADMIN (Optional)
# =============================================================
@admin.register(PostImage)
class PostImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'post', 'image', 'created_at')
    search_fields = ('post__title',)
    list_filter = ('created_at',)
    autocomplete_fields = ('post',)
