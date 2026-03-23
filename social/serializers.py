from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from social.models import (
    Post, PostImage, Comment, Like, 
    Bookmark, Follow, Profile
)
from accounts.models import User

# =============================================================
# POST FILTER
# =============================================================
from django_filters import rest_framework as filters

class PostFilter(filters.FilterSet):
    tags = filters.CharFilter(method='filter_tags')

    class Meta:
        model = Post
        fields = ['author', 'is_public', 'tags']

    def filter_tags(self, queryset, name, value):
        return queryset.filter(tags__contains=[value])

# =============================================================
# PROFILE FILTER
# =============================================================
class ProfileFilter(filters.FilterSet):
    first_name = filters.CharFilter(field_name='first_name', lookup_expr='icontains')
    last_name = filters.CharFilter(field_name='last_name', lookup_expr='icontains')
    location = filters.CharFilter(field_name='location', lookup_expr='icontains')
    is_verified = filters.BooleanFilter(field_name='is_verified')
    is_private = filters.BooleanFilter(field_name='is_private')

    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'location', 'is_verified', 'is_private']

# =============================================================
# PROFILE SERIALIZER
# =============================================================
class ProfileSerializer(serializers.ModelSerializer):
    avatar_url = serializers.ReadOnlyField()
    cover_image_url = serializers.ReadOnlyField()
    full_name = serializers.ReadOnlyField()
    posts_count = serializers.ReadOnlyField()
    followers_count = serializers.ReadOnlyField()
    following_count = serializers.ReadOnlyField()

    class Meta:
        model = Profile
        fields = [
            "owner", "first_name", "last_name", "bio", "dob", "location",
            "country_code", "phone_number", "avatar", "cover_image",
            "website", "is_verified", "is_private",
            "avatar_url", "cover_image_url",
            "full_name", "posts_count", "followers_count", "following_count"
        ]
        read_only_fields = [
            "full_name", "posts_count", "followers_count", "following_count",
            "avatar_url", "cover_image_url", "owner"
        ]
        ref_name = "SocialProfile"

# =============================================================
# POST IMAGE SERIALIZER
# =============================================================
class PostImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostImage
        fields = ["id", "post", "image"]
        ref_name = "SocialPostImage"

# =============================================================
# POST SERIALIZER
# =============================================================
class PostSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)
    images = PostImageSerializer(many=True, read_only=True)

    likes_count = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    bookmarks_count = serializers.SerializerMethodField()

    @extend_schema_field(serializers.IntegerField())
    def get_likes_count(self, obj):
        return obj.likes_count

    @extend_schema_field(serializers.IntegerField())
    def get_comments_count(self, obj):
        return obj.comments_count

    @extend_schema_field(serializers.IntegerField())
    def get_bookmarks_count(self, obj):
        return obj.bookmarks_count

    class Meta:
        model = Post
        fields = [
            "id", "author", "title", "content", "tags", "is_public",
            "created_at", "updated_at",
            "images", "likes_count", "comments_count", "bookmarks_count"
        ]
        ref_name = "SocialPost"

# =============================================================
# COMMENT SERIALIZER
# =============================================================
class CommentSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField(read_only=True)
    replies_count = serializers.SerializerMethodField()
    likes_count = serializers.SerializerMethodField()
    
    post = serializers.PrimaryKeyRelatedField(read_only=True)

    @extend_schema_field(serializers.IntegerField())
    def get_replies_count(self, obj):
        return obj.replies_count

    @extend_schema_field(serializers.IntegerField())
    def get_likes_count(self, obj):
        return obj.likes_count

    class Meta:
        model = Comment
        fields = [
            "id", "author", "post", "content", "parent",
            "created_at", "updated_at",
            "likes_count", "replies_count"
        ]
        ref_name = "SocialComment"

# =============================================================
# LIKE SERIALIZER
# =============================================================
class LikeSerializer(serializers.ModelSerializer):
    liked_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Like
        fields = ["id", "liked_by", "post", "comment", "created_at"]
        ref_name = "SocialLike"

# =============================================================
# BOOKMARK SERIALIZER
# =============================================================
class BookmarkSerializer(serializers.ModelSerializer):
    bookmarked_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Bookmark
        fields = ["id", "post", "bookmarked_by", "created_at"]
        ref_name = "SocialBookmark"

# =============================================================
# FOLLOW SERIALIZER
# =============================================================
class FollowSerializer(serializers.ModelSerializer):
    follower = serializers.StringRelatedField(read_only=True)
    followee = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Follow
        fields = ["id", "follower", "followee", "created_at"]
        ref_name = "SocialFollow"
