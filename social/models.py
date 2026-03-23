import uuid
from django.db import models
from django.utils.functional import cached_property
from django.core.exceptions import ValidationError
from accounts.models import User
from core.models import BaseModel
from core.cloudinary import upload_to_cloudinary
from core.constants import NOTIFICATION_TYPES

PLACEHOLDER_COVER_URL = "https://dummyimage.com/800x450/000/fff&text={name}+Cover"
PLACEHOLDER_AVATAR_URL = "https://dummyimage.com/200x200/000/fff&text={name}"
PLACEHOLDER_GROUP_URL = "https://dummyimage.com/200x200/000/fff&text={name}+Group"

# =============================================================
# POST MODEL
# =============================================================
class Post(BaseModel):
    """
    Represents a social media post.
    """
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="posts")
    title = models.CharField(max_length=255, blank=True)
    content = models.TextField()
    tags = models.JSONField(default=list, blank=True)  
    is_public = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['author', 'created_at']),
            models.Index(fields=['deleted_at', 'created_at']),
            models.Index(fields=['is_public', 'created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return self.title or f"Post by {self.author}"

    # =============================================================
    # Cached properties for counts
    # =============================================================
    @cached_property
    def likes_count(self):
        return self.likes.count()

    @cached_property
    def comments_count(self):
        return self.comments.filter(deleted_at__isnull=True).count()

    @cached_property
    def bookmarks_count(self):
        return self.bookmarks.count()


# =============================================================
# POST IMAGE MODEL
# =============================================================
class PostImage(BaseModel):
    """
    Stores images related to posts.
    """
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="images")
    image = models.URLField(max_length=500, blank=True, null=True)
    _image_file = None  # temporary storage before uploading to cloudinary

    def __str__(self):
        return f"Image for {self.post}"

    def save(self, *args, **kwargs):
        # Upload image to Cloudinary if _image_file is provided
        if self._image_file:
            self.image = upload_to_cloudinary(self._image_file, folder="social/posts/images")
            self._image_file = None
        super().save(*args, **kwargs)


# =============================================================
# COMMENT MODEL
# =============================================================
class Comment(BaseModel):
    """
    Comments on posts. Supports replies via self-referential parent.
    """
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="comments")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    content = models.TextField()
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.CASCADE, related_name="replies"
    )

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['post', 'created_at']),
            models.Index(fields=['author', 'created_at']),
        ]

    def __str__(self):
        return f"Comment by {self.author} on {self.post}"

    def clean(self):
        # Ensure a reply belongs to the same post as its parent
        if self.parent and self.parent.post != self.post:
            raise ValidationError("Reply must be on the same post as parent comment")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    # Cached counts
    @cached_property
    def likes_count(self):
        return self.likes.count()

    @cached_property
    def replies_count(self):
        return self.replies.filter(deleted_at__isnull=True).count()


# =============================================================
# LIKE MODEL
# =============================================================
class Like(BaseModel):
    """
    Represents a like on a post or comment. Only one target per like.
    """
    liked_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="likes")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="likes", null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, related_name="likes", null=True, blank=True)

    def __str__(self):
        target = self.post or self.comment
        return f"{self.liked_by} liked {target}"

    def clean(self):
        if not self.post and not self.comment:
            raise ValidationError("Like must be associated with either a post or comment")
        if self.post and self.comment:
            raise ValidationError("Like cannot be associated with both post and comment")

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


# =============================================================
# BOOKMARK MODEL
# =============================================================
class Bookmark(BaseModel):
    """
    Bookmark posts.
    """
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="bookmarks")
    bookmarked_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="bookmarks")

    class Meta:
        indexes = [
            models.Index(fields=['bookmarked_by', 'created_at']),
        ]

    def __str__(self):
        return f"{self.bookmarked_by} bookmarked {self.post}"


# =============================================================
# FOLLOW MODEL
# =============================================================
class Follow(BaseModel):
    """
    Represents following relationship between users.
    """
    follower = models.ForeignKey(User, on_delete=models.CASCADE, related_name="following")
    followee = models.ForeignKey(User, on_delete=models.CASCADE, related_name="followers")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['follower', 'followee'], name='unique_follow')
        ]
        indexes = [
            models.Index(fields=['follower', 'created_at']),
            models.Index(fields=['followee', 'created_at']),
        ]

    def __str__(self):
        return f"{self.follower} follows {self.followee}"

    def clean(self):
        if self.follower == self.followee:
            raise ValidationError("Users cannot follow themselves")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

# =============================================================
# PROFILE MODEL
# =============================================================
class Profile(BaseModel):
    """
    Stores additional profile info for users.
    """
    owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="social_profile")
    first_name = models.CharField(max_length=30, default="John")
    last_name = models.CharField(max_length=30, default="Doe")
    bio = models.TextField(blank=True, default="")
    dob = models.DateField(blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, default="")
    country_code = models.CharField(max_length=5, blank=True, default="")
    phone_number = models.CharField(max_length=20, blank=True, default="")
    avatar = models.URLField(max_length=500, blank=True, null=True)
    cover_image = models.URLField(max_length=500, blank=True, null=True)
    website = models.URLField(blank=True, default="")
    is_verified = models.BooleanField(default=False)
    is_private = models.BooleanField(default=False)

    _avatar_file = None
    _cover_file = None

    class Meta:
        verbose_name = "Profile"
        verbose_name_plural = "Profiles"
        ordering = ["owner__username"]

    def __str__(self):
        return f"{self.owner.username}'s profile"

    # =============================================================
    # Cached properties
    # =============================================================
    @cached_property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    @cached_property
    def posts_count(self) -> int:
        return self.owner.posts.filter(deleted_at__isnull=True).count()

    @cached_property
    def followers_count(self) -> int:
        return self.owner.followers.count()

    @cached_property
    def following_count(self) -> int:
        return self.owner.following.count()

    @cached_property
    def cover_image_url(self) -> str:
        if self.cover_image:
            return self.cover_image
        name = self.owner.username.replace(" ", "+")
        return PLACEHOLDER_COVER_URL.format(name=name)

    @cached_property
    def avatar_url(self) -> str:
        if self.avatar:
            return self.avatar
        name = self.owner.username.replace(" ", "+")
        return PLACEHOLDER_AVATAR_URL.format(name=name)

    # =============================================================
    # Save method for uploading files to cloudinary
    # =============================================================
    def save(self, *args, **kwargs):
        if self._avatar_file:
            self.avatar = upload_to_cloudinary(self._avatar_file, folder="social/profile/avatars")
            self._avatar_file = None
        if self._cover_file:
            self.cover_image = upload_to_cloudinary(self._cover_file, folder="social/profile/covers")
            self._cover_file = None
        super().save(*args, **kwargs)
