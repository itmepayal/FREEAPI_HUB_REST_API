import uuid
from django.db import models
from django.db.models import Min, Max
from django.utils import timezone
from django.utils.text import slugify
from django.core.exceptions import ValidationError
from core.models import BaseModel
from core.cloudinary import upload_to_cloudinary
from core.constants import (
    COLOR_CHOICES, SIZE_CHOICES,
    ADDRESS_TYPES, DISCOUNT_TYPE_CHOICES,
    ORDER_STATUS, PAYMENT_METHODS, PAYMENT_STATUS
)
from accounts.models import User

# ===============================
# CATEGORY MODEL
# ===============================
class Category(BaseModel):
    name = models.CharField(max_length=120)
    slug = models.SlugField(unique=True, blank=True)
    description = models.TextField(blank=True, null=True)
    parent = models.ForeignKey(
        'self', on_delete=models.CASCADE, null=True, blank=True, related_name='children'
    )
    image = models.URLField(max_length=500, blank=True, null=True)
    _image_file = None

    class Meta:
        verbose_name_plural = "Categories"
        ordering = ['name']

    def clean(self):
        if Category.objects.filter(name=self.name, is_active=True).exclude(id=self.id).exists():
            raise ValidationError({"name": "Category with this name already exists."})

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name)
            unique_id = uuid.uuid4().hex[:6]
            self.slug = f"{base_slug}-{unique_id}"

        if self._image_file:
            self.image = upload_to_cloudinary(self._image_file, folder="categories")
            self._image_file = None

        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


# ===============================
# PRODUCT MODEL
# ===============================
class Product(BaseModel):
    category = models.ForeignKey(Category, related_name="products", on_delete=models.CASCADE)
    seller = models.ForeignKey(User, related_name="products", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, blank=True)
    description = models.TextField(blank=True)
    short_description = models.CharField(max_length=300, blank=True)
    is_featured = models.BooleanField(default=False)
    main_image = models.URLField(max_length=500, blank=True, null=True)
    _image_file = None

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name)
            unique_id = uuid.uuid4().hex[:6]
            self.slug = f"{base_slug}-{unique_id}"
        if self._image_file:
            self.main_image = upload_to_cloudinary(self._image_file, folder="products/main")
            self._image_file = None
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def min_price(self):
        return self.variants.aggregate(min_price=Min('price'))['min_price'] or 0

    @property
    def max_price(self):
        return self.variants.aggregate(max_price=Max('price'))['max_price'] or 0

    @property
    def is_in_stock(self):
        return self.variants.filter(stock__gt=0).exists()

    @property
    def discount_percentage(self):
        discounts = [v.discount_percentage for v in self.variants.all()]
        return max(discounts) if discounts else 0
    
    def update_average_rating(self):
        from django.db.models import Avg
        result = self.reviews.filter(is_active=True).aggregate(Avg('rating'))
        return result['rating__avg'] or 0

# ===============================
# PRODUCT VARIANT MODEL
# ===============================
class ProductVariant(BaseModel):
    product = models.ForeignKey(Product, related_name="variants", on_delete=models.CASCADE)
    sku = models.CharField(max_length=100, unique=True, blank=True)
    color = models.CharField(max_length=20, choices=COLOR_CHOICES, blank=True, null=True)
    size = models.CharField(max_length=10, choices=SIZE_CHOICES, blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    compare_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    stock = models.PositiveIntegerField(default=0)
    track_inventory = models.BooleanField(default=True)

    class Meta:
        unique_together = ['product', 'color', 'size']

    def save(self, *args, **kwargs):
        if not self.sku:
            self.sku = f"SKU-{uuid.uuid4().hex[:12].upper()}"
        super().save(*args, **kwargs)

    @property
    def discount_percentage(self):
        if self.compare_price and self.compare_price > self.price:
            return int(((self.compare_price - self.price) / self.compare_price) * 100)
        return 0

    @property
    def in_stock(self):
        return not self.track_inventory or self.stock > 0


# ===============================
# PRODUCT IMAGE MODEL
# ===============================
class ProductImage(BaseModel):
    product = models.ForeignKey(Product, related_name="images", on_delete=models.CASCADE)
    image = models.URLField(max_length=500)
    alt_text = models.CharField(max_length=255, blank=True)
    is_primary = models.BooleanField(default=False)
    display_order = models.PositiveIntegerField(default=0)
    _image_file = None

    class Meta:
        ordering = ['display_order', 'created_at']

    def save(self, *args, **kwargs):
        if self._image_file:
            self.image = upload_to_cloudinary(self._image_file, folder="products/images")
            self._image_file = None
        super().save(*args, **kwargs)


# ===============================
# CART & CART ITEM
# ===============================
class Cart(BaseModel):
    user = models.OneToOneField(User, related_name="cart", on_delete=models.CASCADE)

    def subtotal(self):
        return sum(item.total_price for item in self.items.filter(is_active=True))

    def total_price(self):
        return self.subtotal()


class CartItem(BaseModel):
    cart = models.ForeignKey('Cart', related_name="items", on_delete=models.CASCADE)
    variant = models.ForeignKey(ProductVariant, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['cart', 'variant'],
                condition=models.Q(is_active=True),
                name='unique_active_cart_item'
            )
        ]

    def clean(self):
        if self.quantity < 1:
            raise ValidationError({"quantity": "Quantity must be at least 1."})
        if self.variant.track_inventory and self.quantity > self.variant.stock:
            raise ValidationError({
                "quantity": f"Only {self.variant.stock} items available in stock."
            })

    @property
    def total_price(self):
        return self.variant.price * self.quantity

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

# ===============================
# ADDRESS MODEL
# ===============================
class Address(BaseModel):
    user = models.ForeignKey(User, related_name="addresses", on_delete=models.CASCADE)
    address_type = models.CharField(max_length=10, choices=ADDRESS_TYPES, default="HOME")
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100, default="India")
    is_default = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if self.is_default:
            Address.objects.filter(user=self.user, is_default=True).exclude(id=self.id).update(is_default=False)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.full_name}, {self.city}"


# ===============================
# COUPON MODEL
# ===============================
class Coupon(BaseModel):
    code = models.CharField(max_length=50, unique=True)
    discount_type = models.CharField(max_length=20, choices=DISCOUNT_TYPE_CHOICES)
    discount_value = models.DecimalField(max_digits=10, decimal_places=2)
    min_order_value = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    max_discount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    usage_limit = models.PositiveIntegerField(default=1)
    used_count = models.PositiveIntegerField(default=0)

    @property
    def is_valid(self):
        now = timezone.now()
        return self.is_active and self.valid_from <= now <= self.valid_to and self.used_count < self.usage_limit

    def calculate_discount(self, amount):
        if not self.is_valid or amount < self.min_order_value:
            return 0
        if self.discount_type == "PERCENTAGE":
            discount = (amount * self.discount_value) / 100
            if self.max_discount:
                discount = min(discount, self.max_discount)
        else:
            discount = min(self.discount_value, amount)
        return discount


# ===============================
# ORDER & ORDER ITEM
# ===============================
class Order(BaseModel):
    user = models.ForeignKey(User, related_name="ecommerce_orders", on_delete=models.CASCADE)
    address = models.ForeignKey(Address, on_delete=models.PROTECT)
    coupon = models.ForeignKey(Coupon, null=True, blank=True, on_delete=models.SET_NULL)
    order_number = models.CharField(max_length=20, unique=True, editable=False)
    status = models.CharField(max_length=20, choices=ORDER_STATUS, default="PENDING")
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    shipping_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    def save(self, *args, **kwargs):
        if not self.order_number:
            self.order_number = f"ORD-{uuid.uuid4().hex[:10].upper()}"
        super().save(*args, **kwargs)


class OrderItem(BaseModel):
    order = models.ForeignKey(Order, related_name="items", on_delete=models.CASCADE)
    variant = models.ForeignKey(ProductVariant, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    @property
    def total_price(self):
        return self.price * self.quantity


# ===============================
# PAYMENT MODEL
# ===============================
class Payment(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order = models.OneToOneField(Order, related_name="payment", on_delete=models.CASCADE)
    method = models.CharField(max_length=20, choices=PAYMENT_METHODS)
    transaction_id = models.CharField(max_length=255, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default="PENDING")
    paid_at = models.DateTimeField(null=True, blank=True)
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    refunded_at = models.DateTimeField(null=True, blank=True)


# ===============================
# WISHLIST MODEL
# ===============================
class Wishlist(BaseModel):
    user = models.OneToOneField(User, related_name="wishlist", on_delete=models.CASCADE)
    variants = models.ManyToManyField(ProductVariant, related_name="wishlisted_by", blank=True)


# ===============================
# PRODUCT REVIEW MODEL
# ===============================
class ProductReview(BaseModel):
    product = models.ForeignKey(Product, related_name="reviews", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="reviews", on_delete=models.CASCADE)
    order_item = models.ForeignKey(OrderItem, null=True, blank=True, on_delete=models.SET_NULL)
    rating = models.PositiveSmallIntegerField()
    title = models.CharField(max_length=200, blank=True)
    comment = models.TextField(blank=True)
    is_approved = models.BooleanField(default=False)

    class Meta:
        unique_together = ('product', 'user', 'order_item')
        ordering = ['-created_at']

    def clean(self):
        if not (1 <= self.rating <= 5):
            raise ValidationError({"rating": "Rating must be between 1 and 5."})
        if self.order_item and self.order_item.order.user != self.user:
            raise ValidationError({"order_item": "Order item does not belong to this user."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.product.name} - {self.user.username} - {self.rating}"
