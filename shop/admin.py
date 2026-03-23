from django.contrib import admin
from .models import (
    Category, Product, ProductVariant, ProductImage, ProductReview,
    Cart, CartItem, Address, Coupon, Order, OrderItem, Payment, Wishlist
)

# ===============================
# INLINE MODELS
# ===============================
class ProductVariantInline(admin.TabularInline):
    model = ProductVariant
    extra = 1
    readonly_fields = ('sku', 'discount_percentage', 'in_stock')


class ProductImageInline(admin.TabularInline):
    model = ProductImage
    extra = 1
    readonly_fields = ('image',)
    fields = ('image', 'alt_text', 'is_primary', 'display_order')


class ProductReviewInline(admin.TabularInline):
    model = ProductReview
    extra = 1
    readonly_fields = ('user', 'rating', 'title', 'comment')
    fields = ('user', 'rating', 'title', 'comment', 'is_approved')


class CartItemInline(admin.TabularInline):
    model = CartItem
    extra = 1
    readonly_fields = ('total_price',)


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 1
    readonly_fields = ('total_price',)


# ===============================
# MODEL ADMINS
# ===============================
@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent', 'is_active')
    search_fields = ('name',)
    prepopulated_fields = {"slug": ("name",)}

    def get_queryset(self, request):
        return Category.all_objects.all()


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'seller', 'is_featured', 'is_active', 'created_at')
    list_filter = ('is_featured', 'category')
    search_fields = ('name', 'category__name', 'seller__username')
    prepopulated_fields = {"slug": ("name",)}
    inlines = [ProductVariantInline, ProductImageInline, ProductReviewInline]

    def get_queryset(self, request):
        return Product.all_objects.select_related('category', 'seller')


@admin.register(ProductVariant)
class ProductVariantAdmin(admin.ModelAdmin):
    list_display = ('product', 'sku', 'color', 'size', 'price', 'stock', 'in_stock', 'is_active')
    list_filter = ('color', 'size', 'product__category')
    search_fields = ('sku', 'product__name')

    def get_queryset(self, request):
        return ProductVariant.all_objects.select_related('product')


@admin.register(ProductReview)
class ProductReviewAdmin(admin.ModelAdmin):
    list_display = ('product', 'user', 'rating', 'is_approved', 'is_active', 'created_at')
    list_filter = ('is_approved', 'rating')
    search_fields = ('product__name', 'user__username', 'title', 'comment')

    def get_queryset(self, request):
        return ProductReview.all_objects.select_related('product', 'user')


@admin.register(ProductImage)
class ProductImageAdmin(admin.ModelAdmin):
    list_display = ('product', 'image', 'alt_text', 'is_primary', 'display_order', 'is_active')
    list_filter = ('is_primary', 'product')
    search_fields = ('product__name',)

    def get_queryset(self, request):
        return ProductImage.all_objects.select_related('product')


@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_active')
    search_fields = ('user__username',)
    inlines = [CartItemInline]

    def get_queryset(self, request):
        return Cart.all_objects.select_related('user')


@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ('cart', 'variant', 'quantity', 'total_price', 'is_active')
    search_fields = ('cart__user__username', 'variant__sku')

    def get_queryset(self, request):
        return CartItem.all_objects.select_related('cart', 'variant')


@admin.register(Wishlist)
class WishlistAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_active')
    search_fields = ('user__username',)
    filter_horizontal = ('variants',)

    def get_queryset(self, request):
        return Wishlist.all_objects.select_related('user')


@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display = ('user', 'full_name', 'address_type', 'city', 'state', 'is_default', 'is_active')
    list_filter = ('address_type', 'city', 'state', 'is_default')
    search_fields = ('user__username', 'full_name', 'city', 'state', 'postal_code')

    def get_queryset(self, request):
        return Address.all_objects.select_related('user')


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ('code', 'discount_type', 'discount_value', 'valid_from', 'valid_to', 'usage_limit', 'used_count', 'is_active')
    list_filter = ('discount_type', 'valid_from', 'valid_to')
    search_fields = ('code',)

    def get_queryset(self, request):
        return Coupon.all_objects.all()


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_number', 'user', 'status', 'total_amount', 'is_active', 'created_at')
    list_filter = ('status',)
    search_fields = ('order_number', 'user__username')
    inlines = [OrderItemInline]

    def get_queryset(self, request):
        return Order.all_objects.select_related('user', 'address', 'coupon')


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ('order', 'variant', 'quantity', 'total_price', 'is_active')
    search_fields = ('order__order_number', 'variant__sku')

    def get_queryset(self, request):
        return OrderItem.all_objects.select_related('order', 'variant')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('order', 'method', 'status', 'amount', 'paid_at', 'refund_amount', 'refunded_at', 'is_active')
    list_filter = ('method', 'status')
    search_fields = ('order__order_number', 'transaction_id', 'order__user__username')

    def get_queryset(self, request):
        return Payment.all_objects.select_related('order')
