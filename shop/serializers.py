import uuid
from decimal import Decimal
from rest_framework import serializers
from shop.models import (
    Category, Product, ProductVariant, ProductImage,
    Cart, CartItem, Address, Coupon, Order, OrderItem,
    Payment, Wishlist, ProductReview
)

# ===============================
# CATEGORY SERIALIZER
# ===============================
class CategorySerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()
    
    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 'parent', 'image', 'children']

    def get_children(self, obj):
        return CategorySerializer(obj.children.filter(is_active=True), many=True).data


# ===============================
# CATEGORY IMAGE UPLOAD SERIALIZER
# ===============================
class CategoryImageUploadSerializer(serializers.Serializer):
    file = serializers.ImageField(required=True)


# ===============================
# PRODUCT IMAGE SERIALIZER
# ===============================
class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ['id', 'image', 'alt_text', 'is_primary', 'display_order']


# ===============================
# PRODUCT VARIANT SERIALIZER
# ===============================
class ProductVariantSerializer(serializers.ModelSerializer):
    discount_percentage = serializers.ReadOnlyField()
    in_stock = serializers.ReadOnlyField()

    class Meta:
        model = ProductVariant
        fields = [
            'id', 'sku', 'color', 'size', 'price', 'compare_price',
            'stock', 'track_inventory', 'discount_percentage', 'in_stock'
        ]


# ===============================
# PRODUCT SERIALIZER
# ===============================
class ProductSerializer(serializers.ModelSerializer):
    variants = ProductVariantSerializer(many=True, read_only=True)
    main_image = serializers.URLField(required=False)
    slug = serializers.ReadOnlyField()

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'slug', 'short_description', 'description',
            'is_featured', 'main_image', 'category', 'seller', 'variants'
        ]


# ===============================
# PRODUCT IMAGE UPLOAD SERIALIZER
# ===============================
class ProductImageUploadSerializer(serializers.Serializer):
    file = serializers.ImageField(required=True)


# ===============================
# CART ITEM SERIALIZER
# ===============================
class ProductVariantInCartSerializer(serializers.ModelSerializer):
    discount_percentage = serializers.ReadOnlyField()
    in_stock = serializers.ReadOnlyField()

    class Meta:
        model = ProductVariant
        fields = [
            'id', 'sku', 'color', 'size', 'price', 'compare_price',
            'stock', 'track_inventory', 'discount_percentage', 'in_stock'
        ]


class CartItemSerializer(serializers.ModelSerializer):
    product = serializers.SerializerMethodField()
    total_price = serializers.ReadOnlyField()

    class Meta:
        model = CartItem
        fields = ['id', 'quantity', 'total_price', 'product']

    def get_product(self, obj):
        product = obj.variant.product
        return {
            "id": product.id,
            "name": product.name,
            "slug": product.slug,
            "short_description": product.short_description,
            "description": product.description,
            "is_featured": product.is_featured,
            "main_image": product.main_image,
            "category": product.category.id,
            "seller": product.seller.id,
            "variant": ProductVariantInCartSerializer(obj.variant).data
        }


# ===============================
# CART SERIALIZER
# ===============================
class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    subtotal = serializers.SerializerMethodField()
    total_price = serializers.SerializerMethodField()

    class Meta:
        model = Cart
        fields = ['id', 'user', 'items', 'subtotal', 'total_price']

    def get_subtotal(self, obj):
        return sum(item.total_price for item in obj.items.filter(is_active=True))

    def get_total_price(self, obj):
        return self.get_subtotal(obj)


# ===============================
# CHECKOUT SERIALIZER
# ===============================
class CheckoutSerializer(serializers.Serializer):
    address_id = serializers.UUIDField(required=True)
    coupon_code = serializers.CharField(required=False, allow_blank=True, allow_null=True)


# ===============================
# ADDRESS SERIALIZER
# ===============================
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = [
            'id', 'user', 'address_type', 'full_name', 'phone',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country', 'is_default'
        ]
        read_only_fields = ['id', 'user']


# ===============================
# COUPON SERIALIZER
# ===============================
class CouponSerializer(serializers.ModelSerializer):
    is_valid = serializers.ReadOnlyField()

    class Meta:
        model = Coupon
        fields = [
            'id', 'code', 'discount_type', 'discount_value',
            'min_order_value', 'max_discount', 'valid_from', 'valid_to',
            'usage_limit', 'used_count', 'is_valid'
        ]


# ===============================
# ORDER ITEM SERIALIZER
# ===============================
class OrderItemSerializer(serializers.ModelSerializer):
    variant = ProductVariantSerializer(read_only=True)
    total_price = serializers.ReadOnlyField()

    class Meta:
        model = OrderItem
        fields = ['id', 'variant', 'quantity', 'price', 'total_price']


# ===============================
# ORDER SERIALIZER
# ===============================
class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    subtotal = serializers.ReadOnlyField()
    total_amount = serializers.ReadOnlyField()
    discount_amount = serializers.ReadOnlyField()
    tax_amount = serializers.ReadOnlyField()
    shipping_cost = serializers.ReadOnlyField()
    order_number = serializers.ReadOnlyField()

    class Meta:
        model = Order
        fields = [
            'id', 'user', 'address', 'coupon', 'order_number', 'status',
            'subtotal', 'discount_amount', 'tax_amount', 'shipping_cost',
            'total_amount', 'items'
        ]


# ===============================
# PAYMENT SERIALIZER
# ===============================
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = [
            'id', 'order', 'method', 'transaction_id',
            'amount', 'status', 'paid_at', 'refund_amount', 'refunded_at'
        ]


# ===============================
# WISHLIST SERIALIZER
# ===============================
class WishlistSerializer(serializers.ModelSerializer):
    variants = ProductVariantSerializer(many=True, read_only=True)

    class Meta:
        model = Wishlist
        fields = ['id', 'user', 'variants']


# ===============================
# PRODUCT REVIEW SERIALIZER
# ===============================
class ProductReviewSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = ProductReview
        fields = [
            'id', 'product', 'user', 'order_item',
            'rating', 'title', 'comment', 'is_approved'
        ]
