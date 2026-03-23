import razorpay
import stripe
from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from core.utils import api_response
from core.permissions import IsAdminOrSuperAdmin, IsOwnerOrAdmin, IsSuperAdmin, IsAuthenticatedUser
from shop.models import (
    Category, Product, ProductVariant, 
    ProductImage, Cart, CartItem,
    Address, Coupon, Order, OrderItem,
    Payment, ProductReview
)
from shop.serializers import (
    CategorySerializer, CategoryImageUploadSerializer,
    ProductSerializer, ProductImageUploadSerializer,
    ProductVariantSerializer, ProductImageSerializer,
    CartSerializer, CartItemSerializer, AddressSerializer,
    CouponSerializer, CheckoutSerializer, OrderSerializer,
    OrderItemSerializer, PaymentSerializer, ProductReviewSerializer,
    WishlistSerializer
)
from decimal import Decimal

# =============================================================
# CATEGORY VIEWSET
# =============================================================
class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.filter(is_active=True)
    serializer_class = CategorySerializer
    permission_classes = [IsAdminOrSuperAdmin]

    search_fields = ['name']
    ordering_fields = ['created_at', 'updated_at']

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category = serializer.save()
        return api_response(
            True, "Category created successfully.",
            serializer.data, status_code=status.HTTP_201_CREATED
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Category retrieved successfully.", serializer.data)

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        category = serializer.save()
        return api_response(True, "Category updated successfully.", serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Category deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['POST'], url_path='restore')
    def restore_category(self, request, pk=None):
        category = Category.all_objects.get(pk=pk)
        if category.is_active:
            return api_response(False, "Category is already active.", None, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            category.restore()
        except ValidationError as e:
            return api_response(False, str(e), None, status_code=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(category)
        return api_response(True, "Category restored successfully.", serializer.data)

    @action(detail=True, methods=['POST'], url_path='image')
    def upload_image(self, request, pk=None):
        category = self.get_object()
        serializer = CategoryImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category._image_file = serializer.validated_data['file']
        category.save()
        return api_response(True, "Category image uploaded successfully.", {"image": category.image})

# =============================================================
# PRODUCT VIEWSET
# =============================================================
class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    search_fields = ['name', 'description', 'category__name']
    ordering_fields = ['price', 'created_at', 'updated_at']

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product = serializer.save()
        return api_response(True, "Product created successfully.", serializer.data, status_code=status.HTTP_201_CREATED)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Product retrieved successfully.", serializer.data)

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        product = serializer.save()
        return api_response(True, "Product updated successfully.", serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Product deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['POST'], url_path='restore')
    def restore_product(self, request, pk=None):
        product = Product.all_objects.get(pk=pk)
        if product.is_active:
            return api_response(False, "Product is already active.", None, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            product.restore()
        except ValidationError as e:
            return api_response(False, str(e), None, status_code=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(product)
        return api_response(True, "Product restored successfully.", serializer.data)

    @action(detail=True, methods=['POST'], url_path='image')
    def upload_main_image(self, request, pk=None):
        product = self.get_object()
        serializer = ProductImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product._image_file = serializer.validated_data['file']
        product.save()
        return api_response(True, "Product main image uploaded successfully.", {"main_image": product.main_image})

# =============================================================
# PRODUCT VARIANT VIEWSET
# =============================================================
class ProductVariantViewSet(viewsets.ModelViewSet):
    serializer_class = ProductVariantSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        product_id = self.kwargs.get('product_pk')
        return ProductVariant.objects.filter(product_id=product_id)

    # =============================================================
    # CREATE PRODUCT VARIANT
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        product_id = self.kwargs.get('product_pk')
        product = get_object_or_404(Product, pk=product_id)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        variant = serializer.save(product=product)
        return api_response(True, "Product variant created successfully.", serializer.data, status_code=status.HTTP_201_CREATED)

    # =============================================================
    # RETRIEVE PRODUCT VARIANT
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Product variant retrieved successfully.", serializer.data)

    # =============================================================
    # UPDATE PRODUCT VARIANT
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Product variant updated successfully.", serializer.data)

    # =============================================================
    # PARTIAL UPDATE PRODUCT VARIANT
    # =============================================================
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    # =============================================================
    # DELETE PRODUCT VARIANT
    # =============================================================
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Product variant deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

# =============================================================
# PRODUCT IMAGE VIEWSET
# =============================================================
class ProductImageViewSet(viewsets.ModelViewSet):
    serializer_class = ProductImageSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        product_id = self.kwargs.get("product_pk")
        return ProductImage.objects.filter(product_id=product_id)

    # =============================================================
    # CREATE PRODUCT IMAGE
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        product_id = self.kwargs.get("product_pk")
        product = get_object_or_404(Product, pk=product_id)

        serializer = ProductImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        image_instance = ProductImage(product=product)
        image_instance._image_file = serializer.validated_data["file"]
        image_instance.save()

        return api_response(
            True,
            "Product image uploaded successfully.",
            ProductImageSerializer(image_instance).data,
            status_code=status.HTTP_201_CREATED,
        )

    # =============================================================
    # UPDATE PRODUCT IMAGE
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ProductImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance._image_file = serializer.validated_data["file"]
        instance.save()
        return api_response(
            True,
            "Product image updated successfully.",
            ProductImageSerializer(instance).data,
            status_code=status.HTTP_200_OK,
        )

    # =============================================================
    # PARTIAL UPDATE PRODUCT IMAGE
    # =============================================================
    @transaction.atomic
    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    # =============================================================
    # RETRIEVE PRODUCT IMAGE
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Product image retrieved successfully.", serializer.data)

    # =============================================================
    # DELETE PRODUCT IMAGE
    # =============================================================
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Product image deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

# =============================================================
# ADDRESS VIEWSET
# =============================================================
class AddressViewSet(viewsets.ModelViewSet):
    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        return Address.objects.filter(user=self.request.user, is_active=True)

    # =============================================================
    # CREATE ADDRESS
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        address = serializer.save(user=request.user)
        return api_response(True, "Address created successfully.", serializer.data, status_code=status.HTTP_201_CREATED)

    # =============================================================
    # RETRIEVE PRODUCT IMAGE
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Address retrieved successfully.", serializer.data)
    
    # =============================================================
    # UPDATE ADDRESS
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Address updated successfully.", serializer.data)

    # =============================================================
    # PARTIAL UPDATE ADDRESS
    # =============================================================
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    # =============================================================
    # DELETE ADDRESS
    # =============================================================
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Address deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

    # =============================================================
    # SET DEFAULT ADDRESS
    # =============================================================
    @action(detail=True, methods=['POST'], url_path='set-default')
    def set_default(self, request, pk=None):
        address = self.get_object()
        address.is_default = True
        address.save()
        serializer = self.get_serializer(address)
        return api_response(True, "Address set as default.", serializer.data)

# =============================================================
# COUPON CODE VIEWSET
# =============================================================
class CouponViewSet(viewsets.ModelViewSet):
    serializer_class = CouponSerializer
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        return Coupon.objects.filter(is_active=True)

    # =============================================================
    # CREATE COUPON
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        coupon = serializer.save()
        return api_response(True, "Coupon created successfully.", serializer.data, status_code=status.HTTP_201_CREATED)

    # =============================================================
    # RETRIEVE COUPON
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Coupon retrieved successfully.", serializer.data)

    # =============================================================
    # UPDATE COUPON
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return api_response(True, "Coupon updated successfully.", serializer.data)

    # =============================================================
    # PARTIAL UPDATE COUPON
    # =============================================================
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    # =============================================================
    # DELETE COUPON 
    # =============================================================
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return api_response(True, "Coupon deleted successfully.", None, status_code=status.HTTP_204_NO_CONTENT)

    # =============================================================
    # VALIDATE COUPON
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='validate')
    def validate_coupon(self, request):
        code = request.data.get('code')
        order_amount = float(request.data.get('order_amount', 0))

        if not code:
            return api_response(False, "Coupon code is required.", None, status.HTTP_400_BAD_REQUEST)

        try:
            coupon = Coupon.objects.get(code=code, is_active=True)
        except Coupon.DoesNotExist:
            return api_response(False, "Invalid coupon code.", None, status.HTTP_400_BAD_REQUEST)

        if not coupon.is_valid:
            return api_response(False, "Coupon is expired or usage limit reached.", None, status.HTTP_400_BAD_REQUEST)

        discount_amount = coupon.calculate_discount(order_amount)
        return api_response(True, "Coupon is valid.", {"code": coupon.code, "discount": discount_amount})

# =============================================================
# CART VIEWSET
# =============================================================
class CartViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET CART
    # =============================================================
    def list(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        serializer = CartSerializer(cart)
        return api_response(True, "Cart retrieved successfully.", serializer.data)

    # =============================================================
    # ADD ITEM TO CART
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='add')
    @transaction.atomic
    def add_item(self, request):
        variant_id = request.data.get("variant_id")
        if not variant_id:
            return api_response(False, "Variant ID is required.", None, status.HTTP_400_BAD_REQUEST)

        try:
            quantity = int(request.data.get("quantity", 1))
            if quantity <= 0:
                raise ValueError
        except ValueError:
            return api_response(False, "Quantity must be a positive integer.", None, status.HTTP_400_BAD_REQUEST)

        variant = get_object_or_404(ProductVariant, pk=variant_id)
        cart, _ = Cart.objects.get_or_create(user=request.user)

        cart_item, created = CartItem.all_objects.get_or_create(
            cart=cart,
            variant=variant,
            defaults={"quantity": quantity, "is_active": True}
        )

        if not created:
            if not cart_item.is_active:
                cart_item.restore()
                cart_item.quantity = quantity
            else:
                cart_item.quantity += quantity
            cart_item.save(update_fields=['quantity', 'is_active', 'deleted_at'])

        serializer = CartSerializer(cart)
        return api_response(True, "Item added to cart successfully.", serializer.data)

    # =============================================================
    # UPDATE ITEM QUANTITY
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='update')
    @transaction.atomic
    def update_item(self, request):
        variant_id = request.data.get("variant_id")
        if not variant_id:
            return api_response(False, "Variant ID is required.", None, status.HTTP_400_BAD_REQUEST)

        try:
            quantity = int(request.data.get("quantity", 1))
        except ValueError:
            return api_response(False, "Quantity must be an integer.", None, status.HTTP_400_BAD_REQUEST)

        cart = get_object_or_404(Cart, user=request.user)
        cart_item = get_object_or_404(CartItem.all_objects, cart=cart, variant_id=variant_id)

        if quantity <= 0:
            cart_item.delete()
        else:
            cart_item.quantity = quantity
            if not cart_item.is_active:
                cart_item.restore()
            cart_item.save(update_fields=['quantity', 'is_active', 'deleted_at'])

        serializer = CartSerializer(cart)
        return api_response(True, "Cart updated successfully.", serializer.data)

    # =============================================================
    # REMOVE ITEM FROM CART
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='remove')
    @transaction.atomic
    def remove_item(self, request):
        variant_id = request.data.get("variant_id")
        if not variant_id:
            return api_response(False, "Variant ID is required.", None, status.HTTP_400_BAD_REQUEST)

        cart = get_object_or_404(Cart, user=request.user)
        cart_item = get_object_or_404(CartItem.all_objects, cart=cart, variant_id=variant_id)
        cart_item.delete()

        serializer = CartSerializer(cart)
        return api_response(True, "Item removed from cart successfully.", serializer.data)

    # =============================================================
    # CLEAR CART
    # =============================================================
    @action(detail=False, methods=['DELETE'], url_path='clear')
    @transaction.atomic
    def clear_cart(self, request):
        cart = get_object_or_404(Cart, user=request.user)
        for item in cart.items.all():
            item.delete()

        serializer = CartSerializer(cart)
        return api_response(True, "Cart cleared successfully.", serializer.data)

    # =============================================================
    # CHECKOUT CART
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='checkout')
    @transaction.atomic
    def checkout(self, request):
        serializer = CheckoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        cart = get_object_or_404(Cart, user=request.user)
        if not cart.items.filter(is_active=True).exists():
            return api_response(False, "Cart is empty.", None, status.HTTP_400_BAD_REQUEST)

        address = get_object_or_404(Address, id=serializer.validated_data['address_id'], user=request.user)
        coupon_code = serializer.validated_data.get('coupon_code')

        subtotal = cart.subtotal()
        discount_amount = Decimal('0')
        coupon = None

        if coupon_code:
            try:
                coupon = Coupon.objects.get(code=coupon_code, is_active=True)
                discount_amount = Decimal(coupon.calculate_discount(subtotal))
            except Coupon.DoesNotExist:
                return api_response(False, "Invalid coupon code.", None, status.HTTP_400_BAD_REQUEST)

        TAX_RATE = Decimal('0.18')
        SHIPPING_COST = Decimal('50')
        tax_amount = subtotal * TAX_RATE
        total_amount = subtotal - discount_amount + tax_amount + SHIPPING_COST

        variant_ids = [item.variant.id for item in cart.items.filter(is_active=True)]
        variants = ProductVariant.objects.select_for_update().filter(id__in=variant_ids)
        variant_map = {v.id: v for v in variants}

        for item in cart.items.filter(is_active=True):
            variant = variant_map[item.variant.id]
            if variant.track_inventory and item.quantity > variant.stock:
                return api_response(
                    False,
                    f"Insufficient stock for {variant.product.name} ({variant.sku})",
                    None,
                    status.HTTP_400_BAD_REQUEST
                )

        order = Order.objects.create(
            user=request.user,
            address=address,
            coupon=coupon,
            subtotal=subtotal,
            discount_amount=discount_amount,
            tax_amount=tax_amount,
            shipping_cost=SHIPPING_COST,
            total_amount=total_amount
        )

        for item in cart.items.filter(is_active=True):
            variant = variant_map[item.variant.id]
            OrderItem.objects.create(
                order=order,
                variant=variant,
                quantity=item.quantity,
                price=variant.price
            )
            if variant.track_inventory:
                variant.stock -= item.quantity
                variant.save(update_fields=['stock'])

        cart.items.all().delete()

        serializer = OrderSerializer(order)
        return api_response(True, "Checkout successful.", serializer.data)

# =============================================================
# PAYMENT VIEWSET
# =============================================================
class PaymentViewSet(viewsets.ModelViewSet):
    serializer_class = PaymentSerializer
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        return Payment.objects.filter(user=self.request.user)

    # =============================================================
    # CREATE ORDER: RAZORPAY
    # =============================================================
    @action(detail=False, methods=["POST"], url_path="create-razorpay-order")
    def create_razorpay_order(self, request):
        order_id = request.data.get("order_id")
        order = Order.objects.get(id=order_id, user=request.user)
        amount = float(order.total_amount)

        payment, created = Payment.objects.get_or_create(
            order=order,
            defaults={
                "user": request.user,
                "method": "RAZORPAY",
                "amount": amount,
                "status": "PENDING",
                "transaction_id": ""
            }
        )

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        razorpay_order = client.order.create({
            "amount": int(amount * 100),
            "currency": "INR",
            "payment_capture": 1
        })
        payment.transaction_id = razorpay_order["id"]
        payment.save()

        return api_response(True, "Razorpay order created successfully.", {
            "razorpay_order_id": razorpay_order["id"],
            "razorpay_key": settings.RAZORPAY_KEY_ID,
            "amount": int(amount * 100),
            "currency": "INR",
        })

    # =============================================================
    # VERIFY PAYMENT: RAZORPAY
    # =============================================================
    @action(detail=False, methods=["POST"], url_path="verify-razorpay")
    def verify_razorpay_payment(self, request):
        payment_id = request.data.get("razorpay_payment_id")
        order_id = request.data.get("razorpay_order_id")
        signature = request.data.get("razorpay_signature")

        if not all([payment_id, order_id, signature]):
            return api_response(False, "All Razorpay fields are required.", None, status.HTTP_400_BAD_REQUEST)

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        try:
            client.utility.verify_payment_signature({
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature
            })
        except razorpay.errors.SignatureVerificationError:
            return api_response(False, "Invalid Razorpay signature.", None, status.HTTP_400_BAD_REQUEST)

        payment = Payment.objects.get(transaction_id=order_id)
        if payment.status == "SUCCESS":
            return api_response(False, "Payment already processed.", None, status.HTTP_400_BAD_REQUEST)

        payment.status = "SUCCESS"
        payment.transaction_id = payment_id
        payment.paid_at = timezone.now()
        payment.save()

        payment.order.status = "CONFIRMED"
        payment.order.save()

        return api_response(True, "Razorpay payment verified successfully.", PaymentSerializer(payment).data)

    # =============================================================
    # CREATE ORDER: STRIPE
    # =============================================================
    @action(detail=False, methods=["POST"], url_path="create-stripe-order")
    def create_stripe_order(self, request):
        order_id = request.data.get("order_id")
        order = Order.objects.get(id=order_id, user=request.user)
        amount = float(order.total_amount)

        payment, created = Payment.objects.get_or_create(
            order=order,
            defaults={
                "user": request.user,
                "method": "STRIPE",
                "amount": amount,
                "status": "PENDING",
                "transaction_id": ""
            }
        )

        stripe.api_key = settings.STRIPE_SECRET_KEY
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"Order #{order.id}"},
                    "unit_amount": int(amount * 100),
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{settings.FRONTEND_URL}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{settings.FRONTEND_URL}/payment-cancel",
        )

        payment.transaction_id = session.id
        payment.save()

        return api_response(True, "Stripe session created successfully.", {
            "session_id": session.id,
            "checkout_url": session.url
        })

    # =============================================================
    # VERIFY PAYMENT: STRIPE
    # =============================================================
    @action(detail=False, methods=["POST"], url_path="verify-stripe")
    def verify_stripe_payment(self, request):
        session_id = request.data.get("session_id")
        if not session_id:
            return api_response(False, "Stripe session_id is required.", None, status.HTTP_400_BAD_REQUEST)

        stripe.api_key = settings.STRIPE_SECRET_KEY
        session = stripe.checkout.Session.retrieve(session_id)
        payment = Payment.objects.get(transaction_id=session.id)

        if payment.status == "SUCCESS":
            return api_response(False, "Payment already processed.", None, status.HTTP_400_BAD_REQUEST)

        if session.payment_status == "paid":
            payment.status = "SUCCESS"
            payment.paid_at = timezone.now()
            payment.save()

            payment.order.status = "CONFIRMED"
            payment.order.save()

            return api_response(True, "Stripe payment verified successfully.", PaymentSerializer(payment).data)
        else:
            return api_response(False, "Stripe payment not completed.", None, status.HTTP_400_BAD_REQUEST)

# =============================================================
# ORDER VIEWSET
# =============================================================
class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Order.objects.all() 
        return Order.objects.filter(user=user) 

    # =============================================================
    # RETRIEVE ORDER
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Order retrieved successfully.", serializer.data)

    # =============================================================
    # CANCEL ORDER
    # =============================================================
    @action(detail=True, methods=['POST'], url_path='cancel')
    @transaction.atomic
    def cancel_order(self, request, pk=None):
        order = self.get_object()
        if order.status not in ['PENDING', 'CONFIRMED']:
            return api_response(False, "Order cannot be cancelled.", None, status.HTTP_400_BAD_REQUEST)

        order.status = 'CANCELLED'
        order.save(update_fields=['status'])

        for item in order.items.all():
            variant = item.variant
            if variant.track_inventory:
                variant.stock += item.quantity
                variant.save(update_fields=['stock'])

        return api_response(True, "Order cancelled successfully.", self.get_serializer(order).data)

    # =============================================================
    # CONFIRM ORDER (Admin Only)
    # =============================================================
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminOrSuperAdmin], url_path='confirm')
    @transaction.atomic
    def confirm_order(self, request, pk=None):
        order = self.get_object()
        if order.status != 'PENDING':
            return api_response(False, "Only pending orders can be confirmed.", None, status.HTTP_400_BAD_REQUEST)

        order.status = 'CONFIRMED'
        order.save(update_fields=['status'])
        return api_response(True, "Order confirmed successfully.", self.get_serializer(order).data)

    # =============================================================
    # GET ORDER ITEMS
    # =============================================================
    @action(detail=True, methods=['GET'], url_path='items')
    def order_items(self, request, pk=None):
        order = self.get_object()
        items = order.items.all()
        serializer = OrderItemSerializer(items, many=True)
        return api_response(True, "Order items fetched successfully.", serializer.data)

    # =============================================================
    # FILTER ORDERS BY STATUS 
    # =============================================================
    @action(detail=False, methods=['GET'], url_path='filter')
    def filter_orders(self, request):
        status_filter = request.query_params.get('status')
        queryset = self.get_queryset()
        if status_filter:
            queryset = queryset.filter(status=status_filter.upper())
        serializer = self.get_serializer(queryset, many=True)
        return api_response(True, "Filtered orders fetched successfully.", serializer.data)
    
    # =============================================================
    # SHIP ORDERS 
    # =============================================================
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminOrSuperAdmin], url_path='ship')
    @transaction.atomic
    def ship_order(self, request, pk=None):
        order = self.get_object()
        if order.status != 'CONFIRMED':
            return api_response(False, "Only confirmed orders can be shipped.", None, status.HTTP_400_BAD_REQUEST)
        
        order.status = 'SHIPPED'
        order.save(update_fields=['status'])
        return api_response(True, "Order shipped successfully.", self.get_serializer(order).data)

    # =============================================================
    # DELIVERY ORDERS 
    # =============================================================
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminOrSuperAdmin], url_path='deliver')
    @transaction.atomic
    def deliver_order(self, request, pk=None):
        order = self.get_object()
        if order.status != 'SHIPPED':
            return api_response(False, "Only shipped orders can be delivered.", None, status.HTTP_400_BAD_REQUEST)
        
        order.status = 'DELIVERED'
        order.save(update_fields=['status'])
        return api_response(True, "Order delivered successfully.", self.get_serializer(order).data)

# =============================================================
# WISHLIST VIEWSET
# =============================================================
class WishlistViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # HELPER: get or create wishlist
    # =============================================================
    def _get_wishlist(self, user):
        wishlist, _ = Wishlist.objects.get_or_create(user=user)
        return wishlist

    # =============================================================
    # GET USER WISHLIST
    # =============================================================
    def list(self, request):
        wishlist = self._get_wishlist(request.user)
        serializer = WishlistSerializer(wishlist)
        return api_response(True, "Wishlist fetched successfully.", serializer.data)

    # =============================================================
    # ADD ITEM TO WISHLIST
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='add')
    @transaction.atomic
    def add_item(self, request):
        variant_id = request.data.get("variant_id")
        if not variant_id:
            return api_response(False, "variant_id is required.", None, status.HTTP_400_BAD_REQUEST)

        variant = get_object_or_404(ProductVariant, id=variant_id)
        wishlist = self._get_wishlist(request.user)
        wishlist.variants.add(variant)
        return api_response(True, "Item added to wishlist.", None, status.HTTP_200_OK)

    # =============================================================
    # REMOVE ITEM FROM WISHLIST
    # =============================================================
    @action(detail=False, methods=['POST'], url_path='remove')
    @transaction.atomic
    def remove_item(self, request):
        variant_id = request.data.get("variant_id")
        if not variant_id:
            return api_response(False, "variant_id is required.", None, status.HTTP_400_BAD_REQUEST)

        variant = get_object_or_404(ProductVariant, id=variant_id)
        wishlist = self._get_wishlist(request.user)
        wishlist.variants.remove(variant)
        return api_response(True, "Item removed from wishlist.", None, status.HTTP_200_OK)

    # =============================================================
    # CLEAR ENTIRE WISHLIST
    # =============================================================
    @action(detail=False, methods=['DELETE'], url_path='clear')
    @transaction.atomic
    def clear_wishlist(self, request):
        wishlist = self._get_wishlist(request.user)
        wishlist.variants.clear()
        return api_response(True, "Wishlist cleared.", None, status.HTTP_200_OK)

# =============================================================
# PRODUCT REVIEW VIEWSET
# =============================================================
class ProductReviewViewSet(viewsets.ModelViewSet):
    serializer_class = ProductReviewSerializer
    permission_classes = [IsAuthenticatedUser]

    # =============================================================
    # GET QUERYSET
    # =============================================================
    def get_queryset(self):
        product_id = self.kwargs.get('product_pk')
        if product_id:
            return ProductReview.objects.filter(product_id=product_id, is_active=True)
        return ProductReview.objects.filter(is_active=True)

    # =============================================================
    # CREATE PRODUCT REVIEW
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        product_id = self.kwargs.get('product_pk')
        product = get_object_or_404(Product, id=product_id)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        existing_review = ProductReview.objects.filter(user=request.user, product=product).first()
        if existing_review:
            return api_response(False, "You have already reviewed this product.", None, status.HTTP_400_BAD_REQUEST)

        review = serializer.save(user=request.user, product=product)
        return api_response(True, "Review added successfully.", self.get_serializer(review).data, status.HTTP_201_CREATED)

    
    # =============================================================
    # RETRIEVE REVIEW
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return api_response(True, "Review retrieved successfully.", serializer.data)

    # =============================================================
    # UPDATE REVIEW
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            return api_response(False, "You can only edit your own review.", None, status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        instance.product.update_average_rating()

        return api_response(True, "Review updated successfully.", serializer.data)

    # =============================================================
    # DELETE REVIEW (Soft Delete)
    # =============================================================
    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user and not request.user.is_staff:
            return api_response(False, "You can only delete your own review.", None, status.HTTP_403_FORBIDDEN)

        instance.delete()
        instance.product.update_average_rating()
        return api_response(True, "Review deleted successfully.", None, status.HTTP_204_NO_CONTENT)

    # =============================================================
    # GET REVIEWS OF CURRENT USER
    # =============================================================
    @action(detail=False, methods=['GET'], url_path='my-reviews')
    def my_reviews(self, request):
        reviews = ProductReview.objects.filter(user=request.user, is_active=True)
        serializer = self.get_serializer(reviews, many=True)
        return api_response(True, "Your reviews fetched successfully.", serializer.data)

    # =============================================================
    # RESTORE REVIEW 
    # =============================================================
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminOrSuperAdmin], url_path='restore')
    def restore_review(self, request, pk=None):
        review = ProductReview.all_objects.get(pk=pk)
        if review.is_active:
            return api_response(False, "Review is already active.", None, status.HTTP_400_BAD_REQUEST)
        review.restore()
        return api_response(True, "Review restored successfully.", self.get_serializer(review).data)
    
    # =============================================================
    # GET AVERAGE RATING FOR PRODUCT
    # =============================================================
    @action(detail=False, methods=['GET'], url_path='product-rating')
    def product_rating(self, request):
        product_id = request.query_params.get('product_id')
        if not product_id:
            return api_response(False, "Product ID is required.", None, status.HTTP_400_BAD_REQUEST)

        product = get_object_or_404(Product, pk=product_id)
        avg_rating = ProductReview.objects.filter(product=product, is_active=True).aggregate(models.Avg('rating'))['rating__avg'] or 0
        return api_response(True, "Average rating fetched successfully.", {"product_id": product.id, "average_rating": avg_rating})

