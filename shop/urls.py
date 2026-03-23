from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedDefaultRouter
from shop import views

# =============================================================
# MAIN ROUTER
# =============================================================
router = DefaultRouter()
router.register(r'categories', views.CategoryViewSet, basename='category')
router.register(r'products', views.ProductViewSet, basename='product')
router.register(r'addresses', views.AddressViewSet, basename='address')
router.register(r'coupons', views.CouponViewSet, basename='coupon')
router.register(r'cart', views.CartViewSet, basename='cart')
router.register(r'orders', views.OrderViewSet, basename='order')
router.register(r'payments', views.PaymentViewSet, basename='payment')
router.register(r'wishlist', views.WishlistViewSet, basename='wishlist')

# =============================================================
# NESTED ROUTERS FOR PRODUCT
# =============================================================
products_router = NestedDefaultRouter(router, r'products', lookup='product')
products_router.register(r'variants', views.ProductVariantViewSet, basename='product-variants')
products_router.register(r'images', views.ProductImageViewSet, basename='product-images')
products_router.register(r'reviews', views.ProductReviewViewSet, basename='product-reviews')

# =============================================================
# URLPATTERNS
# =============================================================
urlpatterns = [
    path('', include(router.urls)),
    path('', include(products_router.urls)),
]


