from django.urls import path
from .views import (
    KitchenGetView, KitchenPostView, KitchenPutView, KitchenPatchView, KitchenDeleteView,
    StatusCodesView, RequestMetaView, QueryAndPathView, CacheAndHeadersView,
    TemplateResponseView, XMLResponseView, GzipResponseView, BrotliResponseView,
    CookiesView, RedirectView,
    JPEGImageView, JPGImageView, PNGImageView, WEBPImageView, SVGImageView,
)

urlpatterns = [
    # CRUD
    path("get/", KitchenGetView.as_view(), name="kitchen-get"),
    path("post/", KitchenPostView.as_view(), name="kitchen-post"),
    path("put/", KitchenPutView.as_view(), name="kitchen-put"),
    path("patch/", KitchenPatchView.as_view(), name="kitchen-patch"),
    path("delete/", KitchenDeleteView.as_view(), name="kitchen-delete"),

    # Extras
    path("status/", StatusCodesView.as_view(), name="status-all"),
    path("status/<int:code>/", StatusCodesView.as_view(), name="status-single"),
    path("meta/", RequestMetaView.as_view(), name="meta"),
    path("query/", QueryAndPathView.as_view(), name="query"),
    path("path/<str:name>/", QueryAndPathView.as_view(), name="path"),
    path("cache/", CacheAndHeadersView.as_view(), name="cache"),
    path("template/", TemplateResponseView.as_view(), name="template"),
    path("xml/", XMLResponseView.as_view(), name="xml"),
    path("gzip/", GzipResponseView.as_view(), name="gzip"),
    path("brotli/", BrotliResponseView.as_view(), name="brotli"),
    path("cookies/", CookiesView.as_view(), name="cookies"),
    path("redirect/", RedirectView.as_view(), name="redirect"),

    # Images
    path("image/jpeg/", JPEGImageView.as_view(), name="image-jpeg"),
    path("image/jpg/", JPGImageView.as_view(), name="image-jpg"),
    path("image/png/", PNGImageView.as_view(), name="image-png"),
    path("image/webp/", WEBPImageView.as_view(), name="image-webp"),
    path("image/svg/", SVGImageView.as_view(), name="image-svg"),
]
