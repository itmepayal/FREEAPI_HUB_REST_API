import io
import gzip
import brotli
from django.http import HttpResponse, FileResponse, HttpResponseRedirect
from django.template.loader import render_to_string
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import AllowAny
from PIL import Image, ImageDraw
from core.logger import get_logger 
from core.constants import STATUS_CODES
from core.utils import api_response, get_client_ip

# ============================================================
# Logger Configuration
# ============================================================
logger = get_logger(__name__)

# ============================================================
# Kitchen GET Endpoint
# ============================================================
class KitchenGetView(APIView):
    """Handles GET requests"""
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        logger.info("KitchenGetView accessed via GET")
        return api_response(True, "GET request received", {"method": "GET"})

# ============================================================
# Kitchen POST Endpoint
# ============================================================
class KitchenPostView(APIView):
    """Handles POST requests"""
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.info("KitchenPostView accessed via POST")
        return api_response(True, "POST request received", {"method": "POST", "data": request.data})

# ============================================================
# Kitchen PUT Endpoint
# ============================================================
class KitchenPutView(APIView):
    """Handles PUT requests"""
    permission_classes = [AllowAny]

    def put(self, request, *args, **kwargs):
        logger.info("KitchenPutView accessed via PUT")
        return api_response(True, "PUT request received", {"method": "PUT", "data": request.data})

# ============================================================
# Kitchen PATCH Endpoint
# ============================================================
class KitchenPatchView(APIView):
    """Handles PATCH requests"""
    permission_classes = [AllowAny]

    def patch(self, request, *args, **kwargs):
        logger.info("KitchenPatchView accessed via PATCH")
        return api_response(True, "PATCH request received", {"method": "PATCH", "data": request.data})

# ============================================================
# Kitchen DELETE Endpoint
# ============================================================
class KitchenDeleteView(APIView):
    """Handles DELETE requests"""
    permission_classes = [AllowAny]

    def delete(self, request, *args, **kwargs):
        logger.warning("KitchenDeleteView received DELETE request")
        return api_response(True, "DELETE request processed", {}, status.HTTP_204_NO_CONTENT)

# ============================================================
# Status Codes Endpoint
# ============================================================
class StatusCodesView(APIView):
    """Returns all or specific HTTP status codes with detailed metadata"""
    permission_classes = [AllowAny]

    def get(self, request, code=None):
        logger.debug(f"StatusCodesView accessed with code={code}")

        if code is None:
            logger.info("Returning full HTTP status code metadata list")
            return api_response(True, "All HTTP status codes", STATUS_CODES, status_code=status.HTTP_200_OK)

        try:
            code_str = str(int(code))  
        except ValueError:
            logger.warning(f"Invalid status code value: {code}")
            return api_response(False, "Invalid status code", status_code=status.HTTP_400_BAD_REQUEST)

        code_data = STATUS_CODES.get(code_str)
        if not code_data:
            logger.error(f"Status code {code_str} not found in STATUS_CODES dictionary")
            return api_response(False, f"Status code {code_str} not found", status_code=status.HTTP_404_NOT_FOUND)

        logger.info(f"Returning details for status code {code_str}")
        return api_response(True, "Status code details", code_data, status_code=int(code_str))

# ============================================================
# Request Meta Endpoint
# ============================================================
class RequestMetaView(APIView):
    """Returns client IP, user agent, and request headers"""
    permission_classes = [AllowAny]

    def get(self, request):
        client_ip = get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "")
        headers = {k[5:].replace("_", "-").title(): v for k, v in request.META.items() if k.startswith("HTTP_")}
        logger.info(f"RequestMetaView accessed from {client_ip} with UA={ua}")
        data = {"headers": headers, "client_ip": client_ip, "user_agent": ua}
        return api_response(True, "Request metadata", data)

# ============================================================
# Query & Path Params Endpoint
# ============================================================
class QueryAndPathView(APIView):
    """Handles query parameters and path variables"""
    permission_classes = [AllowAny]

    def get(self, request, name=None):
        logger.debug(f"QueryAndPathView accessed with name={name}")
        if name:
            return api_response(True, "Path variable received", {"path_variable": name})
        return api_response(True, "Query params received", {"query_params": request.query_params})

# ============================================================
# Cache & Headers Endpoint
# ============================================================
class CacheAndHeadersView(APIView):
    """Sets cache control and custom response headers"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("CacheAndHeadersView accessed")
        resp = api_response(True, "Cache-Control example", {"cached": True})
        resp["Cache-Control"] = "public, max-age=60"
        resp["X-Example"] = "KitchenSink"
        return resp

# ============================================================
# Template Response Endpoint
# ============================================================
class TemplateResponseView(APIView):
    """Renders and returns an HTML template"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("TemplateResponseView rendering template")
        html = render_to_string("public/example.html", {"name": "Kitchen"})
        return HttpResponse(html, content_type="text/html")

# ============================================================
# XML Response Endpoint
# ============================================================
class XMLResponseView(APIView):
    """Returns XML formatted response"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.debug("XMLResponseView accessed")
        xml = '<?xml version="1.0"?><response><msg>Hello XML</msg></response>'
        return HttpResponse(xml, content_type="application/xml")

# ============================================================
# Gzip Compression Endpoint
# ============================================================
class GzipResponseView(APIView):
    """Returns gzip compressed data"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("GzipResponseView accessed for compression")
        text = "This is some text compressed with gzip" * 10
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb") as f:
            f.write(text.encode("utf-8"))
        resp = HttpResponse(out.getvalue(), content_type="application/octet-stream")
        resp["Content-Encoding"] = "gzip"
        return resp

# ============================================================
# Brotli Compression Endpoint
# ============================================================
class BrotliResponseView(APIView):
    """Returns Brotli compressed data"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("BrotliResponseView accessed for Brotli compression")
        try:
            compressed = brotli.compress(("brotli text " * 30).encode("utf-8"))
        except Exception:
            logger.exception("Brotli compression failed")
            return api_response(False, "Install 'brotli' package for compression", status_code=500)
        resp = HttpResponse(compressed, content_type="application/octet-stream")
        resp["Content-Encoding"] = "br"
        return resp

# ============================================================
# Cookies Endpoint
# ============================================================
class CookiesView(APIView):
    """Handles cookie creation, retrieval, and deletion"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("CookiesView GET - cookies fetched")
        return api_response(True, "Cookies fetched", {"cookies": request.COOKIES})

    def post(self, request):
        logger.info("CookiesView POST - setting cookie")
        resp = api_response(True, "Cookie set successfully")
        resp.set_cookie("kitchen_cookie", "yummy", max_age=86400, httponly=True)
        return resp

    def delete(self, request):
        logger.info("CookiesView DELETE - removing cookie")
        resp = api_response(True, "Cookie removed successfully")
        resp.delete_cookie("kitchen_cookie")
        return resp

# ============================================================
# Redirect Endpoint
# ============================================================
class RedirectView(APIView):
    """Redirects user to an external URL"""
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("RedirectView redirecting user to example.com")
        return HttpResponseRedirect("https://example.com/")

# ============================================================
# JPEG Image
# ============================================================
class JPEGImageView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("JPEGImageView generating image")
        img = Image.new("RGB", (400, 100), color=(200, 200, 200))
        d = ImageDraw.Draw(img)
        d.text((10, 40), "Image JPEG", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        return FileResponse(buf, content_type="image/jpeg", filename="image.jpeg")

# ============================================================
# JPG Image
# ============================================================
class JPGImageView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("JPGImageView generating image")
        img = Image.new("RGB", (400, 100), color=(200, 200, 200))
        d = ImageDraw.Draw(img)
        d.text((10, 40), "Image JPG", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        return HttpResponse(buf.getvalue(), content_type="image/jpeg")

# ============================================================
# PNG Image
# ============================================================
class PNGImageView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("PNGImageView generating image")
        img = Image.new("RGB", (400, 100), color=(200, 200, 200))
        d = ImageDraw.Draw(img)
        d.text((10, 40), "Image PNG", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return HttpResponse(buf.getvalue(), content_type="image/png")

# ============================================================
# WEBP Image
# ============================================================
class WEBPImageView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("WEBPImageView generating image")
        img = Image.new("RGB", (400, 100), color=(200, 200, 200))
        d = ImageDraw.Draw(img)
        d.text((10, 40), "Image WEBP", fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="WEBP")
        buf.seek(0)
        return HttpResponse(buf.getvalue(), content_type="image/webp")

# ============================================================
# SVG Image
# ============================================================
class SVGImageView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger.info("SVGImageView generating SVG")
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="100">'
            '<rect width="100%" height="100%" fill="lightgray"/>'
            '<text x="10" y="50">SVG KitchenSink</text></svg>'
        )
        return HttpResponse(svg, content_type="image/svg+xml")
