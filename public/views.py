import json, random
from pathlib import Path
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from rest_framework.permissions import AllowAny

# =====================================================
# SETTINGS
# =====================================================
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# =====================================================
# BASE VIEW
# =====================================================
class JSONBaseView(APIView):
    """Base class for all JSON dataset views"""
    permission_classes = [AllowAny]
    filename = None
    id_field = "id"

    def get_data(self):
        """Load dataset JSON file"""
        path = DATA_DIR / f"{self.filename}.json"
        try:
            data = json.load(open(path, "r", encoding="utf-8"))
            if isinstance(data, dict):
                data = next(iter(data.values()))
            if not isinstance(data, list):
                data = []
            return data
        except FileNotFoundError:
            return []

# =====================================================
# LIST VIEW
# =====================================================
class JSONListView(JSONBaseView):
    """GET all items (paginated)"""
    def get(self, request):
        data = self.get_data()
        paginator = PageNumberPagination()
        paginator.page_size = 10
        page = paginator.paginate_queryset(data, request)
        return paginator.get_paginated_response(page)


# =====================================================
# DETAIL VIEW
# =====================================================
class JSONDetailView(JSONBaseView):
    """GET single item by ID"""
    def get(self, request, pk):
        data = self.get_data()
        item = next((d for d in data if str(d.get(self.id_field)) == str(pk)), None)
        if not item:
            return Response(
                {"detail": f"{self.filename.title()} not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        return Response(item)


# =====================================================
# RANDOM VIEW
# =====================================================
class JSONRandomView(JSONBaseView):
    """GET random item"""
    def get(self, request):
        data = self.get_data()
        if not data:
            return Response(
                {"detail": "No data available"},
                status=status.HTTP_404_NOT_FOUND
            )
        return Response(random.choice(data))


# =====================================================
# SPECIFIC DATASET CLASSES
# =====================================================
class UserListView(JSONListView): filename = "users"
class UserDetailView(JSONDetailView): filename = "users"
class UserRandomView(JSONRandomView): filename = "users"

class ProductListView(JSONListView): filename = "products"
class ProductDetailView(JSONDetailView): filename = "products"
class ProductRandomView(JSONRandomView): filename = "products"

class JokeListView(JSONListView): filename = "jokes"
class JokeDetailView(JSONDetailView): filename = "jokes"
class JokeRandomView(JSONRandomView): filename = "jokes"

class BookListView(JSONListView): filename = "books"
class BookDetailView(JSONDetailView): filename = "books"
class BookRandomView(JSONRandomView): filename = "books"

class StockListView(JSONListView): filename = "stocks"
class StockDetailView(JSONDetailView): filename = "stocks"
class StockRandomView(JSONRandomView): filename = "stocks"

class QuoteListView(JSONListView): filename = "quotes"
class QuoteDetailView(JSONDetailView): filename = "quotes"
class QuoteRandomView(JSONRandomView): filename = "quotes"

class MealListView(JSONListView): filename = "meals"
class MealDetailView(JSONDetailView): filename = "meals"
class MealRandomView(JSONRandomView): filename = "meals"

class DogListView(JSONListView): filename = "dogs"
class DogDetailView(JSONDetailView): filename = "dogs"
class DogRandomView(JSONRandomView): filename = "dogs"

class CatListView(JSONListView): filename = "cats"
class CatDetailView(JSONDetailView): filename = "cats"
class CatRandomView(JSONRandomView): filename = "cats"