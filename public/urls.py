from django.urls import path
from .views import (
    UserListView, UserDetailView, UserRandomView,
    ProductListView, ProductDetailView, ProductRandomView,
    JokeListView, JokeDetailView, JokeRandomView,
    BookListView, BookDetailView, BookRandomView,
    StockListView, StockDetailView, StockRandomView,
    QuoteListView, QuoteDetailView, QuoteRandomView,
    MealListView, MealDetailView, MealRandomView,
    DogListView, DogDetailView, DogRandomView,
    CatListView, CatDetailView, CatRandomView,
)

urlpatterns = [
    # ---------------- Users ----------------
    path("users/random/", UserRandomView.as_view(), name="user-random"),
    path("users/<str:pk>/", UserDetailView.as_view(), name="user-detail"),
    path("users/", UserListView.as_view(), name="user-list"),

    # ---------------- Products ----------------
    path("products/random/", ProductRandomView.as_view(), name="product-random"),
    path("products/<str:pk>/", ProductDetailView.as_view(), name="product-detail"),
    path("products/", ProductListView.as_view(), name="product-list"),

    # ---------------- Jokes ----------------
    path("jokes/random/", JokeRandomView.as_view(), name="joke-random"),
    path("jokes/<str:pk>/", JokeDetailView.as_view(), name="joke-detail"),
    path("jokes/", JokeListView.as_view(), name="joke-list"),

    # ---------------- Books ----------------
    path("books/random/", BookRandomView.as_view(), name="book-random"),
    path("books/<str:pk>/", BookDetailView.as_view(), name="book-detail"),
    path("books/", BookListView.as_view(), name="book-list"),

    # ---------------- Stocks ----------------
    path("stocks/random/", StockRandomView.as_view(), name="stock-random"),
    path("stocks/<str:pk>/", StockDetailView.as_view(), name="stock-detail"),
    path("stocks/", StockListView.as_view(), name="stock-list"),

    # ---------------- Quotes ----------------
    path("quotes/random/", QuoteRandomView.as_view(), name="quote-random"),
    path("quotes/<str:pk>/", QuoteDetailView.as_view(), name="quote-detail"),
    path("quotes/", QuoteListView.as_view(), name="quote-list"),

    # ---------------- Meals ----------------
    path("meals/random/", MealRandomView.as_view(), name="meal-random"),
    path("meals/<str:pk>/", MealDetailView.as_view(), name="meal-detail"),
    path("meals/", MealListView.as_view(), name="meal-list"),

    # ---------------- Dogs ----------------
    path("dogs/random/", DogRandomView.as_view(), name="dog-random"),
    path("dogs/<str:pk>/", DogDetailView.as_view(), name="dog-detail"),
    path("dogs/", DogListView.as_view(), name="dog-list"),

    # ---------------- Cats ----------------
    path("cats/random/", CatRandomView.as_view(), name="cat-random"),
    path("cats/<str:pk>/", CatDetailView.as_view(), name="cat-detail"),
    path("cats/", CatListView.as_view(), name="cat-list"),
]
