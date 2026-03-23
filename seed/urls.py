from django.urls import path
from .views import SeedTodosView

app_name = "seed"

urlpatterns = [
    path("todos/", SeedTodosView.as_view(), name="seed-todos"),
]