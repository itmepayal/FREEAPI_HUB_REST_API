# core/views.py
from django.shortcuts import render
from django.urls import get_resolver

def api_root(request):
    """
    Nicely designed API Hub root page
    """
    resolver = get_resolver()
    api_namespaces = [ns for ns, _ in resolver.namespace_dict.items() if ns]

    context = {
        "project": "config Hub",
        "version": "v1.0",
        "docs": {
            "swagger": request.build_absolute_uri("/api/v1/docs/swagger/"),
            "redoc": request.build_absolute_uri("/api/v1/docs/redoc/"),
            "schema": request.build_absolute_uri("/api/v1/schema/")
        },
        "apps": api_namespaces
    }
    return render(request, "core/api_root.html", context)
