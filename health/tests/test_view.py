import pytest
from rest_framework import status
from django.urls import reverse

pytestmark = pytest.mark.django_db

def test_health_check_success(api_client):
    """Ensure health endpoint returns 200 OK with expected JSON"""
    url = reverse("health:health-check") 
    response = api_client.get(url)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {
        "status": "ok",
        "message": "API is running"
    }
    