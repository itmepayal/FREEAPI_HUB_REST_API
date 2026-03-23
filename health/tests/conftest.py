import pytest
from rest_framework.test import APIClient

@pytest.fixture
def api_client():
    """Return a DRF test client for API requests."""
    return APIClient()