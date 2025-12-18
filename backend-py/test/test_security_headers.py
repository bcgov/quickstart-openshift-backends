"""Tests for SecurityHeadersMiddleware to ensure security headers are correctly applied."""

import pytest
from fastapi.testclient import TestClient
from src.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


def test_security_headers_present(client):
    """Test that all required security headers are present in responses."""
    response = client.get("/")
    
    # Required security headers
    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    
    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"
    
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    
    # HSTS is only set on HTTPS requests (see main.py lines 67-72)
    # TestClient uses HTTP by default, so we verify HSTS is NOT present on HTTP requests
    assert "Strict-Transport-Security" not in response.headers
    
    assert "Referrer-Policy" in response.headers
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_server_header_removed(client):
    """Test that Server header and proxy-related headers are removed."""
    response = client.get("/")
    
    # Server header should not be present
    assert "Server" not in response.headers
    
    # Proxy-related headers should not be present
    assert "X-Powered-By" not in response.headers
    assert "X-AspNet-Version" not in response.headers


def test_cache_control_api_endpoints(client):
    """Test that API endpoints have proper no-cache headers."""
    # Test an API endpoint
    response = client.get("/api/v1/user")
    
    # API endpoints should have no-cache headers
    assert "Cache-Control" in response.headers
    cache_control = response.headers["Cache-Control"]
    assert "no-store" in cache_control
    assert "no-cache" in cache_control
    assert "private" in cache_control
    
    assert "Pragma" in response.headers
    assert response.headers["Pragma"] == "no-cache"
    
    assert "Expires" in response.headers
    assert response.headers["Expires"] == "0"


def test_cache_control_non_api_endpoints(client):
    """Test that non-API endpoints have appropriate cache headers."""
    response = client.get("/")
    
    # Non-API endpoints should allow caching with revalidation
    assert "Cache-Control" in response.headers
    cache_control = response.headers["Cache-Control"]
    assert "public" in cache_control
    assert "max-age=3600" in cache_control
    assert "must-revalidate" in cache_control


def test_security_headers_different_status_codes(client):
    """Test that security headers are present for different HTTP status codes."""
    # Test 200 OK
    response = client.get("/")
    assert response.status_code == 200
    assert "X-Content-Type-Options" in response.headers
    
    # Test 404 Not Found
    response = client.get("/nonexistent")
    assert response.status_code == 404
    assert "X-Content-Type-Options" in response.headers


def test_security_headers_different_methods(client):
    """Test that security headers are present for different HTTP methods."""
    # GET request
    response = client.get("/")
    assert "X-Content-Type-Options" in response.headers
    
    # POST request (if endpoint exists)
    # Note: This will fail if / doesn't accept POST, but that's okay
    # The important thing is headers are set regardless of method
    response = client.post("/", json={})
    # Headers should still be present even if method not allowed
    assert response.status_code in (200, 405)
    assert "X-Content-Type-Options" in response.headers


def test_hsts_only_on_https(client):
    """Test that HSTS header is only set on HTTPS requests."""
    # HTTP request (TestClient default) - HSTS should not be present
    response = client.get("/")
    assert response.url.scheme == "http"
    assert "Strict-Transport-Security" not in response.headers
    
    # HTTP request with X-Forwarded-Proto: http - HSTS should not be present
    response = client.get("/", headers={"X-Forwarded-Proto": "http"})
    assert "Strict-Transport-Security" not in response.headers
    
    # Simulate HTTPS via X-Forwarded-Proto header (reverse proxy scenario)
    response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert "Strict-Transport-Security" in response.headers
    assert "preload" in response.headers["Strict-Transport-Security"]
    assert "includeSubDomains" in response.headers["Strict-Transport-Security"]
