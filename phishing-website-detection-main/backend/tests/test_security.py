"""
Security Configuration & API Hardening Tests.
"""

from __future__ import annotations

import app as flask_app
import features
import pytest


def test_cors_headers_present(client):
    """Verify CORS headers are present to allow communication with React frontend."""
    res = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert res.status_code == 200
    assert "Access-Control-Allow-Origin" in res.headers


def test_debug_mode_disabled():
    """Verify Flask debug mode is not enabled in production configuration."""
    assert flask_app.app.debug is False, "Production Flask app should not run in debug mode"


def test_ssrf_blocked_in_url_prediction(client):
    """
    Verify that scanning an internal URL (e.g. localhost, 127.0.0.1, 192.168.1.1)
    does not trigger internal network requests, but completes safely using lexical evaluation.
    """
    internal_urls = [
        "http://127.0.0.1:5000/predict",
        "http://localhost:5000",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/admin",
    ]

    for url in internal_urls:
        res = client.post("/predict", json={"url": url})
        assert res.status_code == 200
        data = res.get_json()
        assert 0 <= data["risk_score"] <= 100
        # Network features should be missing (-1 or 0 for TLS)
        assert data["unavailable_features"] >= 10


def test_no_sensitive_secrets_in_errors(client):
    """Verify that error messages do not leak internal system paths or secrets."""
    res = client.post("/predict", json={"url": "   "})
    assert res.status_code == 400
    msg = res.get_json().get("message", "")
    assert "password" not in msg.lower()
    assert "token" not in msg.lower()
    assert "secret" not in msg.lower()
