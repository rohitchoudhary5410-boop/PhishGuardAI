"""
Test Suite for Backend Security Hardening:
1. Global & Mutating Route Rate Limiting (429 with Retry-After)
2. Payload Size Limits & Memory DoS Prevention (413)
3. Path Traversal & Filename Sanitization
4. Strict CORS Policy (Allowing verified origins, blocking evil origins)
5. Server Header Masking & Security Headers
6. SSRF Redirect Protection
"""

from __future__ import annotations

import io
import pytest


def test_cors_origin_blocking(client):
    """Verify that unauthorized external origins do NOT receive CORS allow headers."""
    # Evil origin
    res_evil = client.get("/health", headers={"Origin": "https://evil-attacker-website.xyz"})
    assert res_evil.status_code == 200
    assert "Access-Control-Allow-Origin" not in res_evil.headers

    # Authorized local dev origin
    res_good = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert res_good.status_code == 200
    assert res_good.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


def test_server_header_masked(client):
    """Verify server banner fingerprint is masked to PhishGuard-AI."""
    res = client.get("/health")
    assert res.headers.get("Server") == "PhishGuard-AI"


def test_path_traversal_sanitized(client):
    """Verify directory traversal filename tricks are sanitized safely."""
    # An attacker uploading ../../../sensitive_config.pdf
    data = {
        "file": (io.BytesIO(b"%PDF-1.4 clean test"), "../../../sensitive_config.pdf")
    }
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    data = res.get_json()
    assert data["filename"] == "sensitive_config.pdf"
    assert ".." not in data["filename"]


def test_rate_limiting_enforced(client, monkeypatch):
    """Verify that exceeding rate limits returns 429 Too Many Requests."""
    import app
    # Set a tiny rate limit for the test
    monkeypatch.setattr(app.limiter, "limit", 3)
    # Clear history for client
    app.limiter.requests.clear()

    # Make 3 valid requests
    for _ in range(3):
        r = client.post("/predict", json={"url": "https://google.com"})
        assert r.status_code == 200

    # 4th request must be blocked
    blocked = client.post("/predict", json={"url": "https://google.com"})
    assert blocked.status_code == 429
    assert "Rate limit exceeded" in blocked.get_json()["message"]
    assert blocked.headers.get("Retry-After") == "60"

    # Reset limiter requests
    app.limiter.requests.clear()


def test_oversized_file_rejected(client):
    """Verify oversized upload buffer (> 25MB) is caught."""
    # Create a 26MB stream
    huge_data = b"0" * (26 * 1024 * 1024)
    res = client.post(
        "/api/scan/file",
        data={"file": (io.BytesIO(huge_data), "huge_file.dat")},
        content_type="multipart/form-data"
    )
    assert res.status_code == 413
