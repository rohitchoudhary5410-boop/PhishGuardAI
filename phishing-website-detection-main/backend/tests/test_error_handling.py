"""
Input Validation & Error Handling Tests.
"""

from __future__ import annotations

import pytest


def test_predict_missing_url(client):
    """Missing 'url' field must return 400."""
    res = client.post("/predict", json={})
    assert res.status_code == 400
    assert "required" in res.get_json()["message"]


def test_predict_empty_url(client):
    """Empty or whitespace 'url' string must return 400."""
    res1 = client.post("/predict", json={"url": ""})
    assert res1.status_code == 400

    res2 = client.post("/predict", json={"url": "   \t\n  "})
    assert res2.status_code == 400


def test_predict_non_string_url(client):
    """Non-string 'url' types must return 400 without crashing."""
    res1 = client.post("/predict", json={"url": 12345})
    assert res1.status_code == 400

    res2 = client.post("/predict", json={"url": ["https://google.com"]})
    assert res2.status_code == 400

    res3 = client.post("/predict", json={"url": None})
    assert res3.status_code == 400


def test_predict_malformed_json(client):
    """Malformed or non-dict JSON body must return 400."""
    res = client.post(
        "/predict",
        data="this is not json",
        content_type="application/json",
    )
    assert res.status_code == 400

    res_arr = client.post(
        "/predict",
        json=["https://google.com"],
    )
    assert res_arr.status_code == 400


def test_predict_oversized_url(client):
    """URL exceeding 2048 characters must return 400."""
    giant_url = "https://example.com/" + "a" * 2500
    res = client.post("/predict", json={"url": giant_url})
    assert res.status_code == 400
    assert "2048" in res.get_json()["message"]


def test_predict_invalid_feature_overrides(client):
    """Non-dict feature overrides must return 400."""
    res = client.post("/predict", json={"url": "https://google.com", "features": "not a dict"})
    assert res.status_code == 400


def test_bulk_scan_empty_payload(client):
    """POST /bulk-scan with empty payload must return 400."""
    res = client.post("/bulk-scan", json={})
    assert res.status_code == 400


def test_bulk_scan_empty_urls_list(client):
    """POST /bulk-scan with empty urls list must return 400."""
    res = client.post("/bulk-scan", json={"urls": []})
    assert res.status_code == 400


def test_bulk_scan_exceeds_max_limit(client):
    """POST /bulk-scan with > 200 URLs must return 413 Payload Too Large."""
    urls = [f"https://example{i}.com" for i in range(250)]
    res = client.post("/bulk-scan", json={"urls": urls})
    assert res.status_code == 413
    assert "200" in res.get_json()["message"]


def test_email_scan_missing_content(client):
    """POST /api/email/scan without content/subject/body must return 400."""
    res = client.post("/api/email/scan", json={})
    assert res.status_code == 400
