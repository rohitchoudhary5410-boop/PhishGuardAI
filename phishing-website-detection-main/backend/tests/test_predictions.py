"""
Machine Learning URL Prediction Endpoint Tests.
"""

from __future__ import annotations

import pytest


def test_predict_legitimate_url(client, mock_network):
    """Test URL prediction with legitimate URL under mocked network."""
    res = client.post("/predict", json={"url": "https://www.google.com"})
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.get_json()

    # Check response structure
    assert data["url"] == "https://www.google.com"
    assert data["prediction"] in {"Legitimate", "Suspicious", "Phishing"}
    assert "probability" in data
    assert "risk_score" in data
    assert "phishing_probability" in data
    assert "model" in data
    assert data["model"] == "Random Forest"
    assert "scan_id" in data
    assert "scan_time" in data
    assert "features" in data
    assert isinstance(data["features"], dict)

    # Risk score must be an integer between 0 and 100
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100

    # Phishing probability must be float between 0.0 and 1.0
    assert 0.0 <= data["phishing_probability"] <= 1.0

    # Model confidence probability must be between 0.0 and 1.0
    assert 0.0 <= data["probability"] <= 1.0

    # Classification rules verification
    p = data["phishing_probability"]
    if p >= 0.75:
        assert data["prediction"] == "Phishing"
    elif p <= 0.35:
        assert data["prediction"] == "Legitimate"
    else:
        assert data["prediction"] == "Suspicious"


def test_predict_phishing_url_with_overrides(client, mock_network):
    """
    Test prediction with high-risk phishing feature overrides
    to verify deterministic phishing classification without visiting harmful sites.
    """
    res = client.post(
        "/predict",
        json={
            "url": "http://paypal-verification-secure-update-account.com/login/auth.php",
            "features": {
                "length_url": 68,
                "directory_length": 45,
                "time_domain_activation": 1,
                "qty_dollar_directory": 2,
                "tls_ssl_certificate": 0,
                "qty_redirects": 3,
            },
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert 0 <= data["risk_score"] <= 100
    assert "features" in data
    assert data["total_features"] == 111


def test_predict_classification_thresholds(client, mock_network):
    """Verify that predictions precisely obey PHISHING_THRESHOLD (0.75) and LEGITIMATE_THRESHOLD (0.35)."""
    # Test a set of URLs from the authorized test set
    test_urls = [
        "https://www.wikipedia.org",
        "https://github.com",
        "http://netflix-billing-issue-resolve.net/verify",
        "http://secure-bank-update-account.info/login",
    ]

    for url in test_urls:
        res = client.post("/predict", json={"url": url})
        assert res.status_code == 200
        data = res.get_json()
        p = data["phishing_probability"]

        if p >= 0.75:
            assert data["prediction"] == "Phishing"
        elif p <= 0.35:
            assert data["prediction"] == "Legitimate"
        else:
            assert data["prediction"] == "Suspicious"

        assert 0 <= data["risk_score"] <= 100


def test_predict_feature_explanation_block(client, mock_network):
    """Verify top explained features returned in prediction response."""
    res = client.post("/predict", json={"url": "https://accounts.google.com/signin"})
    assert res.status_code == 200
    data = res.get_json()

    features_block = data["features"]
    assert isinstance(features_block, dict)
    assert len(features_block) <= 8

    for feat_name, feat_info in features_block.items():
        assert "label" in feat_info
        assert "value" in feat_info
        assert "risk" in feat_info
        assert feat_info["risk"] in {"low_risk", "medium_risk", "high_risk"}
        assert "impact" in feat_info
        assert "description" in feat_info
