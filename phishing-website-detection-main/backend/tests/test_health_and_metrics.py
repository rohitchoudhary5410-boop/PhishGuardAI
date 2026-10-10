"""
Backend Health Check & Metrics API Tests.
"""

from __future__ import annotations

import app as flask_app
import features


def test_model_loaded_successfully():
    """Verify that the Random Forest model and Scaler are properly loaded in app.py."""
    assert flask_app.model is not None, "Model should be loaded"
    assert hasattr(flask_app.model, "predict_proba"), "Model should support predict_proba"
    assert flask_app.scaler is not None, "Scaler should be loaded"
    assert hasattr(flask_app.scaler, "transform"), "Scaler should support transform"
    assert flask_app.model.n_features_in_ == 111, "Model must expect exactly 111 features"
    assert flask_app.scaler.n_features_in_ == 111, "Scaler must expect exactly 111 features"
    assert len(features.FEATURE_ORDER) == 111, "FEATURE_ORDER must contain 111 features"


def test_health_endpoint_success(client):
    """Verify GET /health returns HTTP 200 and expected schema."""
    res = client.get("/health")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert res.is_json, "Response must be JSON"

    data = res.get_json()
    assert data["status"] == "ok"
    assert data["model"] == "RandomForestClassifier"
    assert data["n_estimators"] == 100
    assert data["features_expected"] == 111
    assert data["scaler_features"] == 111
    assert "thresholds" in data
    assert data["thresholds"]["phishing"] == 0.75
    assert data["thresholds"]["legitimate"] == 0.35
    assert "training_clip_bounds" in data
    assert "degenerate_features" in data


def test_model_metrics_endpoint_success(client):
    """Verify GET /model-metrics returns valid comparison baselines and evaluation stats."""
    res = client.get("/model-metrics")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert res.is_json, "Response must be JSON"

    data = res.get_json()
    assert "models" in data
    assert isinstance(data["models"], list)
    assert len(data["models"]) == 3

    rf_model = next((m for m in data["models"] if m["name"] == "Random Forest"), None)
    assert rf_model is not None, "Random Forest model entry must exist"
    assert rf_model["selected"] is True
    assert rf_model["accuracy"] == 0.9701
    assert rf_model["precision"] == 0.9554
    assert rf_model["recall"] == 0.9592
    assert rf_model["f1_score"] == 0.9573
    assert rf_model["roc_auc"] == 0.995
    assert rf_model["training_samples"] == 69767

    assert data["testSamples"] == 17442
    assert "featureImportance" in data
    assert len(data["featureImportance"]) == 10
    assert "comparisonData" in data
    assert "confusion" in data
    assert data["confusion"]["truePositive"] == 5850
    assert data["confusion"]["trueNegative"] == 11070


def test_root_route_browser_and_json(client):
    """Verify GET / returns HTML for browsers and JSON for explicit API consumers."""
    # 1. API client requesting JSON
    api_res = client.get("/", headers={"Accept": "application/json"})
    assert api_res.status_code == 200
    assert api_res.is_json
    data = api_res.get_json()
    assert data["status"] == "ok"
    assert "endpoints" in data

    # 2. Browser requesting HTML
    browser_res = client.get(
        "/",
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    )
    assert browser_res.status_code == 200
    assert "text/html" in browser_res.content_type
    assert b"PhishGuard AI Backend Console" in browser_res.data
