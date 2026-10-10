"""
Pytest configuration and shared fixtures for PhishGuard AI backend tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure backend directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as flask_app
import features


@pytest.fixture
def app():
    """Flask application instance configured for testing."""
    flask_app.app.config.update(
        {
            "TESTING": True,
        }
    )
    return flask_app.app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def mock_network():
    """
    Mocks network feature extraction in features.py so that tests:
    1. Run fast (<10ms per test).
    2. Never connect to live suspicious websites or the internet.
    3. Return consistent baseline network values.
    """
    baseline_network = {
        "domain_spf": 1,
        "asn_ip": 15169,
        "time_domain_activation": 7300,
        "time_domain_expiration": 365,
        "qty_ip_resolved": 1,
        "qty_nameservers": 4,
        "qty_mx_servers": 5,
        "ttl_hostname": 300,
        "tls_ssl_certificate": 1,
        "time_response": 0.15,
        "qty_redirects": 0,
        "url_google_index": -1,
        "domain_google_index": -1,
    }

    with patch("features.extract_network", return_value=baseline_network) as mocked:
        yield mocked
