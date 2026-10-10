"""
Feature Extraction, Order, Degradation, Bounds, and SSRF Security Tests.
"""

from __future__ import annotations

import features
import pytest


def test_feature_order_count_and_types():
    """Verify that exactly 111 features exist in FEATURE_ORDER and are correctly named."""
    assert len(features.FEATURE_ORDER) == 111
    assert "qty_dot_url" in features.FEATURE_ORDER
    assert "length_url" in features.FEATURE_ORDER
    assert "directory_length" in features.FEATURE_ORDER
    assert "time_domain_activation" in features.FEATURE_ORDER
    assert "asn_ip" in features.FEATURE_ORDER
    assert "tls_ssl_certificate" in features.FEATURE_ORDER


def test_feature_extraction_without_network():
    """Verify that with_network=False extracts all 111 features without network calls."""
    vector, named, clamped = features.extract_features(
        "https://example.com/test/index.html?ref=123",
        with_network=False,
    )
    assert len(vector) == 111
    assert len(named) == 111
    assert all(isinstance(v, (int, float)) for v in vector)

    # Lexical features must be extracted
    assert named["length_url"] > 0
    assert named["domain_length"] > 0
    assert named["directory_length"] > 0

    # Network-dependent features must gracefully degrade to -1
    assert named["time_domain_activation"] == -1
    assert named["asn_ip"] == -1
    assert named["time_response"] == -1
    assert named["qty_nameservers"] == -1
    assert named["tls_ssl_certificate"] == -1


def test_training_clipping_bounds():
    """Verify that training IQR clipping clamps length_url, qty_dot_url, qty_at_url, url_shortened."""
    # Create an artificially long URL
    long_url = "https://example.com/" + "a" * 150
    _, named, clamped = features.extract_features(long_url, with_network=False, clip=True)

    # length_url must be clamped to 72.0 as per training bounds
    assert named["length_url"] <= 72.0
    assert "length_url" in clamped

    # Degenerate features must be clamped to their training constants
    assert named["qty_dot_url"] == 2.0
    assert named["qty_at_url"] == 0.0
    assert named["url_shortened"] == 0.0


def test_ssrf_protection_guards():
    """Verify that is_ssrf_risk detects loopback, private IPs, and internal targets."""
    # Loopback
    assert features.is_ssrf_risk("127.0.0.1") is True
    assert features.is_ssrf_risk("localhost") is True
    assert features.is_ssrf_risk("::1") is True

    # Private RFC 1918
    assert features.is_ssrf_risk("192.168.1.1") is True
    assert features.is_ssrf_risk("10.0.0.1") is True
    assert features.is_ssrf_risk("172.16.0.1") is True

    # Link-local (Cloud metadata e.g. AWS/GCP/Azure)
    assert features.is_ssrf_risk("169.254.169.254") is True

    # Empty / None
    assert features.is_ssrf_risk("") is True
    assert features.is_ssrf_risk(None) is True

    # Valid external public domain
    assert features.is_ssrf_risk("google.com") is False
    assert features.is_ssrf_risk("github.com") is False
