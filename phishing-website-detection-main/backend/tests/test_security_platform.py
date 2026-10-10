"""
Test Suite for PhishGuard AI Security Platform & Multi-Vector Threat Engine
Tests:
1. Background Protection State Machine (Start, Pause, Stop)
2. Website Protection URL Scanner & SSRF Gateways
3. On-Device File Security Scanner (Signatures, Spoofed Extensions, EICAR, Hashes, ZIPs)
4. Scam Message and Payment-Link Analyzer
5. Unified Scan History & False-Positive Reporting
"""

from __future__ import annotations

import io
import zipfile
import pytest


# ---------------------------------------------------------------------------
# 1. Protection State Engine Tests
# ---------------------------------------------------------------------------

def test_security_status_endpoint(client):
    """Verify /api/security/status returns valid JSON and active state."""
    res = client.get("/api/security/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "status" in data
    assert data["status"] in ("ACTIVE", "PAUSED", "STOPPED")
    assert "total_scans" in data
    assert "threats_blocked" in data
    assert "uptime_seconds" in data
    assert "limitations_notice" in data


def test_security_controls_state_machine(client):
    """Verify Start, Pause, and Stop transitions."""
    # Pause
    res = client.post("/api/security/pause")
    assert res.status_code == 200
    assert res.get_json()["status"] == "PAUSED"

    # Verify status reflects pause
    st = client.get("/api/security/status").get_json()
    assert st["status"] == "PAUSED"
    assert st["is_active"] is False

    # Stop
    res = client.post("/api/security/stop")
    assert res.status_code == 200
    assert res.get_json()["status"] == "STOPPED"

    # Start
    res = client.post("/api/security/start")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ACTIVE"
    st = client.get("/api/security/status").get_json()
    assert st["status"] == "ACTIVE"
    assert st["is_active"] is True


# ---------------------------------------------------------------------------
# 2. Website Protection URL Scanner Tests
# ---------------------------------------------------------------------------

def test_scan_url_benign(client):
    """Verify benign website scan returns Safe verdict."""
    res = client.post("/api/scan/url", json={"url": "https://wikipedia.org", "with_network": False})
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] in ("Safe", "Legitimate")
    assert data["risk_score"] < 50
    assert "detection_reasons" in data


def test_scan_url_ssrf_blocking(client):
    """Verify SSRF targets are blocked at gateway with high risk and explanation."""
    targets = [
        "http://127.0.0.1:5000/internal",
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/router-config",
        "http://192.168.1.1/admin"
    ]
    for url in targets:
        res = client.post("/api/scan/url", json={"url": url})
        assert res.status_code == 200
        data = res.get_json()
        assert data["verdict"] == "Blocked"
        assert data["is_ssrf_blocked"] is True
        assert data["risk_score"] >= 90
        assert "SSRF" in data["threat_category"]


def test_scan_url_brand_impersonation(client):
    """Verify brand impersonation in subdomain receives high risk."""
    url = "http://paypal.com.account-update.xyz/login/verify"
    res = client.post("/api/scan/url", json={"url": url, "with_network": False})
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_score"] >= 45
    assert any("impersonation" in r.lower() or "paypal" in r.lower() for r in data["detection_reasons"])


def test_scan_url_direct_ip(client):
    """Verify IP-address URLs are flagged as suspicious or phishing."""
    url = "http://93.184.216.34/secure/login.php"
    res = client.post("/api/scan/url", json={"url": url, "with_network": False})
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_score"] >= 40
    assert any("ip address" in r.lower() for r in data["detection_reasons"])


# ---------------------------------------------------------------------------
# 3. On-Device File Security Scanner Tests
# ---------------------------------------------------------------------------

def test_scan_file_clean_document(client):
    """Verify clean text and PDF files pass inspection as Clean."""
    content = b"%PDF-1.4\n1 0 obj\n<< /Title (Annual Report) >>\nendobj\ntrailer<<>>%%EOF"
    data = {"file": (io.BytesIO(content), "sample_report.pdf")}
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "Clean"
    assert result["risk_score"] < 35
    assert len(result["sha256"]) == 64
    assert result["detected_type"] == "PDF Document"


def test_scan_file_disguised_executable(client):
    """
    Verify spoofed extension (Windows PE executable b'MZ' disguised as .pdf)
    is caught and marked as Malicious.
    """
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 200
    data = {"file": (io.BytesIO(fake_pdf), "invoice_update.pdf")}
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 80
    assert "Disguised" in result["threat_category"]


def test_scan_file_eicar_test_signature(client):
    """Verify standard benign EICAR anti-malware test signature is identified."""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    data = {"file": (io.BytesIO(eicar_bytes), "eicar.com")}
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "Malicious"
    assert "EICAR" in result["threat_category"]
    assert result["risk_score"] >= 90


def test_scan_file_safe_zip_inspection(client):
    """Verify ZIP archive is safely inspected in memory without disk extraction."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("notes.txt", "Project meeting notes")
        zf.writestr("image.png", b"\x89PNG\r\n\x1a\nfakeimage")
    zip_buffer.seek(0)

    data = {"file": (zip_buffer, "archive_docs.zip")}
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "Clean"
    assert result["archive_details"] is not None
    assert result["archive_details"]["entry_count"] == 2
    assert "notes.txt" in result["archive_details"]["contained_files"]


def test_scan_file_hidden_executable_in_zip(client):
    """Verify ZIP containing suspicious .exe payload is flagged."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("setup_payload.exe", b"MZ\x00\x00")
    zip_buffer.seek(0)

    data = {"file": (zip_buffer, "installer_bundle.zip")}
    res = client.post("/api/scan/file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] in ("Suspicious", "Malicious")
    assert "Executable" in result["threat_category"]


# ---------------------------------------------------------------------------
# 4. Scam Message and Payment-Link Analyzer Tests
# ---------------------------------------------------------------------------

def test_scan_message_bank_suspension(client):
    """Verify bank suspension fraud message is detected with high risk score."""
    msg = (
        "URGENT: Your account has been suspended due to pending KYC verification. "
        "Immediate action is required within 24 hours. Click to verify your account: "
        "http://hdfc-bank-kyc-verify.xyz/login"
    )
    res = client.post("/api/scan/message", json={"message": msg})
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "High Risk Scam"
    assert result["risk_score"] >= 65
    assert len(result["safe_actions"]) > 0


def test_scan_message_otp_lure(client):
    """Verify OTP and UPI PIN harvesting attempt is flagged."""
    msg = "Congratulations! You won cash prize. Enter your UPI PIN and share 6-digit OTP to receive money immediately."
    res = client.post("/api/scan/message", json={"message": msg})
    assert res.status_code == 200
    result = res.get_json()
    assert result["risk_score"] >= 65
    assert any("otp" in str(ind).lower() or "credential" in str(ind).lower() for ind in result["indicators"])


def test_scan_message_clean(client):
    """Verify ordinary friendly text returns Clean / Low Risk."""
    msg = "Hey Alex, are we still meeting for lunch at 12:30 PM today near the park?"
    res = client.post("/api/scan/message", json={"message": msg})
    assert res.status_code == 200
    result = res.get_json()
    assert result["verdict"] == "Low Risk / Clean"
    assert result["risk_score"] < 35


# ---------------------------------------------------------------------------
# 5. Unified Scan History & False-Positive Reporting Tests
# ---------------------------------------------------------------------------

def test_unified_scan_history_and_fp(client):
    """Verify scan history records all vectors and supports false-positive reports."""
    # Run a URL scan and a message scan to populate history
    client.post("/api/scan/url", json={"url": "https://github.com", "with_network": False})
    client.post("/api/scan/message", json={"message": "Clean test notification"})

    # Fetch history
    res = client.get("/api/scan/history")
    assert res.status_code == 200
    history = res.get_json()
    assert isinstance(history, list)
    assert len(history) >= 2

    # Verify history entry structure
    first = history[0]
    assert "id" in first
    assert "type" in first
    assert "verdict" in first
    assert "risk_score" in first

    # Report false positive
    fp_res = client.post("/api/security/false-positive", json={
        "scan_id": first["id"],
        "feedback": "This was an internal testing URL.",
        "user_verdict": "Safe"
    })
    assert fp_res.status_code == 200
    assert fp_res.get_json()["status"] == "recorded"
