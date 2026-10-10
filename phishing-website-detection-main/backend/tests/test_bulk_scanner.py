"""
Bulk URL Scanner Tests (JSON, CSV Upload, TXT Upload, Limits, Error Handling).
"""

from __future__ import annotations

import io
import pytest


def test_bulk_scan_json_success(client, mock_network):
    """Test POST /bulk-scan with valid JSON payload."""
    urls = ["https://google.com", "https://github.com", "https://wikipedia.org"]
    res = client.post("/bulk-scan", json={"urls": urls})
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 3

    for item in data:
        assert "url" in item
        assert "prediction" in item
        assert "risk_score" in item
        assert 0 <= item["risk_score"] <= 100


def test_bulk_scan_csv_upload_with_header(client, mock_network):
    """Test POST /bulk-scan with a CSV file upload containing a header row."""
    csv_content = b"url,category\ngoogle.com,search\ngithub.com,developer\nwikipedia.org,reference\n"
    data = {
        "file": (io.BytesIO(csv_content), "test_urls.csv"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    results = res.get_json()
    assert isinstance(results, list)
    assert len(results) == 3
    found_urls = [r["url"] for r in results]
    assert any("google.com" in u for u in found_urls)
    assert any("github.com" in u for u in found_urls)
    assert any("wikipedia.org" in u for u in found_urls)


def test_bulk_scan_csv_upload_without_header(client, mock_network):
    """Test POST /bulk-scan with a raw CSV file without a header."""
    csv_content = b"google.com\ngithub.com\n"
    data = {
        "file": (io.BytesIO(csv_content), "plain.csv"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    results = res.get_json()
    assert len(results) == 2


def test_bulk_scan_txt_upload(client, mock_network):
    """Test POST /bulk-scan with a TXT file (one URL per line, comments, empty lines)."""
    txt_content = b"""# Target Scan List
https://google.com

# Another link
https://github.com
https://wikipedia.org

"""
    data = {
        "file": (io.BytesIO(txt_content), "urls.txt"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    results = res.get_json()
    assert len(results) == 3


def test_bulk_scan_empty_file(client):
    """Test POST /bulk-scan with a 0-byte file upload."""
    data = {
        "file": (io.BytesIO(b""), "empty.csv"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "empty" in res.get_json()["message"].lower()


def test_bulk_scan_unsupported_file_extension(client):
    """Test POST /bulk-scan with unsupported file extension (.exe, .pdf, .json)."""
    data = {
        "file": (io.BytesIO(b"some content"), "payload.exe"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "unsupported" in res.get_json()["message"].lower()


def test_bulk_scan_deduplication(client, mock_network):
    """Test that duplicate URLs in upload are deduplicated."""
    txt_content = b"https://google.com\nhttps://google.com\nhttps://google.com\nhttps://github.com\n"
    data = {
        "file": (io.BytesIO(txt_content), "dup.txt"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    results = res.get_json()
    # 3 duplicates of google + 1 github = 2 unique URLs
    assert len(results) == 2


def test_bulk_scan_oversized_file(client):
    """Test that file exceeding 2MB limit returns HTTP 413."""
    oversized = b"a" * (2 * 1024 * 1024 + 500)
    data = {
        "file": (io.BytesIO(oversized), "huge.txt"),
    }
    res = client.post("/bulk-scan", data=data, content_type="multipart/form-data")
    assert res.status_code == 413
