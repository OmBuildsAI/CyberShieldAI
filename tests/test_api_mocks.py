import os
import io
import json
from PIL import Image

import pytest

import utils.url_analyzer as ua
import utils.qr_scanner as qs
import utils.deepfake_check as df


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


def test_analyze_url_with_gsb_mock(monkeypatch):
    # Mock Google Safe Browsing response with a MALWARE match
    def fake_post(*args, **kwargs):
        return DummyResponse(json_data={"matches": [{"threatType": "MALWARE"}]})

    # Ensure requests exists on module and patch it
    monkeypatch.setattr(ua, "requests", ua.requests)
    monkeypatch.setattr(ua.requests, "post", fake_post)

    # Provide fake API key
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-key")

    res = ua.analyze_url("http://example.com/malicious")
    assert isinstance(res, dict)
    assert res.get("source") in ("Google Safe Browsing API", "heuristic")
    # Because we returned MALWARE, risk_score should be > 0 and status Dangerous or Suspicious
    assert res.get("risk_score", 0) >= 1


def test_scan_qr_code_with_vt_mock(monkeypatch, tmp_path):
    # Create a test QR image containing a URL (we'll mock the decoder to avoid qrcode dependency)
    url = "http://example.com/test"

    # Monkeypatch decoder so we don't require the `qrcode` package or real decoding
    monkeypatch.setattr(qs, "scan_qr_from_pil", lambda img: [url])

    # Create a simple in-memory PNG to pass as file-like object
    from PIL import Image
    import io
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    b = io.BytesIO()
    img.save(b, format="PNG")
    b.seek(0)

    # Monkeypatch vt analyzer to avoid real network
    def fake_vt_analyze(u, key, timeout=10.0):
        return {
            "detection_ratio": "1/70",
            "confidence": 2,
            "scan_date": "2025-01-01T00:00:00Z",
            "safety_status": "Dangerous",
            "raw_stats": {"malicious": 1, "suspicious": 0, "undetected": 69},
            "analysis_id": "fake-id",
            "source": "VirusTotal"
        }

    monkeypatch.setattr(qs, "_vt_analyze_url", fake_vt_analyze)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt-key")

    # Open file-like and call scan_qr_code
    result = qs.scan_qr_code(b)

    assert result.get("qr_found") is True
    assert result.get("data") == url
    assert "vt_report" in result
    assert result["vt_report"]["analysis_id"] == "fake-id"


def test_detect_deepfake_with_hf_mock(monkeypatch):
    # Create a small dummy image in-memory
    img = Image.new("RGB", (64, 64), color=(255, 255, 255))
    b = io.BytesIO()
    img.save(b, format="PNG")
    b.seek(0)

    # Fake HF response: label 'REAL' with high score
    def fake_post(url, headers=None, data=None, timeout=10):
        return DummyResponse(json_data=[{"label": "REAL", "score": 0.92}], status_code=200)

    monkeypatch.setenv("HUGGINGFACE_API_TOKEN", "fake-hf-token")
    # patch requests at module level
    monkeypatch.setattr(df, "requests", df.requests)
    monkeypatch.setattr(df.requests, "post", fake_post)

    res = df.detect_deepfake(b)
    assert isinstance(res, dict)
    # If HF used, source should be Hugging Face AI
    assert res.get("source") in ("Hugging Face AI", "heuristic")
