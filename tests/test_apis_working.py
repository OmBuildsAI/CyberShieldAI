import os
import time
import io
from PIL import Image

import pytest

import requests

import utils.url_analyzer as ua
import utils.qr_scanner as qs
import utils.deepfake_check as df


def _print_status(msg):
    print(msg)


def test_google_safe_browsing_live():
    """Verify Google Safe Browsing API responds for sample URLs.

    Skips if no API key is configured in the environment.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GSB_API_KEY")
    if not api_key:
        pytest.skip("Google Safe Browsing API key not configured; skipping live test")

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "cybershieldai-test", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "https://www.google.com"}]
        }
    }

    start = time.perf_counter()
    resp = requests.post(endpoint, json=payload, timeout=15)
    elapsed = time.perf_counter() - start

    _print_status(f"Google SB: HTTP {resp.status_code} in {elapsed:.2f}s")
    try:
        jr = resp.json()
    except Exception as e:
        jr = {"error": f"Invalid JSON: {e}", "text": resp.text}

    _print_status(f"Google SB response: {jr}")
    assert resp.status_code == 200, f"Unexpected status {resp.status_code}"


def test_virustotal_live_on_url():
    """Submit a benign URL to VirusTotal and poll for analysis.

    Skips if VirusTotal API key is not set.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if not vt_key:
        pytest.skip("VirusTotal API key not configured; skipping live test")

    # use a stable benign URL
    test_url = "https://www.google.com"

    start = time.perf_counter()
    try:
        report = qs._vt_analyze_url(test_url, vt_key, timeout=30.0)
    except Exception as e:
        pytest.fail(f"VirusTotal analysis failed: {e}")
    elapsed = time.perf_counter() - start

    _print_status(f"VirusTotal: analysis completed in {elapsed:.2f}s")
    _print_status(f"VirusTotal report: {report}")

    assert isinstance(report, dict)
    assert report.get("source") == "VirusTotal"
    assert "analysis_id" in report


def test_huggingface_deepfake_live():
    """Run `detect_deepfake` on a small sample image and print the HF response.

    Skips if Hugging Face token is not configured.
    """
    hf_token = os.getenv("HUGGINGFACE_API_TOKEN") or os.getenv("HF_API_TOKEN") or os.getenv("HUGGINGFACE_API_KEY")
    if not hf_token:
        pytest.skip("Hugging Face token not configured; skipping live test")

    # Create a tiny white PNG in-memory
    img = Image.new("RGB", (128, 128), color=(255, 255, 255))
    b = io.BytesIO()
    img.save(b, format="PNG")
    b.seek(0)

    start = time.perf_counter()
    res = df.detect_deepfake(b)
    elapsed = time.perf_counter() - start

    _print_status(f"Hugging Face detection finished in {elapsed:.2f}s")
    _print_status(f"Deepfake detection result: {res}")

    assert isinstance(res, dict)
    assert "source" in res
