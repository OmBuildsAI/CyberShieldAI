from typing import List
from PIL import Image
try:
    from pyzbar.pyzbar import decode
except Exception:
    decode = None
try:
    import validators
except Exception:
    validators = None
try:
    import qrcode
except Exception:
    qrcode = None
try:
    import cv2
except Exception:
    cv2 = None
try:
    import requests
except Exception:
    requests = None
import io
import os
import tempfile
import re
import numpy as np
import time
import datetime

# Simple in-memory rate limiter timestamps for VirusTotal: list of epoch seconds
_vt_request_timestamps: List[float] = []
# max requests per minute
_VT_RATE_LIMIT = 4


def scan_qr_from_pil(image: Image.Image) -> List[str]:
    """Decode QR codes from a PIL Image. Returns a list of decoded strings."""
    if not isinstance(image, Image.Image):
        raise ValueError("Expected a PIL.Image.Image object")

    # Prefer pyzbar when available
    if decode is not None:
        decoded = decode(image)
    else:
        # fallback to OpenCV QR detector
        if cv2 is None:
            raise ImportError("Neither pyzbar nor OpenCV are available for QR decoding.")
        # convert PIL image to OpenCV
        arr = np.array(image.convert("RGB"))[:, :, ::-1]
        detector = cv2.QRCodeDetector()
        decoded = []
        # try multi decode if available
        try:
            ret, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(arr)
            if ret:
                for d in decoded_info:
                    if d:
                        # create object-like with .data attribute for compatibility
                        decoded.append(type("D", (), {"data": d.encode('utf-8')})())
        except Exception:
            # fallback to single decode
            try:
                data, pts, _ = detector.detectAndDecode(arr)
                if data:
                    decoded.append(type("D", (), {"data": data.encode('utf-8')})())
            except Exception as e:
                raise
    results = []
    for d in decoded:
        try:
            text = d.data.decode('utf-8')
        except Exception:
            text = d.data
        results.append(text)
    return results


def image_to_cv2(image: Image.Image):
    """Helper: convert PIL Image to OpenCV BGR ndarray"""
    return np.array(image.convert("RGB"))[:, :, ::-1]


def scan_qr_code(image_file) -> dict:
    """Scan a Streamlit-uploaded file-like object for QR codes.

    Returns a dict:
      - qr_found: bool
      - data: str or list
      - is_url: bool
      - qr_count: int
      - message: str
    """
    result = {
        "qr_found": False,
        "data": None,
        "is_url": False,
        "qr_count": 0,
        "message": ""
    }

    # size check
    try:
        size = None
        if hasattr(image_file, "getbuffer"):
            size = len(image_file.getbuffer())
        elif hasattr(image_file, "size"):
            size = image_file.size
        if size is not None and size > 5 * 1024 * 1024:  # 5 MB
            result["message"] = "File too large (over 5MB)."
            return result
    except Exception:
        pass

    # open image
    try:
        if hasattr(image_file, "read") and not isinstance(image_file, (bytes, bytearray)):
            # Streamlit's UploadedFile supports read/getbuffer
            img = Image.open(image_file).convert("RGB")
        else:
            img = Image.open(io.BytesIO(image_file)).convert("RGB")
    except Exception as e:
        result["message"] = f"Invalid image or cannot open: {e}"
        return result

    # decode
    try:
        decoded = scan_qr_from_pil(img)
    except ImportError as e:
        result["message"] = str(e)
        return result
    except Exception:
        # try OpenCV detector as fallback
        if cv2 is not None:
            try:
                detector = cv2.QRCodeDetector()
                data_list = []
                # try multi-decode
                try:
                    ok, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(image_to_cv2(img))
                    if ok:
                        data_list = [d for d in decoded_info if d]
                except Exception:
                    # single decode
                    data, pts, _ = detector.detectAndDecode(image_to_cv2(img))
                    if data:
                        data_list = [data]

                decoded = data_list
            except Exception as e:
                result["message"] = f"Decoding failed: {e}"
                return result
        else:
            result["message"] = "QR decoding failed and no fallback available."
            return result

    # normalize decoded to list of strings
    if isinstance(decoded, str):
        decoded = [decoded]

    decoded = [d for d in decoded if d]
    result["qr_count"] = len(decoded)
    if not decoded:
        result["message"] = "No QR code found"
        return result

    if len(decoded) > 1:
        result["message"] = "Multiple QR codes found; returning first result"
    else:
        result["message"] = "QR code found"

    data0 = decoded[0]
    result["qr_found"] = True
    result["data"] = data0

    # is_url check
    is_url = False
    try:
        if validators is not None:
            is_url = bool(validators.url(data0))
        else:
            is_url = bool(re.match(r"^https?://", data0))
    except Exception:
        is_url = False

    result["is_url"] = is_url
    # If it's a URL, attempt VirusTotal lookup (if API key present)
    vt_report = None
    try:
        if is_url:
            # determine VT API key from env
            vt_api_key = os.getenv('VIRUSTOTAL_API_KEY') or os.getenv('VT_API_KEY')
            if vt_api_key and requests is not None:
                try:
                    vt_report = _vt_analyze_url(data0, vt_api_key)
                except Exception as e:
                    vt_report = {"error": f"VirusTotal lookup failed: {e}"}
            else:
                vt_report = {"error": "VirusTotal API key not configured or requests missing"}
    except Exception:
        vt_report = {"error": "VirusTotal analysis exception"}

    if vt_report is not None:
        result["vt_report"] = vt_report

    return result


def generate_test_qr(url: str, filename: str = None) -> str:
    """Generate a QR PNG for `url`. Returns path to saved PNG file.

    If `filename` is None, a temporary file is created and its path returned.
    """
    if qrcode is None:
        raise ImportError("qrcode library is not installed. Install with `pip install qrcode[pil]`.")

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Empty URL provided to generate_test_qr")

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    if filename:
        path = filename if filename.lower().endswith('.png') else filename + '.png'
        img.save(path)
        return os.path.abspath(path)
    else:
        fd, path = tempfile.mkstemp(suffix='.png')
        os.close(fd)
        img.save(path)
        return path


def _vt_rate_limit_check() -> None:
    """Raise RuntimeError if the rate limit (4 req/min) would be exceeded."""
    global _vt_request_timestamps
    now = time.time()
    # remove older than 60 seconds
    _vt_request_timestamps = [t for t in _vt_request_timestamps if now - t < 60]
    if len(_vt_request_timestamps) >= _VT_RATE_LIMIT:
        raise RuntimeError("VirusTotal rate limit exceeded (4 requests per minute)")


def _vt_analyze_url(url: str, api_key: str, timeout: float = 10.0) -> dict:
    """Analyze a URL with VirusTotal v3 API. Returns a structured report.

    If the API or requests are unavailable, raises RuntimeError.
    """
    if requests is None:
        raise RuntimeError("`requests` is required for VirusTotal integration")

    # Enforce rate limit
    _vt_rate_limit_check()

    headers = {"x-apikey": api_key}

    # Submit URL for analysis
    submit_url = "https://www.virustotal.com/api/v3/urls"
    resp = requests.post(submit_url, data={"url": url}, headers=headers, timeout=timeout)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"VirusTotal submit failed: {resp.status_code} {resp.text}")

    try:
        resp_json = resp.json()
    except Exception as e:
        raise RuntimeError(f"Invalid JSON from VirusTotal submit: {e}")

    analysis_id = resp_json.get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError("VirusTotal did not return analysis id")

    # record timestamp for rate limiting
    _vt_request_timestamps.append(time.time())

    # Poll analysis endpoint until complete (or timeout)
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    deadline = time.time() + timeout
    analysis_json = None
    while time.time() < deadline:
        r2 = requests.get(analysis_url, headers=headers, timeout=timeout)
        if r2.status_code != 200:
            # Accept transient non-200 while polling; break if persistent
            try:
                time.sleep(1)
            except Exception:
                pass
            time.sleep(0.5)
            continue
        try:
            analysis_json = r2.json()
        except Exception:
            time.sleep(0.5)
            continue

        status = analysis_json.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(0.5)

    if analysis_json is None:
        raise RuntimeError("VirusTotal analysis fetch failed or timed out")

    # Parse stats
    attrs = analysis_json.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {}) or {}

    positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) if stats else 0
    detection_ratio = f"{positives}/{total}" if total else "0/0"

    # confidence heuristic: percent malicious among total signals
    confidence = int((positives / total) * 100) if total else 0

    # scan date — try known fields
    scan_ts = attrs.get("date") or attrs.get("end_time") or attrs.get("last_modification_date")
    scan_date = None
    if isinstance(scan_ts, (int, float)):
        try:
            scan_date = datetime.datetime.utcfromtimestamp(int(scan_ts)).isoformat() + "Z"
        except Exception:
            scan_date = None
    # fallback to header date
    if not scan_date:
        scan_date = r2.headers.get("Date") if 'r2' in locals() and hasattr(r2, 'headers') else None

    # safety status
    if positives > 0:
        safety_status = "Dangerous"
    elif int(stats.get("suspicious", 0)) > 0:
        safety_status = "Suspicious"
    else:
        safety_status = "Safe"

    report = {
        "detection_ratio": detection_ratio,
        "confidence": confidence,
        "scan_date": scan_date,
        "safety_status": safety_status,
        "raw_stats": stats,
        "analysis_id": analysis_id,
        "source": "VirusTotal"
    }
    return report
