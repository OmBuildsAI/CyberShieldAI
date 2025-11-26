import os
import re
import json
from typing import Dict, Any

try:
    import requests
except Exception:  # requests may not be available in minimal test envs
    requests = None

try:
    import validators
except Exception:
    validators = None

try:
    # prefer dotenv if available to load `.env`
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # if python-dotenv is not installed, rely on the environment already being set
    pass


def _is_ip_in_hostname(url: str) -> bool:
    # Quick check whether the netloc is an IP address
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc
        # remove port
        host = netloc.split(":")[0]
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
    except Exception:
        return False


def _heuristic_assess(url: str) -> Dict[str, Any]:
    """Return a heuristic assessment (fallback) similar to the previous analyze_url.

    This returns a dict with keys used below when the Google API is unavailable.
    """
    result = {
        "status": "Safe",
        "message": "No strong suspicious signals found",
        "risk_score": 0,
        "risk_factors": [],
        "confidence": 40,
        "source": "heuristic"
    }

    if not isinstance(url, str) or not url.strip():
        result.update({"status": "Invalid", "message": "Empty or invalid input", "confidence": 0})
        return result

    url = url.strip()
    score = 0
    notes = []

    # simple validations
    if validators is not None:
        try:
            valid = bool(validators.url(url))
        except Exception:
            valid = False
    else:
        valid = bool(re.match(r"^https?://[A-Za-z0-9\-\.]+", url))

    if not valid:
        result.update({"status": "Invalid", "message": "URL failed validation", "confidence": 5})
        return result

    if len(url) > 200:
        score += 2
        notes.append("Very long URL")
    elif len(url) > 100:
        score += 1
        notes.append("Long URL")

    if "@" in url:
        score += 2
        notes.append("Contains '@' symbol")

    if _is_ip_in_hostname(url):
        score += 3
        notes.append("Host uses IP address")

    if not url.lower().startswith("https://"):
        score += 1
        notes.append("No HTTPS scheme")

    if url.count(".") > 6:
        score += 2
        notes.append("Many dots in URL")
    elif url.count(".") > 3:
        score += 1
        notes.append("Multiple dots in URL")

    keywords = ["login", "verify", "account", "secure", "banking", "update"]
    found_keywords = [k for k in keywords if k in url.lower()]
    if found_keywords:
        score += min(3, len(found_keywords))
        notes.append(f"Suspicious keywords: {', '.join(found_keywords)}")

    if any(sd in url.lower() for sd in ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "buff.ly", "ow.ly"]):
        score += 3
        notes.append("Shortener domain detected")

    # TLD heuristics
    suspicious_tlds = ['.zip', '.review', '.country', '.kim', '.gq']
    for tld in suspicious_tlds:
        if url.endswith(tld) or (tld in url and url.find(tld) > url.rfind('/')):
            score += 1
            notes.append(f"Suspicious TLD: {tld}")

    # Map raw score to the requested 0-10 scale (cap)
    risk_score = max(0, min(10, score))

    status = "Safe"
    if risk_score >= 6:
        status = "Dangerous"
    elif risk_score >= 3:
        status = "Suspicious"

    confidence = 60 if status == "Safe" else (50 if status == "Suspicious" else 40)

    result.update({
        "status": status,
        "message": "; ".join(notes) if notes else "No strong suspicious signals found",
        "risk_score": risk_score,
        "risk_factors": notes,
        "confidence": confidence,
        "source": "heuristic"
    })
    return result


def _call_google_safe_browsing(url: str, api_key: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Call Google Safe Browsing API v4 threatMatches:find and return parsed result.

    If `requests` is not available this raises RuntimeError.
    """
    if requests is None:
        raise RuntimeError("`requests` library is required for Google Safe Browsing API calls")

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "cybershieldai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    resp = requests.post(endpoint, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def analyze_url(url: str) -> Dict[str, Any]:
    """Assess a URL using Google Safe Browsing when available, else fallback to heuristics.

    Returns:
    {
        'status': 'Safe'|'Suspicious'|'Dangerous'|'Invalid',
        'message': 'Detailed explanation',
        'risk_score': int(0-10),
        'risk_factors': [ ... ],
        'confidence': int(0-100),
        'source': 'Google Safe Browsing API'|'heuristic'
    }
    """
    # Basic input guard
    if not isinstance(url, str) or not url.strip():
        return {"status": "Invalid", "message": "Empty input", "risk_score": 0, "risk_factors": [], "confidence": 0, "source": "heuristic"}

    url = url.strip()

    # Determine API key from env (check multiple common names)
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GSB_API_KEY")

    # Determine legacy `is_valid_format` using validators or regex
    if validators is not None:
        try:
            is_valid_format = bool(validators.url(url))
        except Exception:
            is_valid_format = False
    else:
        is_valid_format = bool(re.match(r"^https?://[A-Za-z0-9\-\.]+", url))

    # If there's an API key and requests available, try the Google API
    if api_key:
        try:
            data = _call_google_safe_browsing(url, api_key)
            matches = data.get("matches") if isinstance(data, dict) else None

            if not matches:
                # No matches -> safe per Google
                out = {"status": "Safe", "message": "No threats found by Google Safe Browsing.", "risk_score": 0, "risk_factors": [], "confidence": 95, "source": "Google Safe Browsing API"}
                # Maintain legacy keys for backward compatibility
                out.update({"is_valid_format": is_valid_format, "suspicious_score": 0, "notes": [out["message"]], "http_status": None})
                return out

            # Parse matches to produce risk factors and score
            risk_factors = []
            score = 0

            severity_map = {
                "MALWARE": 9,
                "SOCIAL_ENGINEERING": 7,
                "UNWANTED_SOFTWARE": 6,
                "POTENTIALLY_HARMFUL_APPLICATION": 5
            }

            for m in matches:
                t = m.get("threatType") or m.get("threat", {}).get("threatType")
                t = t or m.get("threatType")
                if isinstance(t, str):
                    risk_factors.append(str(t))
                    score += severity_map.get(t, 5)

            # normalize/cap to 0-10
            risk_score = max(0, min(10, score // 1))

            # determine status
            status = "Suspicious"
            if risk_score >= 7:
                status = "Dangerous"
            elif risk_score >= 3:
                status = "Suspicious"
            else:
                status = "Safe"

            confidence = 90 if status == "Dangerous" else (80 if status == "Suspicious" else 75)

            message = f"Google Safe Browsing reported threats: {', '.join(risk_factors)}"

            out = {
                "status": status,
                "message": message,
                "risk_score": int(risk_score),
                "risk_factors": risk_factors,
                "confidence": int(confidence),
                "source": "Google Safe Browsing API"
            }
            # Legacy compatibility keys
            legacy_notes = [message]
            out.update({"is_valid_format": is_valid_format, "suspicious_score": int(risk_score), "notes": legacy_notes, "http_status": None})
            return out

        except requests.exceptions.Timeout:
            # Timeout: fall back to heuristics but surface the error
            fallback = _heuristic_assess(url)
            fallback["message"] = "Google Safe Browsing API timeout; heuristic fallback used. " + fallback.get("message", "")
            fallback["source"] = "heuristic"
            # add legacy keys
            fallback.update({"is_valid_format": is_valid_format, "suspicious_score": int(fallback.get("risk_score", 0)), "notes": [fallback.get("message", "")], "http_status": None})
            return fallback
        except Exception as e:
            # Any other API error: include message and fallback
            fallback = _heuristic_assess(url)
            fallback["message"] = f"Google Safe Browsing API error: {e}; heuristic fallback used. " + fallback.get("message", "")
            fallback["source"] = "heuristic"
            # add legacy keys
            fallback.update({"is_valid_format": is_valid_format, "suspicious_score": int(fallback.get("risk_score", 0)), "notes": [fallback.get("message", "")], "http_status": None})
            return fallback

    # No API key or requests not available: use heuristic fallback
    fallback = _heuristic_assess(url)
    fallback.update({"is_valid_format": is_valid_format, "suspicious_score": int(fallback.get("risk_score", 0)), "notes": [fallback.get("message", "")], "http_status": None})
    return fallback


def check_phishing(url: str) -> Dict[str, Any]:
    """Backward-compatible wrapper that returns the same structure as analyze_url.

    This keeps the older `check_phishing` API but simply calls `analyze_url`.
    """
    return analyze_url(url)

