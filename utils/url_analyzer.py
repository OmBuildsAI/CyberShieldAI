import re
try:
    import requests
except Exception:  # requests may not be available in minimal test envs
    requests = None

try:
    import validators
except Exception:
    validators = None

def _is_ip_in_hostname(url):
    # Quick check whether the netloc is an IP address
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc
        # remove port
        host = netloc.split(":")[0]
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
    except Exception:
        return False


def analyze_url(url: str) -> dict:
    """Perform lightweight URL safety heuristics and a status check.

    Returns a dict with simple signals. This is not a replacement for
    a real URL-scanning service — just a starting point.
    """
    result = {
        "url": url,
        "is_valid_format": False,
        "http_status": None,
        "suspicious_score": 0,
        "notes": []
    }

    if not isinstance(url, str) or not url.strip():
        result["notes"].append("Empty or invalid input")
        return result

    url = url.strip()
    # Use validators if available, otherwise fall back to a basic check
    if validators is not None:
        try:
            result["is_valid_format"] = bool(validators.url(url))
        except Exception:
            result["is_valid_format"] = False
    else:
        # Simple regex-based URL check (not perfect, but avoids hard dependency)
        result["is_valid_format"] = bool(re.match(r"^https?://[A-Za-z0-9\-\.]+", url))

    # Basic heuristics
    score = 0
    if len(url) > 100:
        score += 1
        result["notes"].append("Very long URL")
    if "@" in url:
        score += 2
        result["notes"].append("Contains @ symbol (often used in phishing)")
    if url.count("-") > 5:
        score += 1
        result["notes"].append("Many hyphens in URL")
    if _is_ip_in_hostname(url):
        score += 2
        result["notes"].append("Host uses IP address instead of domain")

    # Try to fetch HEAD to get status code
    # Try to fetch HEAD to get status code (only if requests is available)
    if requests is not None:
        try:
            resp = requests.head(url, allow_redirects=True, timeout=5)
            result["http_status"] = resp.status_code
            if resp.status_code >= 400:
                score += 1
                result["notes"].append(f"HTTP status {resp.status_code}")
        except Exception as e:
            result["notes"].append(f"HTTP request failed: {e}")
    else:
        result["notes"].append("`requests` library not available; skipped HTTP check")

    # very naive domain check for suspicious TLDs
    suspicious_tlds = ['.zip', '.review', '.country', '.kim', '.gq']
    for tld in suspicious_tlds:
        if url.endswith(tld) or (tld in url and url.find(tld) > url.rfind('/')):
            score += 1
            result["notes"].append(f"Suspicious TLD: {tld}")

    result["suspicious_score"] = score
    if score >= 4:
        result["notes"].append("Highly suspicious — use caution")
    elif score >= 2:
        result["notes"].append("Suspicious signals present")
    else:
        result["notes"].append("No strong suspicious signals found")

    return result


def check_phishing(url: str) -> dict:
    """Rule-based phishing check returning detailed features and risk score.

    Returns a dict with keys:
    - status: "Safe" | "Suspicious" | "Dangerous" | "Invalid"
    - risk_score: int
    - risk_factors: list[str]
    - features: dict
    - message: str
    """
    out = {
        "status": "Invalid",
        "risk_score": 0,
        "risk_factors": [],
        "features": {},
        "message": ""
    }

    try:
        if not isinstance(url, str) or not url.strip():
            out["message"] = "Empty input"
            return out

        url = url.strip()

        # Validate URL using validators if available
        is_valid = None
        if validators is not None:
            try:
                is_valid = bool(validators.url(url))
            except Exception:
                is_valid = False
        else:
            # basic heuristic if validators not installed
            is_valid = bool(re.match(r"^https?://[A-Za-z0-9\-\.]+", url))

        if not is_valid:
            out["status"] = "Invalid"
            out["message"] = "URL failed validation"
            return out

        # parse components
        from urllib.parse import urlparse
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        # remove credentials if present
        if "@" in netloc:
            host = netloc.split("@")[-1]
        else:
            host = netloc
        host = host.split(":")[0]

        path_and_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

        features = {}
        features["url_length"] = len(url)
        features["has_at_symbol"] = "@" in url
        features["has_ip"] = _is_ip_in_hostname(url)
        features["has_https"] = url.lower().startswith("https://")
        features["num_dots"] = url.count(".")
        keywords = ["login", "verify", "account", "secure", "banking", "update"]
        found_keywords = [k for k in keywords if k in url.lower()]
        features["suspicious_keywords"] = found_keywords
        short_domain_indicators = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "buff.ly", "ow.ly"]
        features["is_short_url"] = any(sd in host.lower() for sd in short_domain_indicators)
        features["num_hyphens"] = url.count("-")
        features["domain_length"] = len(host)

        # scoring
        score = 0
        risk_factors = []

        # url length
        if features["url_length"] > 200:
            score += 2
            risk_factors.append("Very long URL")
        elif features["url_length"] > 100:
            score += 1
            risk_factors.append("Long URL")

        # @ symbol
        if features["has_at_symbol"]:
            score += 2
            risk_factors.append("Contains '@' symbol")

        # IP in hostname
        if features["has_ip"]:
            score += 3
            risk_factors.append("Host uses IP address")

        # HTTPS presence (absence is slightly risky)
        if not features["has_https"]:
            score += 1
            risk_factors.append("No HTTPS scheme")

        # number of dots (many subdomains or trickery)
        if features["num_dots"] > 6:
            score += 2
            risk_factors.append("Many dots in URL")
        elif features["num_dots"] > 3:
            score += 1
            risk_factors.append("Multiple dots in URL")

        # suspicious keywords
        if features["suspicious_keywords"]:
            # weight by count but cap
            kw_points = min(3, len(features["suspicious_keywords"]))
            score += 2 if kw_points >= 1 else 0
            risk_factors.append(f"Suspicious keywords: {', '.join(features['suspicious_keywords'])}")

        # short URL
        if features["is_short_url"]:
            score += 3
            risk_factors.append("Shortener domain detected")

        # hyphens
        if features["num_hyphens"] > 6:
            score += 2
            risk_factors.append("Many hyphens in URL")
        elif features["num_hyphens"] > 3:
            score += 1
            risk_factors.append("Several hyphens in URL")

        # domain length extreme
        if features["domain_length"] > 25:
            score += 1
            risk_factors.append("Very long domain name")

        # finalize status
        status = "Safe"
        if score >= 6:
            status = "Dangerous"
        elif score >= 3:
            status = "Suspicious"

        out["status"] = status
        out["risk_score"] = score
        out["risk_factors"] = risk_factors
        out["features"] = features
        out["message"] = f"URL assessed as {status}. Follow up on the listed risk factors." if risk_factors else "No strong risk factors found."
        return out

    except Exception as e:
        out["status"] = "Invalid"
        out["message"] = f"Error during phishing check: {e}"
        return out
