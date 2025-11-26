from utils.url_analyzer import analyze_url
from utils.deepfake_check import check_deepfake


def test_analyze_url_safe():
    r = analyze_url("https://www.example.com")
    assert isinstance(r, dict)
    assert r["is_valid_format"] is True


def test_analyze_url_suspicious():
    r = analyze_url("http://192.168.0.1/login@phish.example")
    assert isinstance(r, dict)
    assert r["suspicious_score"] >= 1


def test_deepfake_placeholder(tmp_path):
    fake_vid = tmp_path / "small.mp4"
    fake_vid.write_bytes(b"\x00" * 1000)  # tiny fake file
    r = check_deepfake(str(fake_vid))
    assert isinstance(r, dict)
    assert "result" in r
