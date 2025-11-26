try:
    import streamlit as st
except Exception:
    # Minimal fallback stub for environments without streamlit installed.
    # This implements only the attributes used by this file so linters/tests can run.
    from types import SimpleNamespace

    class _DummyCtx:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def header(self, *a, **k): pass
        def subheader(self, *a, **k): pass
        def write(self, *a, **k): pass
        def image(self, *a, **k): pass
        def success(self, *a, **k): pass
        def warning(self, *a, **k): pass
        def error(self, *a, **k): pass

    class _DummyStreamlit:
        def set_page_config(self, *a, **k): pass
        def title(self, *a, **k): pass
        def markdown(self, *a, **k): pass
        def tabs(self, labels):
            # return a list of context managers that can be used with `with`
            return [_DummyCtx() for _ in labels]
        def header(self, *a, **k): pass
        def text_input(self, *a, **k): return ""
        def button(self, *a, **k): return False
        def spinner(self, *a, **k):
            return _DummyCtx()
        def subheader(self, *a, **k): pass
        def write(self, *a, **k): pass
        def file_uploader(self, *a, **k): return None
        def image(self, *a, **k): pass
        def success(self, *a, **k): pass
        def warning(self, *a, **k): pass
        def error(self, *a, **k): pass

    st = _DummyStreamlit()

from PIL import Image
import tempfile
import os
import io
import datetime
import re

import numpy as np
try:
    import cv2
except Exception:
    cv2 = None

from utils.url_analyzer import analyze_url
from utils.qr_scanner import scan_qr_from_pil
from utils.deepfake_check import check_deepfake

st.set_page_config(page_title="CyberShield AI", layout="wide")

st.set_page_config(page_title="🛡️ CyberShield AI - Multi-Modal Threat Detector", page_icon="🛡️", layout="wide")

st.title("🛡️ CyberShield AI - Multi-Modal Threat Detector")
st.markdown("A small Streamlit prototype for URL analysis, QR scanning, and a placeholder deepfake check.")

# --- Sidebar ---
if "history" not in st.session_state:
    st.session_state.history = []

with st.sidebar:
    st.header("CyberShield AI")
    st.write("Multi-modal threat detector: URL phishing, QR decoding, and deepfake image checks.")
    st.markdown("**Features**\n- URL heuristic analysis\n- QR decoding + URL safety check\n- Deepfake image face detection (heuristic)\n")
    st.markdown("---")
    st.subheader("Scan History")
    if st.session_state.history:
        for item in reversed(st.session_state.history[-10:]):
            ts = item.get("time")
            ts_s = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime.datetime) else str(ts)
            st.write(f"- [{item['type'].upper()}] {item['input']} → {item['result']} ({ts_s})")
    else:
        st.write("No scans yet")

    st.markdown("---")
    # Simple statistics
    total = len(st.session_state.history)
    url_count = sum(1 for h in st.session_state.history if h.get("type") == "url")
    qr_count = sum(1 for h in st.session_state.history if h.get("type") == "qr")
    deep_count = sum(1 for h in st.session_state.history if h.get("type") == "deepfake")
    st.subheader("Statistics")
    st.write(f"Total scans: {total}")
    st.write(f"URL scans: {url_count}")
    st.write(f"QR scans: {qr_count}")
    st.write(f"Deepfake checks: {deep_count}")

tabs = st.tabs(["🔗 URL Phishing Detector", "📱 QR Code Scanner & Analyzer", "🎭 Deepfake Image Detector", "About"])

with tabs[0]:
    st.header("🔗 URL Phishing Detector")
    url = st.text_input("Enter a URL to analyze:", placeholder="https://example.com")
    analyze_clicked = st.button("Analyze URL")
    if analyze_clicked and url:
        with st.spinner("Analyzing URL..."):
            try:
                result = analyze_url(url)
            except Exception as e:
                st.error(f"URL analysis failed: {e}")
                result = None

        if result:
            score = int(result.get("suspicious_score", 0))
            if score >= 4:
                label = "Dangerous"
                color = "#dc2626"
            elif score >= 2:
                label = "Suspicious"
                color = "#f59e0b"
            else:
                label = "Likely Safe"
                color = "#16a34a"

            st.markdown(f"<div style='background:{color};padding:8px;border-radius:6px;color:#fff;font-weight:600'>{label}</div>", unsafe_allow_html=True)
            st.write("**Risk score:**", score)
            st.write("**Details:**")
            for note in result.get("notes", []):
                st.write(f"- {note}")

            # Save to history
            st.session_state.history.append({
                "type": "url",
                "input": url,
                "result": label,
                "score": score,
                "time": datetime.datetime.now()
            })

with tabs[1]:
    st.header("📱 QR Code Scanner & Analyzer")
    uploaded_file = st.file_uploader("Upload an image containing a QR code", type=["png", "jpg", "jpeg"] )
    scan_qr = st.button("Scan QR Code")
    if scan_qr:
        if uploaded_file is None:
            st.error("Please upload an image file first.")
        else:
            try:
                img = Image.open(uploaded_file).convert("RGB")
            except Exception as e:
                st.error(f"Unable to open image: {e}")
                img = None

            if img is not None:
                with st.spinner("Scanning for QR codes..."):
                    try:
                        decoded = scan_qr_from_pil(img)
                    except Exception as e:
                        st.error(f"QR scanning failed: {e}")
                        decoded = []

                st.image(img, caption="Uploaded image", use_column_width=True)
                if decoded:
                    st.success(f"Found {len(decoded)} QR code(s)")
                    for d in decoded:
                        st.write("- Data:", d)
                        # Check if data is URL
                        is_url = False
                        try:
                            import validators as _val
                            is_url = bool(_val.url(d))
                        except Exception:
                            is_url = bool(re.match(r"^https?://", str(d)))

                        st.write("  - Looks like URL:" , is_url)
                        if is_url:
                            with st.spinner("Analyzing extracted URL..."):
                                try:
                                    analysis = analyze_url(d)
                                except Exception as e:
                                    st.error(f"URL analysis failed: {e}")
                                    analysis = None

                            if analysis:
                                sc = int(analysis.get("suspicious_score", 0))
                                tag = ("Likely Safe" if sc < 2 else ("Suspicious" if sc < 4 else "Dangerous"))
                                st.write(f"  - Analysis: {tag} (score {sc})")

                        # record history per item
                        st.session_state.history.append({
                            "type": "qr",
                            "input": str(d),
                            "result": ("URL" if is_url else "data"),
                            "time": datetime.datetime.now()
                        })
                else:
                    st.warning("No QR codes found in the image.")

with tabs[2]:
    st.header("🎭 Deepfake Image Detector")
    st.markdown("Upload an image. The detector will attempt face detection and run a lightweight heuristic deepfake check.")
    uploaded_img = st.file_uploader("Upload an image (png, jpg)", type=["png", "jpg", "jpeg"]) 
    detect_btn = st.button("Detect Deepfake")
    if detect_btn:
        if uploaded_img is None:
            st.error("Please upload an image first.")
        else:
            try:
                image = Image.open(uploaded_img).convert("RGB")
            except Exception as e:
                st.error(f"Could not open image: {e}")
                image = None

            if image is not None:
                with st.spinner("Running face detection and heuristic checks..."):
                    faces = []
                    face_count = 0
                    try:
                        if cv2 is None:
                            raise RuntimeError("OpenCV not available")

                        arr = np.array(image.convert("RGB"))[:, :, ::-1]
                        gray = cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)
                        cascade_path = None
                        try:
                            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                        except Exception:
                            cascade_path = None

                        if cascade_path and os.path.exists(cascade_path):
                            face_cascade = cv2.CascadeClassifier(cascade_path)
                            rects = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
                            face_count = len(rects)
                        else:
                            face_count = 0
                    except Exception:
                        face_count = 0

                    st.image(image, caption=f"Uploaded image — faces detected: {face_count}", use_column_width=True)

                    # Basic heuristic for real/fake: placeholder only
                    if face_count >= 1:
                        label = "Likely Real"
                        confidence = 0.72
                    else:
                        label = "Unknown / Possibly Fake"
                        confidence = 0.35

                    # combine with deepfake_check heuristic (size-based) if useful
                    try:
                        # save to temp file and call check_deepfake
                        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_img.name)[1]) as tmpf:
                            tmpf.write(uploaded_img.getbuffer())
                            tmp_path = tmpf.name
                        extra = check_deepfake(tmp_path)
                        # merge confidence heuristically
                        if extra and isinstance(extra.get("confidence"), (int, float)):
                            confidence = min(0.99, confidence + float(extra.get("confidence", 0)) * 0.1)
                    except Exception:
                        extra = None
                    finally:
                        try:
                            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                                os.remove(tmp_path)
                        except Exception:
                            pass

                    st.subheader("Deepfake Result")
                    st.write(f"**{label}** — Confidence: {int(confidence*100)}%")
                    if extra:
                        st.write("Heuristic report:")
                        for k, v in extra.items():
                            st.write(f"- {k}: {v}")

                    st.session_state.history.append({
                        "type": "deepfake",
                        "input": getattr(uploaded_img, 'name', 'uploaded_image'),
                        "result": label,
                        "confidence": float(confidence),
                        "time": datetime.datetime.now()
                    })

with tabs[3]:
    st.header("About")
    st.markdown(
        """
        **CyberShield AI** — prototype Streamlit app for simple cyber security checks.

        - `URL Analyzer` performs basic heuristics and status checks.
        - `QR Scanner` decodes QR codes from uploaded images.
        - `Deepfake Check` is a placeholder stub; integrate a real model under `models/`.

        To run locally:
        ```bash
        pip install -r requirements.txt
        streamlit run app.py
        ```
        """
    )
