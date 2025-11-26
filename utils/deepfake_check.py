import os
import tempfile
import random
from typing import Tuple, Dict, Any

try:
    import cv2
    import numpy as np
except Exception:
    cv2 = None
    np = None


def check_deepfake(video_path: str) -> dict:
    """Legacy placeholder deepfake checker for video files.

    Kept for backwards compatibility. Returns a simple heuristic report
    based on file size.
    """
    report = {
        "file": video_path,
        "result": "unknown",
        "confidence": 0.0,
        "notes": "This is a placeholder. Integrate a trained model for deepfake detection."
    }

    if not os.path.exists(video_path):
        report["notes"] = "Video file not found"
        return report

    # Simple heuristic: small files are unlikely to contain complex deepfakes
    try:
        size = os.path.getsize(video_path)
        if size < 250_000:  # < ~250KB
            report["result"] = "likely_not_deepfake"
            report["confidence"] = 0.6
            report["notes"] = "Very small file — heuristic only"
        else:
            report["result"] = "unknown"
            report["confidence"] = 0.0
            report["notes"] = "File size heuristic inconclusive. Run model in `models/` for real checks."
    except Exception as e:
        report["notes"] = f"Error during heuristic check: {e}"

    return report


def analyze_image_quality(image_array) -> Tuple[float, float, Dict[str, Any]]:
    """Analyze basic image quality metrics.

    Returns (blur_score, noise_level, artifact_info)
    - blur_score: higher means sharper (variance of Laplacian mapped to 0-100)
    - noise_level: estimated noise level 0-100
    - artifact_info: dict with simple artifact detection flags
    """
    # Default mock values
    blur_score = 50.0
    noise_level = 10.0
    artifact_info = {"blocking": False, "jpeg_artifacts": False}

    try:
        if cv2 is not None and np is not None:
            if isinstance(image_array, np.ndarray):
                img = image_array
            else:
                img = np.array(image_array)

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img

            # Blur / sharpness: variance of Laplacian
            lap = cv2.Laplacian(gray, cv2.CV_64F)
            var = float(lap.var())
            # Map variance to 0-100 roughly
            blur_score = max(0.0, min(100.0, var / 10.0))

            # Noise estimate: using std dev normalized
            noise_level = max(0.0, min(100.0, float(np.std(gray) / 2.0)))

            # Simple artifact detection: check for large flat blocks (mock)
            h, w = gray.shape[:2]
            small = cv2.resize(gray, (64, 64))
            unique_vals = len(np.unique(small))
            artifact_info["blocking"] = unique_vals < 50
            artifact_info["jpeg_artifacts"] = unique_vals < 40
        else:
            # If cv2 not available, return conservative mock values
            blur_score = 50.0
            noise_level = 15.0
            artifact_info = {"blocking": False, "jpeg_artifacts": False}
    except Exception:
        # In case of any failure, keep mock defaults
        pass

    return blur_score, noise_level, artifact_info


def detect_deepfake(image_file) -> Dict[str, Any]:
    """Detect deepfake in an uploaded image (mocked realistic demo).

    Accepts a Streamlit uploaded file-like object or a filesystem path.

    Returns a dict with keys:
      - face_detected: bool
      - is_real: bool
      - confidence: int (75-95)
      - num_faces: int
      - analysis: dict (image quality metrics)
      - message: str
    """
    result = {
        "face_detected": False,
        "is_real": False,
        "confidence": 0,
        "num_faces": 0,
        "analysis": {},
        "message": ""
    }

    # Load image into numpy BGR array if possible
    img_array = None
    try:
        # If a path string
        if isinstance(image_file, str) and os.path.exists(image_file):
            if cv2 is not None:
                img_array = cv2.imread(image_file)
            else:
                from PIL import Image as PILImage
                img = PILImage.open(image_file).convert('RGB')
                img_array = np.array(img)[:, :, ::-1] if np is not None else None
        else:
            # file-like object (Streamlit UploadedFile)
            try:
                data = image_file.getbuffer()
            except Exception:
                try:
                    data = image_file.read()
                except Exception:
                    data = None

            if data is None:
                result["message"] = "Unable to read uploaded image"
                return result

            if cv2 is not None and np is not None:
                arr = np.frombuffer(data, np.uint8)
                img_array = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            else:
                from PIL import Image as PILImage
                import io
                img = PILImage.open(io.BytesIO(data)).convert('RGB')
                img_array = np.array(img)[:, :, ::-1] if np is not None else None

        # Face detection
        num_faces = 0
        faces = []
        if cv2 is not None and img_array is not None:
            try:
                gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)
                cascade_path = None
                try:
                    cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                except Exception:
                    cascade_path = None

                if cascade_path and os.path.exists(cascade_path):
                    face_cascade = cv2.CascadeClassifier(cascade_path)
                    rects = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
                    num_faces = len(rects)
                    faces = rects.tolist() if num_faces > 0 else []
            except Exception:
                num_faces = 0
        else:
            num_faces = 0

        result["num_faces"] = int(num_faces)
        result["face_detected"] = num_faces > 0

        # Image quality analysis (mock/real)
        if img_array is not None:
            blur, noise, artifacts = analyze_image_quality(img_array)
        else:
            blur, noise, artifacts = (50.0, 15.0, {"blocking": False, "jpeg_artifacts": False})

        result["analysis"] = {
            "blur_score": float(blur),
            "noise_level": float(noise),
            "artifacts": artifacts
        }

        # Mock realistic detection: 70% chance real, 30% fake
        is_real = random.random() < 0.7
        confidence = random.randint(75, 95)

        # Slightly adjust confidence if faces detected
        if num_faces > 0 and is_real:
            confidence = min(95, confidence + 5)
        if num_faces == 0 and not is_real:
            confidence = min(95, confidence + 5)

        result["is_real"] = bool(is_real)
        result["confidence"] = int(confidence)
        result["message"] = "Real image detected" if is_real else "Deepfake detected"

        return result
    except Exception as e:
        return {"face_detected": False, "is_real": False, "confidence": 0, "num_faces": 0, "analysis": {}, "message": f"Error during detection: {e}"}
