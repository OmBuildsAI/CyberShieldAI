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
import io
import os
import tempfile
import re
import numpy as np


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
