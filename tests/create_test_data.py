#!/usr/bin/env python3
"""Standalone test data generator for CyberShieldAI.

This script generates demo QR images, a test URL list, and placeholder
sample images for deepfake testing under the `data/` directory.

Only requirement: the `qrcode` package (for QR generation). If it's not
installed the script will print installation instructions and still create
the URL list and folder structure.

Run from repository root:

    python3 tests/create_test_data.py

"""
from pathlib import Path
import sys
import os
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SAMPLES_DIR = DATA_DIR / "sample_images"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# QR definitions (requested)
QR_DEFS = {
    "safe_qr.png": "https://www.github.com",
    "suspicious_qr.png": "http://bit.ly/secure-login-account",
    "dangerous_qr.png": "http://192.168.1.1/verify-account.php",
}

# URL list (requested)
TEST_URLS = {
    "SAFE": [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.python.org",
    ],
    "SUSPICIOUS": [
        "http://bit.ly/secure-login-update",
        "http://tinyurl.com/account-verification",
        "http://short.url/banking-update",
    ],
    "DANGEROUS": [
        "http://192.168.1.1/login-verify.php",
        "http://45.76.223.12/secure-account.com",
        "http://10.0.0.1/update-banking.html",
    ],
}


def generate_qr_images():
    try:
        import qrcode
    except Exception:
        print("qrcode library is not installed. Install with: pip install qrcode[pil]")
        return False

    for fname, url in QR_DEFS.items():
        out_path = DATA_DIR / fname
        try:
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(out_path)
            print(f"Generated QR image: {out_path} -> {url}")
        except Exception as e:
            print(f"Failed to generate {fname}: {e}")
            return False
    return True


def write_test_urls():
    out_file = DATA_DIR / "test_urls.txt"
    with out_file.open("w", encoding="utf8") as fh:
        for cat, urls in TEST_URLS.items():
            fh.write(f"# {cat}\n")
            for u in urls:
                fh.write(u + "\n")
            fh.write("\n")
    print(f"Wrote URL list -> {out_file}")


def create_sample_image_placeholders():
    real_dir = SAMPLES_DIR / "real"
    fake_dir = SAMPLES_DIR / "fake"
    real_dir.mkdir(parents=True, exist_ok=True)
    fake_dir.mkdir(parents=True, exist_ok=True)

    # create small placeholder files
    for i in range(1, 3):
        (real_dir / f"real_{i}.jpg").write_bytes(b"")
        (fake_dir / f"fake_{i}.jpg").write_bytes(b"")

    print(f"Created sample image folders: {real_dir} , {fake_dir}")


def print_instructions():
    print("\n=== Demo Data Generated ===")
    print(f"Data folder: {DATA_DIR}")
    print("\nFiles:")
    for fname in QR_DEFS:
        print(f"  - {DATA_DIR / fname}")
    print(f"  - {DATA_DIR / 'test_urls.txt'}")
    print(f"  - {SAMPLES_DIR}/real/ and {SAMPLES_DIR}/fake/ (placeholder files)")

    print("\nUsage suggestions:")
    print("  - QR images: upload the PNGs in the Streamlit app QR tab to test decoding and URL analysis.")
    print("    Expected: safe_qr -> URL to github (safe). suspicious_qr -> shortened URL (suspicious). dangerous_qr -> IP-based URL (dangerous).")
    print("  - URL list: use data/test_urls.txt as input to bulk-test the URL analyzer. Safe/Suspicious/Dangerous categories are included.")
    print("  - Sample images: use the placeholder images to populate the deepfake demo folders. Replace with real images for testing model behavior.")

    print("\nQuick demo script for presentation:")
    print("  1) Install deps (if not installed): pip install -r requirements.txt")
    print("  2) Generate data (already done): python3 tests/create_test_data.py")
    print("  3) Run the app: streamlit run app.py")
    print("  4) In the app: use the QR tab to upload the PNGs and the Deepfake tab to browse sample_images/ for testing.")


def main():
    print(f"Creating demo data under: {DATA_DIR}")
    ok = generate_qr_images()
    write_test_urls()
    create_sample_image_placeholders()
    print_instructions()
    if not ok:
        print('\nNote: QR images were not created because the `qrcode` package is missing.')
        print('Install with: pip install qrcode[pil] and re-run this script to generate QR images.')


if __name__ == '__main__':
    main()
