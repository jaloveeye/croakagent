"""croak-ocr: reads the text in images and PDFs and masks what the rules find.

    POST /inspect   {"kind": "image" | "pdf", "data": "<base64>",
                     "mask_secrets": bool, "mask_pii": bool,
                     "allow": {"email": ["owner@example.com"], ...}}
                 -> {"text": masked text, "secrets": {kind: n}, "pii": {kind: n},
                     "image": "<base64 png>" (images only, when something was masked),
                     "pages": n, "ocr": bool, "ms": elapsed}
    GET  /health

Detection uses the gate's own croak_core.py (mounted read-only), so text,
images and PDFs follow the same rules. Images are masked by drawing black
boxes over the words a rule matched. PDFs come back as masked text: their
text layer is read first, and pages without one are rendered and OCR'd.
Only the gate calls this service; it is not exposed through the proxy.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import sys
import threading
import time
from collections import OrderedDict
from typing import Any

import pytesseract
from fastapi import FastAPI, HTTPException
from pdf2image import convert_from_bytes
from PIL import Image, ImageDraw, ImageOps
from pypdf import PdfReader

sys.path.insert(0, os.environ.get("CROAK_RULES", "/app/rules"))
from croak_core import PII_PATTERNS, SECRET_PATTERNS, redact, spans  # noqa: E402

LANG = os.environ.get("OCR_LANG", "kor+eng")
MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 20
MIN_CONFIDENCE = 30
Image.MAX_IMAGE_PIXELS = 40_000_000  # refuse decompression bombs

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_cache: OrderedDict[str, dict] = OrderedDict()
_lock = threading.Lock()
CACHE_SIZE = 256


def _cached(key: str) -> dict | None:
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    return None


def _store(key: str, value: dict) -> None:
    with _lock:
        _cache[key] = value
        if len(_cache) > CACHE_SIZE:
            _cache.popitem(last=False)


# Two readings of every image: Tesseract misreads differently at each scale,
# so a match found in either one is masked. (scale, tesseract config)
PASSES = ((1, ""), (2, "--psm 6"))


def _words(img: Image.Image, config: str = "") -> tuple[str, list[tuple[int, int, tuple[int, int, int, int]]]]:
    """OCR text with each word's character range and box."""
    d = pytesseract.image_to_data(img, lang=LANG, config=config, output_type=pytesseract.Output.DICT)
    text, words, last_line = "", [], None
    for i, word in enumerate(d["text"]):
        word = (word or "").strip()
        if not word or float(d["conf"][i]) < MIN_CONFIDENCE:
            continue
        line = (d["block_num"][i], d["par_num"][i], d["line_num"][i])
        if text:
            text += "\n" if line != last_line else " "
        last_line = line
        start = len(text)
        text += word
        box = (d["left"][i], d["top"][i], d["left"][i] + d["width"][i], d["top"][i] + d["height"][i])
        words.append((start, len(text), box))
    return text, words


def _is_hangul(ch: str) -> bool:
    return "\uac00" <= ch <= "\ud7a3"


def normalize(text: str) -> tuple[str, list[int]]:
    """Drops spaces Tesseract puts between Hangul syllables ("주 민 번호").
    Returns the text and, for each of its characters, the original index."""
    out, index = [], []
    for i, ch in enumerate(text):
        if ch == " " and 0 < i < len(text) - 1 and _is_hangul(text[i - 1]) and _is_hangul(text[i + 1]):
            continue
        out.append(ch)
        index.append(i)
    return "".join(out), index


def _find_regions(text: str, mask_secrets: bool, mask_pii: bool, allow: dict) -> list[tuple[str, int, int]]:
    """Character ranges to black out. A secret runs to the end of its line:
    OCR often splits a password into words ("qwert 234!"), and the label alone
    would leave the rest readable."""
    norm, index = normalize(text)
    regions = []
    if mask_secrets:
        for k, a, b in spans(norm, SECRET_PATTERNS):
            line_end = norm.find("\n", b)
            regions.append((k, a, line_end if line_end != -1 else len(norm)))
    if mask_pii:
        regions += spans(norm, PII_PATTERNS, allow)
    return [(k, index[a], index[b - 1] + 1) for k, a, b in regions if b > a]


def _masked_text(text: str, mask_secrets: bool, mask_pii: bool, allow: dict) -> tuple[str, dict, dict]:
    text, _ = normalize(text)
    secret_scan = redact(text, SECRET_PATTERNS, "REDACTED")
    text_out = secret_scan.text if mask_secrets else text
    pii_scan = redact(text_out, PII_PATTERNS, "MASKED", allow)
    text_out = pii_scan.text if mask_pii else text_out
    return text_out, secret_scan.found, pii_scan.found


def _inspect_image(raw: bytes, mask_secrets: bool, mask_pii: bool, allow: dict) -> dict:
    img = Image.open(io.BytesIO(raw))
    img.load()
    img = img.convert("RGB")
    boxes: list[tuple[int, int, int, int]] = []
    best: tuple[int, str, dict, dict] | None = None
    secrets_all: dict[str, int] = {}
    pii_all: dict[str, int] = {}
    for scale, config in PASSES:
        view = img if scale == 1 else ImageOps.grayscale(img).resize((img.width * scale, img.height * scale), Image.LANCZOS)
        text, words = _words(view, config)
        masked, secrets, pii = _masked_text(text, True, True, allow)
        # A kind counts as often as the reading that saw it most.
        for total, found in ((secrets_all, secrets), (pii_all, pii)):
            for k, n in found.items():
                total[k] = max(total.get(k, 0), n)
        score = sum(secrets.values()) + sum(pii.values())
        if best is None or score > best[0]:
            best = (score, text, secrets, pii)
        for _, a, b in _find_regions(text, mask_secrets, mask_pii, allow):
            for start, end, (x0, y0, x1, y1) in words:
                if start < b and end > a:
                    boxes.append((x0 // scale, y0 // scale, -(-x1 // scale), -(-y1 // scale)))
    masked, _, _ = _masked_text(best[1], mask_secrets, mask_pii, allow) if best else ("", {}, {})
    out = {"text": masked, "secrets": secrets_all, "pii": pii_all, "pages": 1, "ocr": True}
    if boxes:
        draw = ImageDraw.Draw(img)
        for x0, y0, x1, y1 in boxes:
            draw.rectangle((x0 - 3, y0 - 3, x1 + 3, y1 + 3), fill="black")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        out["image"] = base64.b64encode(buf.getvalue()).decode("ascii")
    return out


def _inspect_pdf(raw: bytes, mask_secrets: bool, mask_pii: bool, allow: dict) -> dict:
    reader = PdfReader(io.BytesIO(raw))
    pages = reader.pages[:MAX_PAGES]
    texts = [(p.extract_text() or "") for p in pages]
    used_ocr = False
    if sum(len(t.strip()) for t in texts) < 20:  # scanned: no text layer
        used_ocr = True
        images = convert_from_bytes(raw, dpi=150, first_page=1, last_page=len(pages) or 1)
        texts = [_words(im)[0] for im in images]
    text = "\n\n".join(f"[page {i + 1}]\n{t.strip()}" for i, t in enumerate(texts))
    masked, secrets, pii = _masked_text(text, mask_secrets, mask_pii, allow)
    return {"text": masked, "secrets": secrets, "pii": pii, "pages": len(reader.pages), "ocr": used_ocr}


@app.post("/inspect")
def inspect(body: dict[str, Any]) -> dict:
    kind = body.get("kind")
    if kind not in ("image", "pdf"):
        raise HTTPException(400, "kind must be image or pdf")
    try:
        raw = base64.b64decode(body.get("data") or "", validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "data must be base64")
    if not raw or len(raw) > MAX_BYTES:
        raise HTTPException(413, f"data must be 1 byte to {MAX_BYTES} bytes")
    mask_secrets = bool(body.get("mask_secrets", True))
    mask_pii = bool(body.get("mask_pii", True))
    allow = {k: frozenset(str(v).lower() for v in vals) for k, vals in (body.get("allow") or {}).items() if isinstance(vals, list)}
    key = hashlib.sha256(
        json.dumps([kind, mask_secrets, mask_pii, sorted((k, sorted(v)) for k, v in allow.items())]).encode() + raw
    ).hexdigest()
    if (hit := _cached(key)) is not None:
        return {**hit, "cached": True}
    t0 = time.monotonic()
    try:
        result = (_inspect_image if kind == "image" else _inspect_pdf)(raw, mask_secrets, mask_pii, allow)
    except (Image.DecompressionBombError, OSError, ValueError) as error:
        raise HTTPException(422, f"could not read the {kind}: {type(error).__name__}")
    result["ms"] = int((time.monotonic() - t0) * 1000)
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    _store(key, result)
    return result


@app.get("/health")
def health() -> dict:
    return {"ok": True, "lang": LANG}
