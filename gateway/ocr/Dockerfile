# croak-ocr: Tesseract (Korean and English) and PDF text extraction for the gate.
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-kor tesseract-ocr-eng poppler-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10002 ocr
COPY ocr_service.py .
USER ocr
EXPOSE 8000
CMD ["uvicorn", "ocr_service:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
