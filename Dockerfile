FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AI_SOC_HOME=/app

WORKDIR /app

# OCR is local and bounded; Poppler renders only pages that lack enough native
# text, while Tesseract handles scanned pages and uploaded chart images.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    poppler-utils tesseract-ocr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 soc && useradd --system --uid 10001 --gid soc --home /app soc
COPY requirements.txt ./
# Upgrade the packaging toolchain before application dependencies so the final
# runtime image does not retain vulnerable packages inherited from the base.
RUN python -m pip install --upgrade pip "setuptools>=78.1.1" \
    && python -m pip install --upgrade -r requirements.txt
COPY --chown=soc:soc . .
RUN mkdir -p data audit evidence reports/generated backups && chown -R soc:soc data audit evidence reports backups

USER 10001:10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health/ready', timeout=3)"]
CMD ["gunicorn", "--config", "deploy/gunicorn.conf.py", "web.app:app"]
