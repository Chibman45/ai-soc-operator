FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2

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
COPY requirements.lock ./
# pip remains available for approved, isolated capability installs. Pin the
# latest release before pip began bundling a vulnerable vendor SBOM, while
# keeping the installed application libraries and setuptools fully patched.
RUN python -m pip install --upgrade "pip==26.1.1" "setuptools==84.2.0" \
    && python -m pip install --require-hashes -r requirements.lock
COPY --chown=soc:soc . .
RUN mkdir -p data audit evidence reports/generated backups && chown -R soc:soc data audit evidence reports backups

USER 10001:10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health/ready', timeout=3)"]
CMD ["gunicorn", "--config", "deploy/gunicorn.conf.py", "web.app:app"]
