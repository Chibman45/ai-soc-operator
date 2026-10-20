"""Validated, provenance-preserving extraction for untrusted uploaded documents.

All callers use this service before sending document content to an AI model.
The original upload is copied into evidence storage and the extraction remains
in ``preview`` state until an authenticated user explicitly requests analysis.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any

SUPPORTED_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".pdf", ".docx", ".md", ".txt",
    ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".webp",
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".webp"}
PURPOSES = {"playbook", "organization_policy", "architecture"}
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_IMAGE_PIXELS = 40_000_000
DEFAULT_OCR_TIMEOUT = 30
MIN_NATIVE_PAGE_TEXT = 30
MAX_DOCX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_CHARS = 500_000
MAX_OCR_BOXES = 10_000
# Keep each Tesseract process to one OpenMP thread. Page count, pixel count, and
# wall-clock timeout provide the other resource bounds around untrusted input.
os.environ.setdefault("OMP_THREAD_LIMIT", "1")
MIME_TYPES = {
    ".yaml": {"application/yaml", "application/x-yaml", "text/yaml", "text/plain"},
    ".yml": {"application/yaml", "application/x-yaml", "text/yaml", "text/plain"},
    ".json": {"application/json", "text/json", "text/plain"},
    ".pdf": {"application/pdf"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".md": {"text/markdown", "text/plain"},
    ".txt": {"text/plain"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".tif": {"image/tiff"},
    ".tiff": {"image/tiff"},
    ".webp": {"image/webp"},
}


class DocumentValidationError(RuntimeError):
    """Raised when an upload fails file-name, size, or content validation."""


def _safe_name(name: str) -> str:
    value = str(name or "").strip()
    if not value or Path(value).name != value or value in {".", ".."}:
        raise DocumentValidationError("invalid upload file name")
    if any(char in value for char in ("/", "\\", "\x00")):
        raise DocumentValidationError("invalid upload file name")
    return value[:240]


def _validate_signature(path: Path, suffix: str) -> None:
    head = path.read_bytes()[:16]
    if suffix == ".pdf" and not head.startswith(b"%PDF-"):
        raise DocumentValidationError("PDF extension does not match the file signature")
    if suffix == ".docx":
        if not head.startswith(b"PK"):
            raise DocumentValidationError("DOCX extension does not match the file signature")
        try:
            with zipfile.ZipFile(path) as archive:
                if "[Content_Types].xml" not in archive.namelist() or "word/document.xml" not in archive.namelist():
                    raise DocumentValidationError("DOCX package signature is invalid")
                total_size = sum(item.file_size for item in archive.infolist())
                if total_size > MAX_DOCX_UNCOMPRESSED_BYTES:
                    raise DocumentValidationError("DOCX package exceeds the uncompressed size limit")
                if any(item.file_size > max(item.compress_size, 1) * 200 for item in archive.infolist()):
                    raise DocumentValidationError("DOCX package has an unsafe compression ratio")
        except zipfile.BadZipFile as exc:
            raise DocumentValidationError("DOCX package signature is invalid") from exc
    signatures = {
        ".png": lambda value: value.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": lambda value: value.startswith(b"\xff\xd8\xff"),
        ".jpeg": lambda value: value.startswith(b"\xff\xd8\xff"),
        ".tif": lambda value: value.startswith((b"II*\x00", b"MM\x00*")),
        ".tiff": lambda value: value.startswith((b"II*\x00", b"MM\x00*")),
        ".webp": lambda value: value.startswith(b"RIFF") and value[8:12] == b"WEBP",
    }
    if suffix in signatures and not signatures[suffix](head):
        raise DocumentValidationError(f"{suffix[1:].upper()} extension does not match the file signature")


def validate_upload(
    path: Path,
    *,
    original_name: str,
    declared_mime: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Validate metadata and file content before any parser sees the upload."""
    name = _safe_name(original_name)
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise DocumentValidationError("uploaded document is not a regular file")
    suffix = Path(name).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise DocumentValidationError(f"unsupported document type: {suffix or 'none'}")
    size = path.stat().st_size
    if size <= 0:
        raise DocumentValidationError("uploaded document is empty")
    if size > max_bytes:
        raise DocumentValidationError(f"uploaded document exceeds the {max_bytes} byte limit")
    _validate_signature(path, suffix)
    normalized_mime = str(declared_mime or "").split(";", 1)[0].strip().lower()
    if normalized_mime and normalized_mime != "application/octet-stream" and normalized_mime not in MIME_TYPES[suffix]:
        raise DocumentValidationError(f"declared MIME type {normalized_mime} does not match {suffix}")
    if suffix in {".yaml", ".yml", ".json", ".md", ".txt"}:
        sample = path.read_bytes()[:8192]
        if b"\x00" in sample:
            raise DocumentValidationError("text document contains binary content")
    return {"name": name, "suffix": suffix, "size": size, "mime_type": normalized_mime or min(MIME_TYPES[suffix])}


def _bounded_image(image):
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = DEFAULT_MAX_IMAGE_PIXELS
    image.load()
    if image.width * image.height > DEFAULT_MAX_IMAGE_PIXELS:
        raise DocumentValidationError("image exceeds the OCR pixel limit")
    return image


def _ocr_image(image, *, timeout: int = DEFAULT_OCR_TIMEOUT) -> dict[str, Any]:
    """Run Tesseract with a hard timeout and retain OCR bounding boxes."""
    try:
        import pytesseract
        from pytesseract import Output
    except ImportError as exc:
        raise RuntimeError("pytesseract is required for scanned document OCR") from exc
    image = _bounded_image(image)
    try:
        data = pytesseract.image_to_data(image, output_type=Output.DICT, timeout=timeout)
    except RuntimeError as exc:
        raise RuntimeError(f"OCR exceeded its {timeout}-second page timeout") from exc
    boxes = []
    for index, value in enumerate(data.get("text", [])):
        text = str(value or "").strip()
        if not text:
            continue
        boxes.append(
            {
                "text": text[:500],
                "left": int(data["left"][index]),
                "top": int(data["top"][index]),
                "width": int(data["width"][index]),
                "height": int(data["height"][index]),
                "confidence": float(data.get("conf", [0] * len(data["text"]))[index]),
            }
        )
        if len(boxes) >= MAX_OCR_BOXES:
            break
    return {"text": " ".join(item["text"] for item in boxes), "boxes": boxes}


def _extract_pdf_pages(path: Path) -> list[str]:
    try:
        from pdfminer.high_level import extract_pages
        from pdfminer.layout import LTTextContainer
    except ImportError as exc:
        raise RuntimeError("pdfminer.six is required for PDF extraction") from exc
    pages = []
    try:
        for layout in extract_pages(str(path)):
            pages.append("\n".join(item.get_text() for item in layout if isinstance(item, LTTextContainer)).strip())
            if len(pages) > DEFAULT_MAX_PAGES:
                raise DocumentValidationError(f"PDF exceeds the {DEFAULT_MAX_PAGES}-page limit")
    except DocumentValidationError:
        raise
    except Exception as exc:
        raise RuntimeError(f"PDF native text extraction failed: {exc}") from exc
    return pages


def _render_pdf_page(path: Path, page_number: int):
    try:
        from pdf2image import convert_from_path
        from pdf2image.exceptions import (
            PDFInfoNotInstalledError,
            PDFPageCountError,
            PDFPopplerTimeoutError,
        )
    except ImportError as exc:
        raise RuntimeError("pdf2image and Poppler are required for scanned PDF OCR") from exc
    try:
        images = convert_from_path(
            str(path), dpi=200, first_page=page_number, last_page=page_number,
            fmt="png", thread_count=1, timeout=DEFAULT_OCR_TIMEOUT,
        )
    except (OSError, PDFInfoNotInstalledError, PDFPageCountError, PDFPopplerTimeoutError) as exc:
        raise RuntimeError(f"PDF page {page_number} rendering failed: {exc}") from exc
    if not images:
        raise RuntimeError(f"could not render PDF page {page_number}")
    return _bounded_image(images[0])


def _add_fragment(fragments: list[str], provenance: list[dict[str, Any]], text: str, **meta: Any) -> None:
    # Preserve indentation because YAML and Markdown whitespace is semantic.
    # OCR engines already return flattened text where whitespace is not trusted.
    cleaned = str(text or "").strip()
    if not cleaned:
        return
    fragments.append(cleaned)
    provenance.append({**meta, "text": cleaned[:2000]})


def _extract_docx(path: Path) -> tuple[list[str], list[dict[str, Any]], bool, list[str]]:
    try:
        from docx import Document
        from docx.table import Table
        from docx.text.paragraph import Paragraph
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError("python-docx and Pillow are required for DOCX extraction") from exc

    try:
        doc = Document(str(path))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"DOCX parsing failed: {exc}") from exc
    Image.MAX_IMAGE_PIXELS = DEFAULT_MAX_IMAGE_PIXELS
    fragments: list[str] = []
    provenance: list[dict[str, Any]] = []
    warnings: list[str] = []
    body_index = 0
    for child in doc.element.body.iterchildren():
        if child.tag.endswith("}p"):
            body_index += 1
            paragraph = Paragraph(child, doc)
            _add_fragment(fragments, provenance, paragraph.text, kind="paragraph", location=f"body:p{body_index}", method="native")
        elif child.tag.endswith("}tbl"):
            body_index += 1
            table = Table(child, doc)
            for row_index, row in enumerate(table.rows, start=1):
                text = " | ".join(cell.text.strip() for cell in row.cells)
                _add_fragment(fragments, provenance, text, kind="table", location=f"body:table{body_index}:row{row_index}", method="native")

    for section_index, section in enumerate(doc.sections, start=1):
        for location, container in (("header", section.header), ("footer", section.footer)):
            for paragraph_index, paragraph in enumerate(container.paragraphs, start=1):
                _add_fragment(
                    fragments, provenance, paragraph.text,
                    kind=location, location=f"section{section_index}:{location}:p{paragraph_index}", method="native",
                )

    ocr_used = False
    seen_images: set[str] = set()
    image_index = 0
    for part in doc.part.package.parts:
        content_type = str(getattr(part, "content_type", ""))
        if not content_type.startswith("image/"):
            continue
        blob = bytes(part.blob)
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen_images:
            continue
        seen_images.add(digest)
        image_index += 1
        try:
            with Image.open(io.BytesIO(blob)) as image:
                ocr = _ocr_image(image.copy())
        except (OSError, RuntimeError, ValueError, Image.DecompressionBombError) as exc:
            provenance.append({"kind": "image", "location": f"image:{image_index}", "method": "ocr_failed", "error": str(exc)[:300]})
            warnings.append(f"Embedded image {image_index} could not be OCR processed: {str(exc)[:160]}")
            continue
        ocr_used = True
        _add_fragment(
            fragments, provenance, ocr.get("text", ""), kind="image",
            location=f"image:{image_index}", method="ocr", boxes=ocr.get("boxes", []),
        )
    return fragments, provenance, ocr_used, warnings


def extract_document(
    path: Path,
    *,
    original_name: str,
    declared_mime: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Extract untrusted content without interpreting or activating it."""
    metadata = validate_upload(path, original_name=original_name, declared_mime=declared_mime, max_bytes=max_bytes)
    suffix = metadata["suffix"]
    fragments: list[str] = []
    provenance: list[dict[str, Any]] = []
    warnings: list[str] = []
    ocr_used = False

    if suffix in {".yaml", ".yml", ".json", ".md", ".txt"}:
        _add_fragment(
            fragments, provenance, Path(path).read_text(encoding="utf-8", errors="replace"),
            kind="text", location="document", method="native",
        )
    elif suffix == ".pdf":
        pages = _extract_pdf_pages(Path(path))
        if len(pages) > DEFAULT_MAX_PAGES:
            raise DocumentValidationError(f"PDF exceeds the {DEFAULT_MAX_PAGES}-page limit")
        for page_number, native_text in enumerate(pages, start=1):
            if len(native_text.strip()) >= MIN_NATIVE_PAGE_TEXT:
                _add_fragment(fragments, provenance, native_text, kind="page", location=f"page:{page_number}", method="native")
                continue
            image = _render_pdf_page(Path(path), page_number)
            ocr = _ocr_image(image)
            ocr_used = True
            _add_fragment(
                fragments, provenance, ocr.get("text", ""), kind="page",
                location=f"page:{page_number}", method="ocr", boxes=ocr.get("boxes", []),
            )
            if not ocr.get("text", "").strip():
                warnings.append(f"No readable text found on page {page_number}")
    elif suffix == ".docx":
        fragments, provenance, ocr_used, docx_warnings = _extract_docx(Path(path))
        warnings.extend(docx_warnings)
    elif suffix in IMAGE_EXTENSIONS:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = DEFAULT_MAX_IMAGE_PIXELS
            with Image.open(path) as image:
                ocr = _ocr_image(image.copy())
        except ImportError as exc:
            raise RuntimeError("Pillow is required for image extraction") from exc
        ocr_used = True
        _add_fragment(
            fragments, provenance, ocr.get("text", ""), kind="image",
            location="image:1", method="ocr", boxes=ocr.get("boxes", []),
        )

    text = "\n\n".join(fragments).strip()
    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentValidationError(f"extracted document exceeds the {MAX_EXTRACTED_CHARS}-character limit")
    if not text:
        warnings.append("No readable text was extracted")
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return {
        **metadata,
        "sha256": digest,
        "text": text,
        "preview": text[:12000],
        "provenance": provenance,
        "warnings": warnings,
        "ocr_used": ocr_used,
    }


def ingest_document(
    conn,
    *,
    org_id: int,
    purpose: str,
    source_path: Path,
    source_name: str,
    declared_mime: str | None = None,
    created_by: int,
    evidence_root: Path,
) -> dict[str, Any]:
    """Store an immutable original and a reviewable extraction preview."""
    if purpose not in PURPOSES:
        raise ValueError(f"unsupported document purpose: {purpose}")
    result = extract_document(source_path, original_name=source_name, declared_mime=declared_mime)
    destination_dir = Path(evidence_root) / "document-ingestions" / str(org_id)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{result['sha256']}{result['suffix']}"
    if not destination.exists():
        with destination.open("xb") as handle:
            handle.write(Path(source_path).read_bytes())
        try:
            os.chmod(destination, 0o440)
        except OSError:
            pass
    elif hashlib.sha256(destination.read_bytes()).hexdigest() != result["sha256"]:
        raise RuntimeError("evidence path collision detected")

    cursor = conn.execute(
        """
        INSERT INTO document_ingestions
            (org_id, purpose, source_name, suffix, mime_type, source_sha256, evidence_path,
             extraction_text, preview_text, provenance_json, warnings_json,
             ocr_used, status, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'preview', ?)
        """,
        (
            org_id, purpose, result["name"], result["suffix"], result["mime_type"], result["sha256"],
            str(destination), result["text"], result["preview"],
            json.dumps(result["provenance"]), json.dumps(result["warnings"]),
            int(result["ocr_used"]), created_by,
        ),
    )
    result.update({"id": int(cursor.lastrowid), "purpose": purpose, "evidence_path": str(destination), "status": "preview"})
    return result


def mark_document_analyzed(conn, ingestion_id: int, *, org_id: int, result_type: str, result_id: int) -> dict[str, Any]:
    """Atomically consume a reviewed preview once for downstream AI analysis."""
    updated = conn.execute(
        """
        UPDATE document_ingestions
        SET status = 'analyzed', analysis_result_type = ?, analysis_result_id = ?, analyzed_at = CURRENT_TIMESTAMP
        WHERE id = ? AND org_id = ? AND status = 'preview'
        """,
        (result_type[:80], int(result_id), int(ingestion_id), int(org_id)),
    ).rowcount
    if not updated:
        raise ValueError("document must be in preview state before analysis")
    row = conn.execute("SELECT * FROM document_ingestions WHERE id = ? AND org_id = ?", (ingestion_id, org_id)).fetchone()
    return dict(row)


def load_document_preview(conn, ingestion_id: int, *, org_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM document_ingestions WHERE id = ? AND org_id = ?", (ingestion_id, org_id)).fetchone()
    if not row:
        raise ValueError("document preview not found")
    result = dict(row)
    result["provenance"] = json.loads(result.pop("provenance_json") or "[]")
    result["warnings"] = json.loads(result.pop("warnings_json") or "[]")
    return result
