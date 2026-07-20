"""Playbook document parser — extract text from PDF/DOCX/MD, convert to YAML via GPT-5.6.

Usage:
    from scripts.playbook_parser import parse_playbook_document
    from scripts.soc_client.openai import OpenAIClient

    client = OpenAIClient(api_key)
    result = parse_playbook_document(Path("soc-sop.pdf"), client.chat)
    if result["valid"]:
        # save result["playbook"] to playbooks/
    else:
        # show result["errors"] for human review
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable


ALLOWED_EXTENSIONS = {".yaml", ".yml", ".pdf", ".docx", ".md", ".txt"}

VALID_STEP_TYPES = {
    "llm", "toolchain", "rule", "thehive",
    "mitre_mapping", "approval", "report",
}

LLM_SCHEMA_PROMPT = """You are a security playbook parser. Convert the following SOC
procedure document into a structured YAML playbook.

The output MUST be valid JSON matching this schema:
{
  "id": "kebab-case-unique-id",
  "name": "Human-Readable Playbook Name",
  "version": 1,
  "description": "One paragraph description",
  "triggers": [
    {"alert_rule": "Rule Name"},
    {"mitre_technique": "T####"},
    {"tags": ["tag1", "tag2"]}
  ],
  "inputs": [
    {"name": "input_name", "required": true, "default": null}
  ],
  "steps": [
    {
      "id": "step_name",
      "type": "llm|toolchain|rule|thehive|mitre_mapping|approval|report",
      ...type-specific fields...
    }
  ]
}

Step types:
- llm: {"id": "...", "type": "llm", "prompt": "..."}
- toolchain: {"id": "...", "type": "toolchain", "run": [{"tool": "...", "operation": "...", "target": "..."}]}
- rule: {"id": "...", "type": "rule", "when": {"condition": "..."}, "action": "skip_to", "target": "step_id"}
- thehive: {"id": "...", "type": "thehive", "action": "create_or_update_case", "inputs": {...}}
- mitre_mapping: {"id": "...", "type": "mitre_mapping"}
- approval: {"id": "...", "type": "approval", "when": {"condition": "..."}, "actions": [...]}
- report: {"id": "...", "type": "report", "report_type": "soc|incident|executive"}

Return ONLY the JSON object. No markdown fences, no explanation."""


def extract_text(path: Path, mime_type: str = "") -> str:
    """Extract plain text from a document file.

    Supports: .txt, .md (native), .pdf (pdfminer), .docx (python-docx)
    """
    suffix = path.suffix.lower()

    if suffix in (".txt", ".md"):
        return path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".pdf":
        try:
            from pdfminer.high_level import extract_text as pdf_extract
            return pdf_extract(str(path))
        except ImportError:
            raise RuntimeError(
                "pdfminer.six is required for PDF parsing. "
                "Install with: pip install pdfminer.six"
            )

    if suffix == ".docx":
        try:
            from docx import Document
            doc = Document(str(path))
            return "\n".join(para.text for para in doc.paragraphs)
        except ImportError:
            raise RuntimeError(
                "python-docx is required for DOCX parsing. "
                "Install with: pip install python-docx"
            )

    if suffix in (".yaml", ".yml"):
        return path.read_text(encoding="utf-8")

    raise RuntimeError(f"Unsupported file type: {suffix}")


def parse_with_llm(
    document_text: str,
    llm_callback: Callable[[str, str], str],
) -> dict[str, Any]:
    """Send document text to GPT-5.6 and get a parsed playbook dict.

    Args:
        document_text: Raw extracted text from the document.
        llm_callback: A function that takes (system_prompt, user_prompt) and returns a string.
            Typically OpenAIClient.chat but wrapped to match this signature.

    Returns:
        Parsed playbook dict, or {"error": "..."} on failure.
    """
    # Truncate very long documents to stay within context limits
    if len(document_text) > 50000:
        document_text = document_text[:50000] + "\n\n[Document truncated at 50,000 characters]"

    try:
        response = llm_callback(LLM_SCHEMA_PROMPT, document_text)
    except Exception as e:
        return {"error": f"LLM call failed: {e}"}

    # Strip markdown fences if present
    cleaned = response.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        return {"error": f"LLM returned invalid JSON: {e}", "raw": response[:500]}


def validate_playbook(playbook: dict[str, Any]) -> list[str]:
    """Validate a parsed playbook against the schema.

    Returns a list of error strings. Empty list means valid.
    """
    errors = []

    if not isinstance(playbook, dict):
        return ["Playbook is not a dictionary"]

    # Required top-level fields
    for field in ("id", "name", "steps"):
        if field not in playbook:
            errors.append(f"Missing required field: {field}")

    if "steps" in playbook:
        steps = playbook["steps"]
        if not isinstance(steps, list) or len(steps) == 0:
            errors.append("'steps' must be a non-empty list")
        else:
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    errors.append(f"Step {i} is not a dictionary")
                    continue
                if "id" not in step:
                    errors.append(f"Step {i} missing 'id'")
                if "type" not in step:
                    errors.append(f"Step {i} missing 'type'")
                elif step["type"] not in VALID_STEP_TYPES:
                    errors.append(
                        f"Step {i} has invalid type '{step['type']}'. "
                        f"Valid types: {', '.join(sorted(VALID_STEP_TYPES))}"
                    )

    # Validate triggers if present
    if "triggers" in playbook:
        triggers = playbook["triggers"]
        if not isinstance(triggers, list):
            errors.append("'triggers' must be a list")
        else:
            for i, trigger in enumerate(triggers):
                if not isinstance(trigger, dict):
                    errors.append(f"Trigger {i} is not a dictionary")
                elif not any(k in trigger for k in ("alert_rule", "mitre_technique", "tags")):
                    errors.append(f"Trigger {i} must have at least one of: alert_rule, mitre_technique, tags")

    return errors


def parse_playbook_document(
    path: Path,
    llm_callback: Callable[[str, str], str],
) -> dict[str, Any]:
    """Full pipeline: extract text → LLM parse → validate.

    Returns:
        {
            "playbook": {...} or None,
            "valid": bool,
            "errors": [...],
            "source_file": str,
            "raw_text_preview": str (first 500 chars)
        }
    """
    if not path.is_file():
        return {
            "playbook": None,
            "valid": False,
            "errors": [f"File not found: {path}"],
            "source_file": str(path),
            "raw_text_preview": "",
        }

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return {
            "playbook": None,
            "valid": False,
            "errors": [f"Unsupported file type: {path.suffix}. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"],
            "source_file": str(path),
            "raw_text_preview": "",
        }

    # For YAML files, try direct parse first
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml
        try:
            content = path.read_text(encoding="utf-8")
            playbook = yaml.safe_load(content)
            errors = validate_playbook(playbook)
            return {
                "playbook": playbook if not errors else None,
                "valid": len(errors) == 0,
                "errors": errors,
                "source_file": str(path),
                "raw_text_preview": content[:500],
            }
        except Exception as e:
            return {
                "playbook": None,
                "valid": False,
                "errors": [f"YAML parse error: {e}"],
                "source_file": str(path),
                "raw_text_preview": "",
            }

    # For non-YAML: extract text → LLM → validate
    try:
        raw_text = extract_text(path)
    except Exception as e:
        return {
            "playbook": None,
            "valid": False,
            "errors": [f"Text extraction failed: {e}"],
            "source_file": str(path),
            "raw_text_preview": "",
        }

    if not raw_text.strip():
        return {
            "playbook": None,
            "valid": False,
            "errors": ["Document appears to be empty"],
            "source_file": str(path),
            "raw_text_preview": "",
        }

    # Parse with LLM
    parsed = parse_with_llm(raw_text, llm_callback)

    if "error" in parsed:
        return {
            "playbook": None,
            "valid": False,
            "errors": [parsed["error"]],
            "source_file": str(path),
            "raw_text_preview": raw_text[:500],
        }

    # Validate
    errors = validate_playbook(parsed)

    return {
        "playbook": parsed if not errors else None,
        "valid": len(errors) == 0,
        "errors": errors,
        "source_file": str(path),
        "raw_text_preview": raw_text[:500],
    }
