"""OpenAI API client for playbook LLM steps.

Provides direct GPT-5.6 calls for classification, summarization,
and analyst analysis. Used by the playbook engine when the Codex
agent delegates LLM steps to a direct API call.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import ssl
from typing import Any

try:
    from .common import audit, utc_now
except ImportError:
    from common import audit, utc_now


# The model string used for all direct LLM calls.
# This is the model required by the hackathon rules.
MODEL = "gpt-5.6"

API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIClient:
    """Lightweight OpenAI API client for GPT-5.6 calls.

    Uses only stdlib (urllib) — no pip dependency on the openai package.
    """

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._ssl_context = ssl.create_default_context()

    def chat(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode("utf-8")

        request = urllib.request.Request(
            API_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
        )

        with opener.open(request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))

        content = result["choices"][0]["message"]["content"]
        audit(
            "openai_call",
            model=MODEL,
            tokens_used=result.get("usage", {}).get("total_tokens", 0),
        )
        return content

    def classify_alert(self, alert_json: str) -> dict[str, Any]:
        system = (
            "You are a senior SOC analyst. Analyze the alert and produce structured JSON.\n"
            "Return a JSON object with these fields:\n"
            '- "incident_type": one of ["credential_compromise", "brute_force", "phishing", '
            '"malware", "data_exfiltration", "lateral_movement", "reconnaissance", "other"]\n'
            '- "confidence": one of ["low", "medium", "high"]\n'
            '- "false_positive_probability": float between 0 and 1\n'
            '- "iocs": list of objects with "type" (ip/domain/hash/user) and "value"\n'
            '- "severity": one of ["info", "low", "medium", "high", "critical"]\n'
            '- "narrative": 2-3 sentence summary of what happened\n'
            '- "affected_assets": list of affected hosts/users\n'
            '- "containment_recommendations": list of recommended containment actions\n'
            "Return ONLY valid JSON, no markdown fences."
        )
        response = self.chat(alert_json, system=system, temperature=0.1)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown fences
            import re
            match = re.search(r"```(?:json)?\s*(.*?)```", response, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            return {"error": "Failed to parse LLM response", "raw": response}

    def analyst_summary(self, classification: dict, enrichment: dict) -> str:
        system = (
            "You are a senior SOC analyst writing an investigation summary.\n"
            "Be concise, factual, and actionable. Use bullet points.\n"
        )
        prompt = (
            f"Investigation classification:\n{json.dumps(classification, indent=2)}\n\n"
            f"Enrichment results:\n{json.dumps(enrichment, indent=2)}\n\n"
            "Write a concise analyst summary covering:\n"
            "1. What happened (one paragraph)\n"
            "2. IOCs and their threat assessment\n"
            "3. Business impact\n"
            "4. Recommended containment actions\n"
            "5. Recommended next steps for investigation"
        )
        return self.chat(prompt, system=system, temperature=0.3)

    def attack_mapping(self, iocs: list[dict], alert_context: str) -> dict[str, Any]:
        system = (
            "You are a MITRE ATT&CK analyst. Map observed behavior to ATT&CK techniques.\n"
            "Return JSON with:\n"
            '- "techniques": list of {"id": "T####", "name": "...", "tactic": "...", "confidence": "low/medium/high"}\n'
            '- "summary": one-paragraph explanation of the attack chain\n'
            "Return ONLY valid JSON."
        )
        prompt = (
            f"IOCs: {json.dumps(iocs)}\n\n"
            f"Alert context: {alert_context}\n\n"
            "Map to MITRE ATT&CK techniques."
        )
        response = self.chat(prompt, system=system, temperature=0.2)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"techniques": [], "summary": response}
