"""Tests for the curated vendor knowledge injected into AI recommendations."""

from __future__ import annotations

import json
import unittest

from web.services.chat import chat_completion
from web.services.platform_knowledge import (
    load_platform_catalog,
    platform_knowledge_context,
    platform_sources,
)


class PlatformKnowledgeTests(unittest.TestCase):
    def test_catalog_covers_every_configured_integration(self):
        expected = {
            "wazuh", "thehive", "cortex", "misp", "virustotal", "abuseipdb",
            "shodan", "urlscan", "hybrid_analysis", "phishtank", "openai_codex",
        }
        self.assertEqual(set(load_platform_catalog()), expected)

    def test_context_is_relevant_bounded_and_source_linked(self):
        context = platform_knowledge_context(
            platforms=["wazuh"],
            query="review duplicate rule ids and decoder coverage",
            max_chars=3000,
        )
        self.assertIn("Wazuh Manager and Indexer", context)
        self.assertIn("documentation.wazuh.com", context)
        self.assertNotIn("VirusTotal API", context)
        self.assertLessEqual(len(context), 3000)

    def test_sources_are_structured_https_links(self):
        sources = platform_sources("thehive")
        self.assertGreaterEqual(len(sources), 3)
        self.assertTrue(all(source["url"].startswith("https://") for source in sources))

    def test_chat_system_prompt_receives_matching_vendor_context(self):
        class CapturingClient:
            def __init__(self):
                self.system = ""

            def chat(self, _prompt, *, system, temperature, max_tokens):
                self.system = system
                return json.dumps({"reasoning": [], "answer": "reviewed", "citations": [], "suggested_actions": []})

        client = CapturingClient()
        response = chat_completion(
            {"source": "wazuh", "alerts": []},
            [],
            "How should I review this Wazuh rule?",
            ai_client=client,
        )
        self.assertEqual(response["answer"], "reviewed")
        self.assertIn("Wazuh custom rules", client.system)
        self.assertIn("cannot authorize tools", client.system)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
