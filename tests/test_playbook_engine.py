"""Tests for the playbook engine."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import TestCase

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.playbook_engine import (
    PlaybookRunner,
    evaluate_condition,
    load_playbook,
    render,
)


class RenderTests(TestCase):
    def test_simple_variable(self):
        ctx = {"name": "test-alert"}
        self.assertEqual(render("Alert: {name}", ctx), "Alert: test-alert")

    def test_nested_variable(self):
        ctx = {"step": {"classify": {"confidence": "high"}}}
        self.assertEqual(
            render("Confidence: {step.classify.confidence}", ctx),
            "Confidence: high",
        )

    def test_equality_check(self):
        ctx = {"ioc": {"type": "ip"}}
        self.assertEqual(render("{ioc.type == 'ip'}", ctx), "True")
        self.assertEqual(render("{ioc.type == 'domain'}", ctx), "False")

    def test_missing_variable_preserved(self):
        ctx = {}
        self.assertEqual(render("Value: {missing}", ctx), "Value: {missing}")

    def test_list_rendering(self):
        ctx = {"a": "1", "b": "2"}
        result = render(["{a}", "{b}", "static"], ctx)
        self.assertEqual(result, ["1", "2", "static"])

    def test_dict_rendering(self):
        ctx = {"key": "value"}
        result = render({"field": "{key}"}, ctx)
        self.assertEqual(result, {"field": "value"})

    def test_numeric_comparison(self):
        ctx = {"score": 0.8}
        self.assertEqual(render("{score > 0.5}", ctx), "True")
        self.assertEqual(render("{score < 0.5}", ctx), "False")

    def test_in_operator(self):
        ctx = {"severity": "high"}
        self.assertEqual(
            render("{severity in ['high', 'critical']}", ctx), "True"
        )
        self.assertEqual(
            render("{severity in ['low', 'medium']}", ctx), "False"
        )


class ConditionTests(TestCase):
    def test_gt(self):
        self.assertTrue(evaluate_condition("score > 0.5", {"score": 0.8}))

    def test_lt(self):
        self.assertTrue(evaluate_condition("score < 0.5", {"score": 0.3}))

    def test_eq(self):
        self.assertTrue(evaluate_condition("status == 'active'", {"status": "active"}))

    def test_neq(self):
        self.assertTrue(evaluate_condition("status != 'closed'", {"status": "active"}))

    def test_in_list(self):
        ctx = {"severity": "high"}
        self.assertTrue(evaluate_condition("severity in ['high', 'critical']", ctx))
        self.assertFalse(evaluate_condition("severity in ['low', 'medium']", ctx))

    def test_gte(self):
        self.assertTrue(evaluate_condition("score >= 0.8", {"score": 0.8}))
        self.assertTrue(evaluate_condition("score >= 0.7", {"score": 0.8}))

    def test_missing_variable(self):
        self.assertFalse(evaluate_condition("missing > 5", {}))


class PlaybookLoadTests(TestCase):
    def test_load_yaml(self):
        content = """
id: test-v1
name: Test Playbook
steps:
  - id: step1
    type: llm
    prompt: "test prompt"
"""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(content)
            f.flush()
            result = load_playbook(Path(f.name))
        self.assertEqual(result["id"], "test-v1")
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(result["steps"][0]["type"], "llm")


class PlaybookRunnerTests(TestCase):
    def _make_runner(self, steps, context=None):
        playbook = {
            "id": "test",
            "name": "Test",
            "steps": steps,
        }
        return PlaybookRunner(playbook, context or {})

    def test_llm_step(self):
        runner = self._make_runner([
            {"id": "analyze", "type": "llm", "prompt": "classify this alert"}
        ])
        result = runner.run()
        self.assertIn("analyze", result["steps"])
        self.assertEqual(result["steps"]["analyze"]["type"], "llm")
        self.assertEqual(result["steps"]["analyze"]["status"], "pending_agent_execution")

    def test_toolchain_step(self):
        runner = self._make_runner([
            {
                "id": "enrich",
                "type": "toolchain",
                "run": [
                    {"tool": "virustotal", "operation": "ip", "target": "1.2.3.4"},
                ],
            }
        ])
        result = runner.run()
        self.assertIn("enrich", result["steps"])
        self.assertEqual(result["steps"]["enrich"]["count"], 1)

    def test_rule_skip_to(self):
        runner = self._make_runner(
            [
                {"id": "classify", "type": "llm", "prompt": "test"},
                {
                    "id": "check_fp",
                    "type": "rule",
                    "when": {"condition": "classify.fp_prob > 0.7"},
                    "action": "skip_to",
                    "target": "report",
                },
                {"id": "enrich", "type": "toolchain", "run": []},
                {"id": "report", "type": "report", "report_type": "soc"},
            ],
            context={"classify": {"fp_prob": 0.9}},
        )
        result = runner.run()
        # classify runs, rule triggers skip_to, enrich is skipped, report runs
        self.assertIn("classify", result["steps"])
        self.assertNotIn("enrich", result["steps"])
        self.assertIn("report", result["steps"])
        # Verify skip_to was triggered
        log_entry = [e for e in runner.execution_log if e["step_id"] == "enrich"]
        if log_entry:
            self.assertEqual(log_entry[0]["status"], "skipped_by_branch")

    def test_rule_condition_not_met(self):
        runner = self._make_runner(
            [
                {"id": "classify", "type": "llm", "prompt": "test"},
                {
                    "id": "check_fp",
                    "type": "rule",
                    "when": {"condition": "classify.fp_prob > 0.7"},
                    "action": "skip_to",
                    "target": "report",
                },
                {"id": "enrich", "type": "toolchain", "run": [{"tool": "vt", "operation": "ip", "target": "1.2.3.4"}]},
                {"id": "report", "type": "report", "report_type": "soc"},
            ],
            context={"classify": {"fp_prob": 0.3}},
        )
        result = runner.run()
        # enrich should run because condition not met
        self.assertIn("enrich", result["steps"])
        self.assertIn("report", result["steps"])

    def test_approval_step(self):
        runner = self._make_runner([
            {
                "id": "escalate",
                "type": "approval",
                "when": {"condition": "decide.severity in ['high', 'critical']"},
                "actions": ["isolate_host"],
            }
        ], context={"decide": {"severity": "high"}})
        result = runner.run()
        self.assertTrue(result["steps"]["escalate"]["needs_approval"])

    def test_conditional_step_skipped(self):
        runner = self._make_runner(
            [
                {
                    "id": "optional",
                    "type": "llm",
                    "prompt": "test",
                    "when": {"condition": "always_run == true"},
                }
            ],
            context={"always_run": False},
        )
        result = runner.run()
        self.assertNotIn("optional", result["steps"])

    def test_execution_log(self):
        runner = self._make_runner([
            {"id": "step1", "type": "llm", "prompt": "test"},
        ])
        runner.run()
        self.assertEqual(len(runner.execution_log), 2)
        self.assertEqual(runner.execution_log[0]["step_id"], "step1")
        self.assertEqual(runner.execution_log[0]["status"], "started")
        self.assertEqual(runner.execution_log[1]["status"], "finished")

    def test_error_handling_continues(self):
        runner = self._make_runner([
            {"id": "step1", "type": "unknown_type"},
            {"id": "step2", "type": "llm", "prompt": "test"},
        ])
        result = runner.run()
        self.assertIn("error", result["steps"]["step1"])
        self.assertIn("step2", result["steps"])

    def test_thehive_step(self):
        runner = self._make_runner([
            {
                "id": "case",
                "type": "thehive",
                "action": "create_or_update_case",
                "inputs": {"title": "Test Case"},
            }
        ])
        result = runner.run()
        self.assertEqual(result["steps"]["case"]["action"], "create_or_update_case")


if __name__ == "__main__":
    import unittest
    unittest.main()
