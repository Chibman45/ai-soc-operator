"""Playbook execution engine.

Loads YAML playbooks, resolves inputs from alert data,
and executes steps in sequence. The agent IS the execution engine —
this module provides the structured step runner, variable resolution,
and branching logic.

Step types:
- llm: agent analysis (classification, summarization, decision-making)
- toolchain: calls to platform APIs (enrichment, lookup)
- rule: conditional branching (skip_to, continue)
- thehive: case management operations
- mitre_mapping: ATT&CK technique mapping
- approval: human approval gate
- report: report generation
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    from .common import ROOT, audit, utc_now
except ImportError:
    from common import ROOT, audit, utc_now

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


def load_playbook(path: Path) -> dict[str, Any]:
    """Load a playbook from YAML or TOML."""
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise RuntimeError(
                "PyYAML is required for YAML playbooks. "
                "Install with: pip install pyyaml"
            )
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    with path.open("rb") as f:
        return tomllib.load(f)


def render(template: Any, context: dict[str, Any]) -> Any:
    """Resolve {variable} references in strings, pass through others.

    Supports dot notation: {step.classify.confidence}
    Supports simple expressions: {ioc.type == 'ip'}
    """
    if isinstance(template, str):
        def _replace(match: re.Match) -> str:
            expr = match.group(1).strip()
            # Handle equality checks: ioc.type == 'ip'
            if "in" in expr and "[" in expr:
                in_match = re.match(r"(.+?)\s+in\s+\[(.+)\]", expr)
                if in_match:
                    left_expr, right_expr = in_match.groups()
                    left_val = _resolve(left_expr.strip(), context)
                    right_vals = [v.strip().strip("'\"") for v in right_expr.split(",")]
                    return str(left_val in right_vals)
            if "==" in expr:
                left, right = expr.split("==", 1)
                left_val = _resolve(left.strip(), context)
                right_val = right.strip().strip("'\"")
                return str(left_val == right_val)
            if "!=" in expr:
                left, right = expr.split("!=", 1)
                left_val = _resolve(left.strip(), context)
                right_val = right.strip().strip("'\"")
                return str(left_val != right_val)
            if ">" in expr:
                left, right = expr.split(">", 1)
                left_val = _resolve(left.strip(), context)
                right_val = right.strip()
                try:
                    return str(float(left_val) > float(right_val))
                except (ValueError, TypeError):
                    return "False"
            if "<" in expr:
                left, right = expr.split("<", 1)
                left_val = _resolve(left.strip(), context)
                right_val = right.strip()
                try:
                    return str(float(left_val) < float(right_val))
                except (ValueError, TypeError):
                    return "False"
            # Simple variable resolution
            value = _resolve(expr, context)
            return str(value) if value is not None else match.group(0)

        return re.sub(r"\{([^}]+)\}", _replace, template)
    if isinstance(template, list):
        return [render(item, context) for item in template]
    if isinstance(template, dict):
        return {k: render(v, context) for k, v in template.items()}
    return template


def _resolve(path: str, context: dict[str, Any]) -> Any:
    """Resolve a dotted path against the context.

    Supports:
    - Direct context keys: "alert.title"
    - Step results: "classify.fp_prob" (looks up steps.classify.fp_prob)
    - Nested access: "alert.user.name"
    """
    parts = path.split(".")
    # First try direct context lookup
    value: Any = context
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = None
            break
    if value is not None:
        return value
    # Fall back to steps namespace for step result references
    steps = context.get("steps", {})
    first = parts[0]
    if first in steps and isinstance(steps[first], dict):
        value = steps[first]
        for part in parts[1:]:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value
    return None


def evaluate_condition(condition_str: str, context: dict[str, Any]) -> bool:
    """Evaluate a simple condition against the context.

    Supports: ==, !=, >, <, >=, <=, in [...]
    Examples:
        "classify.false_positive_probability > 0.7"
        "decide.severity in ['high', 'critical']"
        "classify.confidence == 'high'"
    """
    condition = condition_str.strip()

    # Handle 'in' operator: "value in [list]"
    in_match = re.match(r"(.+?)\s+in\s+\[(.+)\]", condition)
    if in_match:
        left_expr, right_expr = in_match.groups()
        left_val = _resolve(left_expr.strip(), context)
        right_vals = [
            v.strip().strip("'\"") for v in right_expr.split(",")
        ]
        return str(left_val) in right_vals

    # Handle comparison operators (longest first to avoid >= matching >)
    for op in (">=", "<=", "!=", "==", ">", "<"):
        if op in condition:
            left, right = condition.split(op, 1)
            left_val = _resolve(left.strip(), context)
            right_val = right.strip().strip("'\"")
            try:
                if op == ">=":
                    return float(left_val) >= float(right_val)
                if op == "<=":
                    return float(left_val) <= float(right_val)
                if op == "!=":
                    return str(left_val) != right_val
                if op == "==":
                    return str(left_val) == right_val
                if op == ">":
                    return float(left_val) > float(right_val)
                if op == "<":
                    return float(left_val) < float(right_val)
            except (ValueError, TypeError):
                return False

    return False


class PlaybookRunner:
    """Execute a playbook step by step.

    The runner provides structured execution with:
    - Sequential step processing
    - Variable resolution between steps
    - Conditional branching (skip_to)
    - Audit logging for every step
    - Graceful error handling (continues on failure)
    """

    def __init__(
        self,
        playbook: dict[str, Any],
        context: dict[str, Any],
        clients: dict[str, Any] | None = None,
    ):
        self.playbook = playbook
        self.context = context
        self.clients = clients or {}
        self.results: dict[str, Any] = {}
        self.execution_log: list[dict[str, Any]] = []

    def run(self) -> dict[str, Any]:
        steps = self.playbook.get("steps", [])
        skip_to: str | None = None

        for step in steps:
            step_id = step.get("id", "unknown")
            step_type = step.get("type", "unknown")

            # Handle skip_to targeting
            if skip_to and step_id != skip_to:
                self._log(step_id, step_type, "skipped_by_branch", "skip_to active")
                continue
            if skip_to and step_id == skip_to:
                skip_to = None

            # Check step-level condition
            if not self._should_run(step):
                self._log(step_id, step_type, "skipped", "condition not met")
                audit("playbook_step_skipped", step=step_id, reason="condition_not_met")
                continue

            audit("playbook_step_started", step=step_id, type=step_type)
            self._log(step_id, step_type, "started")

            try:
                if step_type == "llm":
                    result = self._run_llm(step)
                elif step_type == "toolchain":
                    result = self._run_toolchain(step)
                elif step_type == "rule":
                    result, new_skip = self._run_rule(step)
                    if new_skip:
                        skip_to = new_skip
                elif step_type == "thehive":
                    result = self._run_thehive(step)
                elif step_type == "mitre_mapping":
                    result = self._run_mitre(step)
                elif step_type == "approval":
                    result = self._run_approval(step)
                elif step_type == "report":
                    result = self._run_report(step)
                else:
                    result = {"error": f"Unknown step type: {step_type}"}

                self.results[step_id] = result
                # Store step results under "steps" namespace to avoid
                # overwriting explicitly provided context values.
                if isinstance(result, dict):
                    self.context.setdefault("steps", {})[step_id] = result

                self._log(step_id, step_type, "finished")
                audit("playbook_step_finished", step=step_id, type=step_type)

            except Exception as e:
                error_result = {"error": str(e)}
                self.results[step_id] = error_result
                self.context[step_id] = error_result
                self._log(step_id, step_type, "failed", str(e))
                audit("playbook_step_failed", step=step_id, error=str(e))
                continue

        return {
            "playbook_id": self.playbook.get("id", "unknown"),
            "playbook_name": self.playbook.get("name", "unknown"),
            "steps": self.results,
            "execution_log": self.execution_log,
            "completed_at": utc_now(),
        }

    def _should_run(self, step: dict[str, Any]) -> bool:
        when = step.get("when")
        if not when:
            return True
        condition = when.get("condition", "")
        if not condition:
            return True
        return evaluate_condition(condition, self.context)

    def _run_llm(self, step: dict[str, Any]) -> dict[str, Any]:
        prompt = render(step.get("prompt", ""), self.context)

        # Try direct GPT-5.6 API call if OpenAI client is available
        openai_client = self.clients.get("openai")
        if openai_client:
            try:
                response = openai_client.chat(prompt, temperature=0.2)
                audit("playbook_llm_gpt56", step=step.get("id"), model="gpt-5.6")
                return {
                    "type": "llm",
                    "model": "gpt-5.6",
                    "prompt": prompt,
                    "response": response,
                    "status": "completed",
                }
            except Exception as e:
                audit("playbook_llm_fallback", step=step.get("id"), error=str(e))
                # Fall through to agent execution

        return {
            "type": "llm",
            "prompt": prompt,
            "status": "pending_agent_execution",
            "instruction": "Agent should analyze the prompt and produce structured output.",
        }

    def _run_toolchain(self, step: dict[str, Any]) -> dict[str, Any]:
        tools = step.get("run", [])
        results = []
        for tool_def in tools:
            tool = render(tool_def.get("tool", ""), self.context)
            operation = render(tool_def.get("operation", ""), self.context)
            target = render(tool_def.get("target", ""), self.context)
            condition = tool_def.get("condition")
            if condition and not evaluate_condition(condition, self.context):
                continue
            results.append({
                "tool": tool,
                "operation": operation,
                "target": target,
                "status": "queued",
            })
        return {"results": results, "count": len(results)}

    def _run_rule(
        self, step: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None]:
        when = step.get("when", {})
        condition = when.get("condition", "")
        action = step.get("action", "")
        target = step.get("target", "")
        if condition and evaluate_condition(condition, self.context):
            if action == "skip_to":
                return {"action": "skip_to", "target": target}, target
        return {"action": "continue"}, None

    def _run_thehive(self, step: dict[str, Any]) -> dict[str, Any]:
        action = step.get("action", "")
        return {
            "type": "thehive",
            "action": action,
            "inputs": render(step.get("inputs", {}), self.context),
            "status": "pending_execution",
        }

    def _run_mitre(self, step: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "mitre_mapping",
            "status": "pending_script_execution",
            "script": "scripts/mitre_attack.py map-evidence",
        }

    def _run_approval(self, step: dict[str, Any]) -> dict[str, Any]:
        when = step.get("when", {})
        actions = step.get("actions", [])
        condition = when.get("condition", "")
        needs_approval = not condition or evaluate_condition(condition, self.context)
        return {
            "type": "approval",
            "actions": actions,
            "needs_approval": needs_approval,
            "status": "pending_human_approval" if needs_approval else "auto_approved",
        }

    def _run_report(self, step: dict[str, Any]) -> dict[str, Any]:
        report_type = render(step.get("type", "soc"), self.context)
        return {
            "type": "report",
            "report_type": report_type,
            "status": "pending_generation",
        }

    def _log(
        self,
        step_id: str,
        step_type: str,
        status: str,
        detail: str = "",
    ) -> None:
        entry = {
            "timestamp": utc_now(),
            "step_id": step_id,
            "step_type": step_type,
            "status": status,
        }
        if detail:
            entry["detail"] = detail
        self.execution_log.append(entry)
