"""SOC Orchestrator — end-to-end alert → case → report pipeline.

This is the main entry point for playbook-driven SOC automation.
It coordinates:
1. Alert ingestion (Wazuh, manual, webhook)
2. Playbook loading and execution
3. IOC enrichment through threat intel platforms
4. MITRE ATT&CK mapping
5. TheHive case creation and management
6. Report generation

Usage:
    python3 -m scripts.orchestrator --alert alert.json --playbook playbooks/identity-compromise.yaml
    python3 -m scripts.orchestrator --alert alert.json  # auto-select playbook
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .common import ROOT, Session, audit, utc_now
    from .playbook_engine import PlaybookRunner, load_playbook
    from .soc_client.thehive import TheHiveClient
    from .soc_client.cortex import CortexClient
    from .soc_client.wazuh import WazuhManagerClient, WazuhIndexerClient
    from .soc_client.enrichment import EnrichmentClient
except ImportError:
    from scripts.common import ROOT, Session, audit, utc_now
    from scripts.playbook_engine import PlaybookRunner, load_playbook
    from scripts.soc_client.thehive import TheHiveClient
    from scripts.soc_client.cortex import CortexClient
    from scripts.soc_client.wazuh import WazuhManagerClient, WazuhIndexerClient
    from scripts.soc_client.enrichment import EnrichmentClient


def load_config() -> dict[str, Any]:
    """Load platform configuration."""
    config_path = ROOT / "config" / "platforms.toml"
    if not config_path.is_file():
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore
    with config_path.open("rb") as f:
        return tomllib.load(f)


def build_clients(config: dict[str, Any]) -> dict[str, Any]:
    """Build platform clients from configuration."""
    import os
    clients: dict[str, Any] = {}
    platforms = config.get("platforms", {})

    # TheHive
    thehive_cfg = platforms.get("thehive", {})
    if thehive_cfg.get("enabled"):
        key = os.environ.get(thehive_cfg.get("credential_env", ""), "")
        if key:
            clients["thehive"] = TheHiveClient(thehive_cfg["base_url"], key)

    # Cortex
    cortex_cfg = platforms.get("cortex", {})
    if cortex_cfg.get("enabled"):
        key = os.environ.get(cortex_cfg.get("credential_env", ""), "")
        if key:
            clients["cortex"] = CortexClient(cortex_cfg["base_url"], key)

    # Wazuh Manager
    wazuh_cfg = platforms.get("wazuh_manager", {})
    if wazuh_cfg.get("enabled"):
        key = os.environ.get(wazuh_cfg.get("credential_env", ""), "")
        if key:
            clients["wazuh_manager"] = WazuhManagerClient(
                wazuh_cfg["base_url"], key
            )

    # Wazuh Indexer
    wazuh_idx = platforms.get("wazuh_indexer", {})
    if wazuh_idx.get("enabled"):
        username = os.environ.get(wazuh_idx.get("username_env", ""), "")
        password = os.environ.get(wazuh_idx.get("password_env", ""), "")
        if username and password:
            clients["wazuh_indexer"] = WazuhIndexerClient(
                wazuh_idx["base_url"], username, password
            )

    # Enrichment (aggregates all threat intel platforms)
    if any(
        platforms.get(p, {}).get("enabled")
        for p in ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"]
    ):
        clients["enrichment"] = EnrichmentClient(config)

    return clients


def auto_select_playbook(
    alert: dict[str, Any], playbook_dir: Path
) -> Path | None:
    """Auto-select the best playbook for an alert based on triggers."""
    if not playbook_dir.is_dir():
        return None

    alert_tags = set(alert.get("tags", []))
    alert_rule = alert.get("rule", {}).get("name", "")
    alert_techniques = alert.get("mitre", {}).get("techniques", [])

    best_match: tuple[int, Path] = (0, Path())

    for playbook_file in playbook_dir.glob("*.yaml"):
        try:
            playbook = load_playbook(playbook_file)
        except Exception:
            continue

        score = 0
        triggers = playbook.get("triggers", [])

        for trigger in triggers:
            if "alert_rule" in trigger and trigger["alert_rule"] in alert_rule:
                score += 10
            if "mitre_technique" in trigger:
                if trigger["mitre_technique"] in alert_techniques:
                    score += 15
            if "tags" in trigger:
                trigger_tags = (
                    trigger["tags"]
                    if isinstance(trigger["tags"], list)
                    else [trigger["tags"]]
                )
                overlap = set(trigger_tags) & alert_tags
                score += len(overlap) * 5

        if score > best_match[0]:
            best_match = (score, playbook_file)

    if best_match[0] > 0:
        return best_match[1]
    return None


def extract_iocs(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Extract IOCs from alert data."""
    iocs = []

    # From alert data
    for field_path in [
        ("source", "ip"),
        ("destination", "ip"),
        ("src_ip",),
        ("dst_ip",),
    ]:
        value = alert
        for key in field_path:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                value = None
                break
        if value and isinstance(value, str):
            iocs.append({"type": "ip", "value": value})

    # From hashes
    for hash_field in ["md5", "sha1", "sha256"]:
        value = alert.get(hash_field) or alert.get("data", {}).get(hash_field)
        if value:
            iocs.append({"type": "hash", "value": value})

    # From domains
    for field in ["hostname", "domain"]:
        value = alert.get(field) or alert.get("data", {}).get(field)
        if value:
            iocs.append({"type": "domain", "value": value})

    # From user
    user = alert.get("user", {}).get("name") or alert.get("user_name")
    if user:
        iocs.append({"type": "user", "value": user})

    return iocs


def execute_playbook(
    playbook_path: Path,
    alert: dict[str, Any],
    clients: dict[str, Any],
    session: Session,
) -> dict[str, Any]:
    """Execute a playbook against an alert."""
    playbook = load_playbook(playbook_path)

    # Build initial context from alert
    iocs = extract_iocs(alert)
    context: dict[str, Any] = {
        "alert": alert,
        "observables": iocs,
        "iocs": iocs,
        "session": {
            "id": session.session_id,
            "mode": session.mode,
            "target": session.target,
        },
    }

    # Extract common alert fields into top-level context
    if "rule" in alert:
        context["rule"] = alert["rule"]
    if "agent" in alert:
        context["agent"] = alert["agent"]

    # Run the playbook
    runner = PlaybookRunner(playbook, context, clients)
    result = runner.run()

    # Post-execution: generate report if not already done
    if "generate_report" not in result.get("steps", {}):
        report_path = session.path("reports") / "soc-report.md"
        _generate_summary_report(result, session, report_path)
        result["report_path"] = str(report_path)

    return result


def _generate_summary_report(
    playbook_result: dict[str, Any],
    session: Session,
    output_path: Path,
) -> None:
    """Generate a summary report from playbook execution results."""
    steps = playbook_result.get("steps", {})
    execution_log = playbook_result.get("execution_log", [])

    lines = [
        "# SOC Investigation Report",
        "",
        f"**Generated (UTC):** {utc_now()}",
        f"**Session:** `{session.session_id}`",
        f"**Playbook:** {playbook_result.get('playbook_name', 'Unknown')}",
        f"**Target:** {session.target}",
        f"**Mode:** {session.mode}",
        "",
        "## Execution Summary",
        "",
        "| Step | Type | Status |",
        "|---|---|---|",
    ]

    for entry in execution_log:
        status_icon = {
            "finished": "✅",
            "skipped": "⏭️",
            "skipped_by_branch": "🔀",
            "failed": "❌",
            "started": "🔄",
        }.get(entry["status"], "❓")
        lines.append(
            f"| {entry['step_id']} | {entry['step_type']} | {status_icon} {entry['status']} |"
        )

    lines.extend(["", "## Findings", ""])

    # Add LLM analysis results
    for step_id, result in steps.items():
        if isinstance(result, dict) and result.get("type") == "llm":
            lines.append(f"### {step_id}")
            if "analysis" in result:
                lines.append(result["analysis"])
            elif "prompt" in result:
                lines.append(f"*Analysis pending for: {result['prompt'][:200]}...*")
            lines.append("")

    # Add enrichment results
    for step_id, result in steps.items():
        if isinstance(result, dict) and "results" in result:
            tool_results = result.get("results", [])
            if tool_results:
                lines.append(f"### {step_id}")
                for tr in tool_results:
                    lines.append(
                        f"- **{tr.get('tool', 'unknown')}** ({tr.get('operation', '')}): "
                        f"`{tr.get('target', '')}` — {tr.get('status', 'pending')}"
                    )
                lines.append("")

    # Add TheHive case info
    for step_id, result in steps.items():
        if isinstance(result, dict) and result.get("type") == "thehive":
            lines.append(f"### {step_id}")
            if "case_id" in result:
                lines.append(f"- **Case ID:** `{result['case_id']}`")
            lines.append(f"- **Action:** {result.get('action', 'unknown')}")
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    audit("report_generated", session_id=session.session_id, output=str(output_path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI SOC Operator — playbook-driven SOC automation"
    )
    parser.add_argument(
        "--alert",
        type=Path,
        required=True,
        help="Path to alert JSON file",
    )
    parser.add_argument(
        "--playbook",
        type=Path,
        help="Path to playbook YAML (auto-selected if not specified)",
    )
    parser.add_argument(
        "--playbook-dir",
        type=Path,
        default=ROOT / "playbooks",
        help="Directory containing playbooks",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "config" / "platforms.toml",
        help="Platform configuration file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute playbook without making API calls",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for results JSON",
    )
    args = parser.parse_args()

    # Load alert
    if not args.alert.is_file():
        print(f"Error: Alert file not found: {args.alert}", file=sys.stderr)
        return 1
    alert = json.loads(args.alert.read_text(encoding="utf-8"))

    # Select playbook
    playbook_path = args.playbook
    if not playbook_path:
        playbook_path = auto_select_playbook(alert, args.playbook_dir)
        if not playbook_path:
            print(
                "Error: No matching playbook found. "
                "Specify one with --playbook or check triggers in playbooks/",
                file=sys.stderr,
            )
            return 1
        print(f"Auto-selected playbook: {playbook_path}")

    if not playbook_path.is_file():
        print(f"Error: Playbook not found: {playbook_path}", file=sys.stderr)
        return 1

    # Load config and build clients
    config = load_config()
    clients = build_clients(config)

    # Start session
    alert_title = alert.get("rule", {}).get("name", alert.get("title", "Unknown alert"))
    session = Session(
        mode="SOC_ANALYST",
        target=alert.get("agent", {}).get("name", "unknown"),
        purpose=f"Playbook execution for: {alert_title}",
    )

    print(f"Session: {session.session_id}")
    print(f"Playbook: {playbook_path.name}")
    print(f"Alert: {alert_title}")

    # Execute playbook
    try:
        result = execute_playbook(playbook_path, alert, clients, session)
    except Exception as e:
        audit("orchestrator_failed", session_id=session.session_id, error=str(e))
        print(f"Error during playbook execution: {e}", file=sys.stderr)
        session.finish()
        return 1

    # Save results
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Results saved to: {args.output}")

    # Print summary
    steps = result.get("steps", {})
    print(f"\nPlaybook completed: {len(steps)} steps executed")
    for step_id, step_result in steps.items():
        if isinstance(step_result, dict):
            status = step_result.get("status", "unknown")
            if "error" in step_result:
                print(f"  ❌ {step_id}: {step_result['error']}")
            else:
                print(f"  ✅ {step_id}: {status}")

    session.finish()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
