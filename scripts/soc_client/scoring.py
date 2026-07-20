"""Deterministic incident scoring engine with LLM-override support.

Two-layer model:
  Layer 1 — Weighted evidence score from alert features (deterministic, traceable)
  Layer 2 — LLM adjustment with explicit justification (optional, behind grey-zone gate)

Usage:
    from scripts.soc_client.scoring import triage

    result = triage(alert_data, enrichment_results)
    # result["score"] = 0.73, result["tier"] = "high"

The score breakdown can be rendered in the web UI for judge inspection.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Severity/value mappings
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.0,
}

REPUTATION_MAP = {
    "malicious": 1.0,
    "suspicious": 0.7,
    "unknown": 0.3,
    "harmless": 0.0,
    "clean": 0.0,
    "undetected": 0.3,
}

# ---------------------------------------------------------------------------
# Tier boundaries
# ---------------------------------------------------------------------------

TIERS: list[tuple[str, float, float]] = [
    ("critical", 0.80, 1.00),
    ("high", 0.60, 0.79),
    ("medium", 0.30, 0.59),
    ("low", 0.00, 0.29),
]

# ---------------------------------------------------------------------------
# Weight vector
# ---------------------------------------------------------------------------

WEIGHTS = {
    "auth_risk": 0.25,
    "observables_risk": 0.22,
    "behavior_risk": 0.18,
    "asset_risk": 0.15,
    "severity_risk": 0.12,
    "correlation_risk": 0.08,
}


def severity_to_score(severity_label: str) -> float:
    """Map a severity label string to [0, 1]."""
    return SEVERITY_MAP.get(severity_label.lower(), 0.3)


def vt_reputation_to_score(vt_data: dict[str, Any] | None) -> float:
    """Extract max reputation score from a VirusTotal response."""
    if not vt_data or "data" not in vt_data:
        return 0.3
    attrs = vt_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    if not stats:
        return 0.3
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    if total == 0:
        return 0.3
    ratio = (malicious + 0.5 * suspicious) / total
    return min(ratio * 2.0, 1.0)


def abuseipdb_to_score(abuse_data: dict[str, Any] | None) -> float:
    """Extract reputation score from AbuseIPDB response."""
    if not abuse_data:
        return 0.3
    data = abuse_data.get("data", {})
    confidence = data.get("abuseConfidenceScore", 0)
    return confidence / 100.0


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def _extract_auth_risk(alert: dict[str, Any]) -> float:
    signals = 0
    total_signals = 5
    tags = set(alert.get("tags") or [])
    rule_name = (alert.get("rule", {}) or {}).get("name", "").lower()

    if any(t in tags for t in {"impossible-travel", "geo-anomaly"}):
        signals += 1
    if "impossible travel" in rule_name:
        signals += 1
    if any(t in tags for t in {"brute-force", "password-spray", "credential-stuffing"}):
        signals += 1
    if any(t in tags for t in {"mfa-failure", "mfa-bypass"}):
        signals += 1
    if "multiple failed" in rule_name or "failed login" in rule_name:
        signals += 1

    data = alert.get("data", {}) or {}
    failed_count = data.get("failed_logins", 0) or alert.get("failed_logins", 0)
    if isinstance(failed_count, (int, float)) and failed_count > 5:
        signals += 1

    user = alert.get("user", {}) or {}
    if user.get("new_device") or user.get("unusual_location"):
        signals += 1

    return min(signals / total_signals, 1.0)


def _extract_observables_risk(
    alert: dict[str, Any],
    enrichment_results: dict[str, Any] | None,
) -> float:
    if not enrichment_results:
        return 0.3
    max_score = 0.0
    platform_count = 0
    for ioc_type, platforms in enrichment_results.items():
        if not isinstance(platforms, dict):
            continue
        for platform_name, result in platforms.items():
            if not isinstance(result, dict):
                continue
            if "error" in result:
                continue
            platform_count += 1
            if platform_name == "virustotal":
                max_score = max(max_score, vt_reputation_to_score(result))
            elif platform_name == "abuseipdb":
                max_score = max(max_score, abuseipdb_to_score(result))
    if platform_count == 0:
        return 0.3
    return max_score


def _extract_behavior_risk(alert: dict[str, Any]) -> float:
    signals = 0
    total_signals = 5
    tags = set(alert.get("tags") or [])
    data = alert.get("data", {}) or {}
    rule_name = (alert.get("rule", {}) or {}).get("name", "").lower()

    if any(t in tags for t in {"suspicious-process", "process-injection", "lsass-access"}):
        signals += 1
    if any(t in tags for t in {"mailbox-rule", "email-forwarding", "o365-anomaly"}):
        signals += 1
    if any(t in tags for t in {"persistence", "registry-modification", "scheduled-task"}):
        signals += 1
    if "powershell" in rule_name or any(k in data for k in ("powershell_cmdline", "script_block")):
        signals += 1
    if data.get("parent_process") and data["parent_process"] in ("winword.exe", "excel.exe", "outlook.exe"):
        signals += 1

    return min(signals / total_signals, 1.0)


def _extract_asset_risk(alert: dict[str, Any]) -> float:
    agent = alert.get("agent", {}) or {}
    user = alert.get("user", {}) or {}
    data = alert.get("data", {}) or {}
    score = 0.0

    hostname = (agent.get("name") or data.get("hostname") or "").lower()
    if any(kw in hostname for kw in {"dc", "domain-controller", "ad-"}):
        score = max(score, 1.0)
    if any(kw in hostname for kw in {"sql", "db-", "exchange", "mail"}):
        score = max(score, 0.8)

    user_name = (user.get("name") or data.get("user") or "").lower()
    privileged_keywords = {"admin", "administrator", "root", "sa_", "svc_", "domain-admin"}
    if any(kw in user_name for kw in privileged_keywords):
        score = max(score, 0.9)

    asset_tags = set(agent.get("tags", []) if isinstance(agent, dict) else [])
    if "critical" in asset_tags or "domain-controller" in asset_tags:
        score = max(score, 1.0)
    if "server" in asset_tags or "production" in asset_tags:
        score = max(score, 0.7)

    return score


def _extract_severity_risk(alert: dict[str, Any]) -> float:
    severity = alert.get("severity") or (alert.get("rule", {}) or {}).get("severity", "info")
    return severity_to_score(str(severity))


def _extract_correlation_risk(
    alert: dict[str, Any],
    enrichment_results: dict[str, Any] | None,
) -> float:
    auth = _extract_auth_risk(alert)
    behavior = _extract_behavior_risk(alert)
    observables = _extract_observables_risk(alert, enrichment_results)
    moderate_signals = sum(1 for v in [auth, behavior, observables] if 0.3 <= v <= 0.6)
    high_signals = sum(1 for v in [auth, behavior, observables] if v > 0.6)
    if moderate_signals >= 2:
        return 0.6
    if moderate_signals >= 1 and high_signals >= 1:
        return 0.8
    if high_signals >= 2:
        return 1.0
    return 0.0


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_features(
    alert: dict[str, Any],
    enrichment_results: dict[str, Any] | None = None,
) -> dict[str, float]:
    return {
        "auth_risk": _extract_auth_risk(alert),
        "observables_risk": _extract_observables_risk(alert, enrichment_results),
        "behavior_risk": _extract_behavior_risk(alert),
        "asset_risk": _extract_asset_risk(alert),
        "severity_risk": _extract_severity_risk(alert),
        "correlation_risk": _extract_correlation_risk(alert, enrichment_results),
    }


# ---------------------------------------------------------------------------
# Confidence interval
# ---------------------------------------------------------------------------


def _compute_confidence_interval(features: dict[str, float]) -> tuple[float, float]:
    scored = sum(1 for v in features.values() if v is not None and v not in (0.0, 0.3))
    total = max(len(features), 1)
    coverage = scored / total
    if coverage >= 0.8:
        half_width = 0.05
    elif coverage >= 0.5:
        half_width = 0.12
    elif coverage >= 0.25:
        half_width = 0.20
    else:
        half_width = 0.30
    return (half_width, half_width)


# ---------------------------------------------------------------------------
# Tier lookup
# ---------------------------------------------------------------------------


def score_to_tier(score: float) -> str:
    for tier, lo, hi in TIERS:
        if lo <= score <= hi:
            return tier
    return "low"


def get_tier_boundaries(tier: str) -> tuple[float, float]:
    for t, lo, hi in TIERS:
        if t == tier:
            return (lo, hi)
    return (0.0, 0.29)


# ---------------------------------------------------------------------------
# Grey-zone detection
# ---------------------------------------------------------------------------


def should_trigger_llm_review(score: float, ci_half_width: float) -> bool:
    ci_lower = max(0.0, score - ci_half_width)
    ci_upper = min(1.0, score + ci_half_width)
    current_tier = score_to_tier(score)
    _, current_lo, current_hi = next((t, lo, hi) for t, lo, hi in TIERS if t == current_tier)
    tier_idx = [t for t, _, _ in TIERS].index(current_tier)
    if tier_idx > 0:
        _, above_lo, _ = TIERS[tier_idx - 1]
        if ci_upper >= above_lo:
            return True
    if tier_idx < len(TIERS) - 1:
        _, _, below_hi = TIERS[tier_idx + 1]
        if ci_lower <= below_hi:
            return True
    return False


# ---------------------------------------------------------------------------
# LLM adjustment
# ---------------------------------------------------------------------------


def apply_llm_adjustment(
    deterministic_score: float,
    llm_json: dict[str, Any] | None,
) -> tuple[float, str | None]:
    if not llm_json:
        return deterministic_score, None
    adjusted = llm_json.get("adjusted_score")
    if adjusted is None:
        return deterministic_score, None
    if not isinstance(adjusted, (int, float)) or not (0.0 <= adjusted <= 1.0):
        return deterministic_score, None
    reason = llm_json.get("adjustment_reason") or "LLM override without explicit reason"
    return float(adjusted), str(reason)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def triage(
    alert: dict[str, Any],
    enrichment_results: dict[str, Any] | None = None,
    llm_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    features = normalize_features(alert, enrichment_results)
    score = sum(WEIGHTS[k] * v for k, v in features.items())
    score = max(0.0, min(1.0, score))
    ci_lo_half, ci_hi_half = _compute_confidence_interval(features)
    ci_lower = max(0.0, score - ci_lo_half)
    ci_upper = min(1.0, score + ci_hi_half)
    needs_review = should_trigger_llm_review(score, ci_lo_half)
    final_score, llm_reason = apply_llm_adjustment(score, llm_override)
    final_tier = score_to_tier(final_score)

    breakdown = []
    for k, w in sorted(WEIGHTS.items(), key=lambda x: -x[1]):
        v = features.get(k, 0.0)
        breakdown.append({
            "feature": k,
            "weight": w,
            "value": v,
            "contribution": round(w * v, 4),
            "label": _feature_label(k, alert),
        })

    ci_half_width_used = (ci_lo_half + ci_hi_half) / 2
    active_signals = sum(1 for v in features.values() if v > 0)
    summary_lines = [
        f"Triage score: {final_score:.2f} ({final_tier})",
        f"Deterministic score: {score:.2f} from {active_signals} active signals across {len(WEIGHTS)} dimensions.",
        f"Confidence interval: [{ci_lower:.2f}, {ci_upper:.2f}]",
        f"Deterministic tier: {score_to_tier(score)} | Final tier: {final_tier}",
    ]
    if needs_review:
        summary_lines.append("Grey-zone: confidence interval overlaps adjacent tier. Recommend LLM review.")
    else:
        summary_lines.append("Sufficient data: deterministic score is stable within its tier.")
    summary = " | ".join(summary_lines)

    return {
        "score": round(final_score, 4),
        "tier": final_tier,
        "confidence_interval": [round(ci_lower, 4), round(ci_upper, 4)],
        "ci_half_width": round(ci_half_width_used, 4),
        "features": {k: round(v, 4) for k, v in features.items()},
        "deterministic_score": round(score, 4),
        "deterministic_tier": score_to_tier(score),
        "summary": summary,
        "llm_adjusted": llm_override is not None and llm_override.get("adjusted_score") is not None,
        "llm_reason": llm_reason,
        "should_trigger_llm": needs_review,
        "breakdown": breakdown,
    }


def _feature_label(key: str, alert: dict[str, Any]) -> str:
    labels = {
        "auth_risk": "Authentication Anomaly",
        "observables_risk": "IOC Reputation",
        "behavior_risk": "Behavioral Signal",
        "asset_risk": "Asset Criticality",
        "severity_risk": "Alert Severity",
        "correlation_risk": "Signal Correlation",
    }
    return labels.get(key, key.replace("_", " ").title())
