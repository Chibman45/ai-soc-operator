#!/usr/bin/env bash
# check_env.sh — Verify required credential environment variables are set.
#
# Usage:
#   bash scripts/check_env.sh
#
# Checks for all platform credentials used by the AI SOC Operator.
# Exits 0 if all required vars are set, 1 if any are missing.

set -euo pipefail

REQUIRED_VARS=(
    "SHODAN_API_KEY"
    "CENSYS_PAT"
    "VIRUSTOTAL_API_KEY"
    "ABUSEIPDB_API_KEY"
    "URLSCAN_API_KEY"
    "HYBRID_ANALYSIS_API_KEY"
    "THEHIVE_API_KEY"
    "CORTEX_API_KEY"
    "WAZUH_API_TOKEN"
)

OPTIONAL_VARS=(
    "PHISHTANK_APP_KEY"
    "MISP_API_KEY"
    "ANY_RUN_SANDBOX_API_KEY"
    "WAZUH_INDEXER_USERNAME"
    "WAZUH_INDEXER_PASSWORD"
)

echo "=== AI SOC Operator — Environment Check ==="
echo ""

MISSING=0

echo "Required credentials:"
for var in "${REQUIRED_VARS[@]}"; do
    if [ -n "${!var:-}" ]; then
        echo "  ✓ $var is set"
    else
        echo "  ✗ $var is MISSING"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
echo "Optional credentials:"
for var in "${OPTIONAL_VARS[@]}"; do
    if [ -n "${!var:-}" ]; then
        echo "  ✓ $var is set"
    else
        echo "  - $var not set (optional)"
    fi
done

echo ""
if [ $MISSING -gt 0 ]; then
    echo "Result: $MISSING required credential(s) missing"
    echo "Fix: source scripts/load_secrets.sh /path/to/keys.txt"
    exit 1
else
    echo "Result: All required credentials are set"
    exit 0
fi
