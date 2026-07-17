#!/usr/bin/env bash
# load_secrets.sh — Load credentials from a keys.txt file into environment.
#
# Usage:
#   source scripts/load_secrets.sh /path/to/keys.txt
#
# keys.txt format (one per line):
#   KEY_NAME=value
#   # comments and blank lines are ignored
#
# SECURITY: keys.txt must be OUTSIDE the repo directory.
# Never commit credentials to git.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: source scripts/load_secrets.sh <path-to-keys.txt>"
    echo "  keys.txt must contain lines like: KEY_NAME=value"
    exit 1
fi

KEYS_FILE="$1"

if [ ! -f "$KEYS_FILE" ]; then
    echo "Error: keys file not found: $KEYS_FILE"
    exit 1
fi

# Check file permissions (warn if too permissive on Unix)
if command -v stat >/dev/null 2>&1; then
    PERMS=$(stat -c %a "$KEYS_FILE" 2>/dev/null || stat -f %Lp "$KEYS_FILE" 2>/dev/null || echo "unknown")
    if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ] && [ "$PERMS" != "unknown" ]; then
        echo "Warning: keys file permissions are $PERMS (should be 600 or 400)"
        echo "  Run: chmod 600 $KEYS_FILE"
    fi
fi

LOADED=0
SKIPPED=0

while IFS= read -r line || [ -n "$line" ]; do
    # Skip comments and blank lines
    line=$(echo "$line" | sed 's/#.*//' | xargs)
    [ -z "$line" ] && continue

    # Parse KEY=value
    KEY=$(echo "$line" | cut -d'=' -f1 | xargs)
    VALUE=$(echo "$line" | cut -d'=' -f2- | xargs)

    if [ -z "$KEY" ] || [ -z "$VALUE" ]; then
        echo "  Skipped: $line"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    export "$KEY=$VALUE"
    echo "  Loaded: $KEY"
    LOADED=$((LOADED + 1))

done < "$KEYS_FILE"

echo ""
echo "Loaded $LOADED credential(s), skipped $SKIPPED"
echo "Credentials are in environment variables — do not echo or log them."
