#!/usr/bin/env bash
# Phase 6: Gist Analysis
# Inherits: USERNAME, LOG_LEVEL, TMP_DIR from env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/logging.sh
source "$SCRIPT_DIR/../lib/logging.sh"
# shellcheck source=../lib/api.sh
source "$SCRIPT_DIR/../lib/api.sh"
# shellcheck source=../lib/findings.sh
source "$SCRIPT_DIR/../lib/findings.sh"

: "${USERNAME:?USERNAME env var required}"

log_info "gists: scanning public gists for $USERNAME"

GISTS=$(api_get_all "https://api.github.com/users/${USERNAME}/gists?per_page=100")

if ! echo "$GISTS" | jq empty 2>/dev/null; then
    log_err "gists: invalid API response"
    exit 1
fi

GIST_COUNT=$(echo "$GISTS" | jq 'length')
log_info "gists: found $GIST_COUNT public gist(s)"

if [[ "$GIST_COUNT" -eq 0 ]]; then
    exit 0
fi

while IFS= read -r gist_json; do
    GIST_ID=$(echo "$gist_json" | jq -r '.id')
    DESCRIPTION=$(echo "$gist_json" | jq -r '.description // ""')

    while IFS= read -r email; do
        [[ -z "$email" ]] && continue
        emit_finding "gists" "medium" "email_in_description" \
            "gist:$GIST_ID" "$email" \
            "Email address found in gist description" \
            "https://gist.github.com/$USERNAME/$GIST_ID"
    done < <(echo "$DESCRIPTION" | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' || true)

    while IFS= read -r filename; do
        [[ -z "$filename" ]] && continue
        case "$filename" in
            *.env*|*credential*|*secret*|*password*|*token*|*.pem|*.key)
                emit_finding "gists" "high" "sensitive_file" \
                    "gist:$GIST_ID" "$filename" \
                    "Sensitive filename in gist" \
                    "https://gist.github.com/$USERNAME/$GIST_ID"
                ;;
        esac
    done < <(echo "$gist_json" | jq -r '.files | objects | keys[]' 2>/dev/null || true)

done < <(echo "$GISTS" | jq -c '.[] | objects')

log_debug "gists: scan complete"
