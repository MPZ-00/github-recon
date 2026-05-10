#!/usr/bin/env bash
# Scans a GitHub user's public profile for exposed PII and emits JSON findings.
# Usage: USERNAME=<user> [GITHUB_TOKEN=<tok>] [LOG_LEVEL=verbose] bash modules/profile.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$(dirname "$SCRIPT_DIR")/lib"

# Source lib helpers if present; otherwise define minimal fallbacks.
if [[ -f "$LIB_DIR/api.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/api.sh"
fi
if [[ -f "$LIB_DIR/log.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/log.sh"
fi

USERNAME="${USERNAME:-}"
LOG_LEVEL="${LOG_LEVEL:-info}"
PRIMARY_EMAIL="${PRIMARY_EMAIL:-}"

_log() {
    local level="$1"; shift
    [[ "$LOG_LEVEL" == "verbose" || "$level" != "debug" ]] && echo "[profile] $*" >&2 || true
}

if [[ -z "$USERNAME" ]]; then
    echo "[profile] ERROR: USERNAME is not set" >&2
    exit 1
fi

# api_get may already be defined by lib/api.sh; only define if missing.
if ! declare -f api_get > /dev/null 2>&1; then
    api_get() {
        local url="$1"
        local auth_header=""
        [[ -n "${GITHUB_TOKEN:-}" ]] && auth_header="Authorization: token ${GITHUB_TOKEN}"
        if [[ -n "$auth_header" ]]; then
            curl -sSL -H "$auth_header" -H "Accept: application/vnd.github+json" "$url"
        else
            curl -sSL -H "Accept: application/vnd.github+json" "$url"
        fi
    }
fi

_log debug "Fetching profile for $USERNAME"
PROFILE=$(api_get "https://api.github.com/users/${USERNAME}")

if ! echo "$PROFILE" | jq empty 2>/dev/null; then
    echo "[profile] ERROR: invalid JSON from GitHub API" >&2
    exit 1
fi

if echo "$PROFILE" | jq -e '.message' > /dev/null 2>&1; then
    msg=$(echo "$PROFILE" | jq -r '.message')
    echo "[profile] ERROR: GitHub API: $msg" >&2
    exit 1
fi

emit() {
    local field="$1" value="$2" severity="$3"
    jq -n \
        --arg module   "profile" \
        --arg field    "$field" \
        --arg value    "$value" \
        --arg severity "$severity" \
        --arg user     "$USERNAME" \
        '{module: $module, user: $user, field: $field, value: $value, severity: $severity}'
}

# Emit a finding for every non-empty PII field.
check_field() {
    local field="$1" severity="$2"
    local value
    value=$(echo "$PROFILE" | jq -r --arg f "$field" '.[$f] // empty')
    if [[ -n "$value" ]]; then
        _log debug "found $field: $value"
        emit "$field" "$value" "$severity"
    fi
}

check_field "name"             "medium"
check_field "email"            "high"
check_field "company"          "medium"
check_field "location"         "medium"
check_field "blog"             "low"
check_field "twitter_username" "low"

# Flag when a public email matches (or differs from) the caller's primary email.
if [[ -n "$PRIMARY_EMAIL" ]]; then
    pub_email=$(echo "$PROFILE" | jq -r '.email // empty')
    if [[ -n "$pub_email" && "$pub_email" != "$PRIMARY_EMAIL" ]]; then
        jq -n \
            --arg module  "profile" \
            --arg user    "$USERNAME" \
            --arg value   "$pub_email" \
            --arg primary "$PRIMARY_EMAIL" \
            '{module: $module, user: $user, field: "email_mismatch", value: $value, primary: $primary, severity: "high"}'
    fi
fi
