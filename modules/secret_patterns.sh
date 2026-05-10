#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

: "${USERNAME:?USERNAME environment variable is required}"

declare -A SECRET_PATTERNS=(
    ["AWS Access Key"]="AKIA"
    ["GitHub Token (ghp)"]="ghp_"
    ["GitHub Token (gho)"]="gho_"
    ["Slack Token"]="xoxb-"
    ["Slack Webhook"]="hooks.slack.com/services"
    ["Anthropic Key"]="sk-ant-"
    ["OpenAI Key"]="sk-proj-"
    ["Stripe Live Key"]="sk_live_"
    ["Stripe Test Key"]="sk_test_"
    ["Private Key"]="PRIVATE KEY"
    ["PostgreSQL URL"]="postgresql://"
    ["MongoDB URL"]="mongodb+srv://"
    ["JWT Secret"]="JWT_SECRET"
    ["API Key var"]="API_KEY="
    ["Sendgrid Key"]="SG."
    ["Twilio"]="twilio"
    ["Heroku API Key"]="HEROKU_API_KEY"
)

SECRET_PATTERN_LABELS=(
    "AWS Access Key"
    "GitHub Token (ghp)"
    "GitHub Token (gho)"
    "Slack Token"
    "Slack Webhook"
    "Anthropic Key"
    "OpenAI Key"
    "Stripe Live Key"
    "Stripe Test Key"
    "Private Key"
    "PostgreSQL URL"
    "MongoDB URL"
    "JWT Secret"
    "API Key var"
    "Sendgrid Key"
    "Twilio"
    "Heroku API Key"
)

TMP_DIR="${TMPDIR:-/tmp}/github-recon-secrets-$$"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

scan_secret_pattern() {
    local label="$1"
    local pattern="${SECRET_PATTERNS[$label]}"
    local safe_label="${label//[^A-Za-z0-9._-]/_}"
    local result_file="${TMP_DIR}/secret-${safe_label}.txt"

    : > "$result_file"

    local result count
    result=$(api_get "https://api.github.com/search/code?q=${pattern}+user:${USERNAME}")
    count=$(printf '%s' "$result" | jq -r '.total_count // 0')

    if [[ "$count" -gt 0 ]]; then
        local repos
        repos=$(printf '%s' "$result" | jq -r '.items[].repository.name' 2>/dev/null \
            | sort -u | tr '\n' ',' | sed 's/,$//')
        printf '%s\t%s\t%s\t%s\n' "$label" "$pattern" "$count" "$repos" >> "$result_file"
    fi
}

for label in "${SECRET_PATTERN_LABELS[@]}"; do
    wait_for_search_slot
    scan_secret_pattern "$label" &
done
wait

found=0
suppressed=0

for label in "${SECRET_PATTERN_LABELS[@]}"; do
    safe_label="${label//[^A-Za-z0-9._-]/_}"
    result_file="${TMP_DIR}/secret-${safe_label}.txt"

    while IFS=$'\t' read -r found_label pattern count repos; do
        [[ -z "$found_label" ]] && continue

        if should_ignore_secret_finding "$found_label" "$pattern"; then
            suppressed=$(( suppressed + 1 ))
            continue
        fi

        emit_finding \
            "secret_patterns" \
            "critical" \
            "secret_pattern" \
            "repo:$repos" \
            "$found_label" \
            "${count} match(es) across repos: $repos" \
            "https://github.com/search?q=${pattern}+user:${USERNAME}"

        found=$(( found + 1 ))
    done < "$result_file"
done

log_normal "Secret pattern scan complete: $found finding(s) emitted, $suppressed suppressed"
