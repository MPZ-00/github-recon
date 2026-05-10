#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

if [[ -z "${USERNAME:-}" ]]; then
    log_error "USERNAME is not set"
    exit 1
fi

log_verbose "Fetching public events for $USERNAME"

EVENTS=$(api_get_all "https://api.github.com/users/${USERNAME}/events/public?per_page=100")

EMAIL_REPO_PAIRS=$(printf '%s' "$EVENTS" | jq -r '
    .[] | select(.type == "PushEvent") |
    . as $ev | .payload.commits[]? |
    select(.author.email | test("users\\.noreply\\.github\\.com") | not) |
    "\(.author.email)\t\($ev.repo.name)"
' 2>/dev/null || true)

if [[ -z "$EMAIL_REPO_PAIRS" ]]; then
    log_normal "Found 0 unique email(s) in commit events"
    exit 0
fi

UNIQUE_EMAILS=$(printf '%s\n' "$EMAIL_REPO_PAIRS" | cut -f1 | sort -u)
EMAIL_COUNT=$(printf '%s\n' "$UNIQUE_EMAILS" | wc -l | tr -d ' ')

log_normal "Found $EMAIL_COUNT unique email(s) in commit events"

while IFS= read -r email; do
    [[ -z "$email" ]] && continue

    REPOS=$(printf '%s\n' "$EMAIL_REPO_PAIRS" | awk -F'\t' -v e="$email" '$1 == e {print $2}' | sort -u | tr '\n' ',' | sed 's/,$//')

    emit_finding "commit_email" "high" \
        "Personal email exposed in commits" \
        "Email <${email}> found in public commit history" \
        "email=${email}" \
        "repos=${REPOS}"

    if [[ -n "${PRIMARY_EMAIL:-}" && "$email" != "$PRIMARY_EMAIL" ]]; then
        emit_finding "email_mismatch" "medium" \
            "Commit email differs from primary" \
            "Email <${email}> does not match configured primary <${PRIMARY_EMAIL}>" \
            "email=${email}" \
            "primary_email=${PRIMARY_EMAIL}" \
            "repos=${REPOS}"
    fi
done <<< "$UNIQUE_EMAILS"
