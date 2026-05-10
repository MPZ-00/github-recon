#!/usr/bin/env bash
# Scan PR reviews authored by USERNAME for leaked email addresses.
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

EMAIL_RE='[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

log_normal "reviews: scanning PR reviews for $USERNAME"

repos=$(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")
repo_names=$(printf '%s' "$repos" | jq -r '.[].name' 2>/dev/null || true)

while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    log_verbose "reviews: fetching PRs for $repo"

    pulls=$(api_get_all "https://api.github.com/repos/${USERNAME}/${repo}/pulls?state=all&per_page=100")
    pr_numbers=$(printf '%s' "$pulls" | jq -r '.[].number' 2>/dev/null || true)

    while IFS= read -r pr_num; do
        [[ -z "$pr_num" ]] && continue
        log_verbose "reviews: checking PR #$pr_num in $repo"

        reviews=$(api_get "https://api.github.com/repos/${USERNAME}/${repo}/pulls/${pr_num}/reviews")

        while IFS= read -r review_json; do
            review_id=$(printf '%s' "$review_json" | jq -r '.id')
            body=$(printf '%s' "$review_json" | jq -r '.body // ""')

            [[ -z "$body" ]] && continue

            while IFS= read -r email; do
                [[ -z "$email" ]] && continue
                emit_finding "reviews" "medium" "email_leak" \
                    "repo:${repo}/pr:${pr_num}/review:${review_id}" \
                    "$email" \
                    "Email in PR review" \
                    "https://github.com/${USERNAME}/${repo}/pull/${pr_num}"
            done < <(printf '%s' "$body" | grep -oE "$EMAIL_RE" || true)

        done < <(printf '%s' "$reviews" | jq -c --arg user "$USERNAME" \
            '.[] | select(.user.login == $user)' 2>/dev/null || true)

    done <<< "$pr_numbers"
done <<< "$repo_names"

log_normal "reviews: done"
