#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

total=0

repos_json=$(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")
repo_names=$(printf '%s' "$repos_json" | jq -r '.[].name // empty')

while IFS= read -r REPO; do
    [[ -z "$REPO" ]] && continue
    log_verbose "Scanning PRs in $REPO"

    pulls=$(api_get_all "https://api.github.com/repos/${USERNAME}/${REPO}/pulls?state=all&per_page=100")
    user_pulls=$(printf '%s' "$pulls" | jq -r --arg u "$USERNAME" \
        '[.[] | select(.user.login == $u)] | .[] | [.number, .title // "", .body // ""] | @tsv')
    [[ -z "$user_pulls" ]] && continue

    while IFS=$'\t' read -r NUM TITLE BODY; do
        for TEXT in "$TITLE" "$BODY"; do
            [[ -z "$TEXT" ]] && continue
            while IFS= read -r EMAIL; do
                [[ -z "$EMAIL" ]] && continue
                emit_finding "pull_requests" "medium" "email_leak" \
                    "repo:$REPO/pr:$NUM" \
                    "$EMAIL" \
                    "Email in PR #$NUM body" \
                    "https://github.com/$USERNAME/$REPO/pull/$NUM"
                total=$(( total + 1 ))
            done < <(printf '%s' "$TEXT" | grep -oE "$EMAIL_REGEX" || true)
        done

        comments=$(api_get_all "https://api.github.com/repos/${USERNAME}/${REPO}/issues/${NUM}/comments?per_page=100")

        while IFS= read -r CBODY; do
            [[ -z "$CBODY" ]] && continue
            while IFS= read -r EMAIL; do
                [[ -z "$EMAIL" ]] && continue
                emit_finding "pull_requests" "medium" "email_leak" \
                    "repo:$REPO/pr:$NUM" \
                    "$EMAIL" \
                    "Email in PR #$NUM comment" \
                    "https://github.com/$USERNAME/$REPO/pull/$NUM"
                total=$(( total + 1 ))
            done < <(printf '%s' "$CBODY" | grep -oE "$EMAIL_REGEX" || true)
        done < <(printf '%s' "$comments" | jq -r --arg u "$USERNAME" '.[] | select(.user.login == $u) | .body // empty')
    done <<< "$user_pulls"
done <<< "$repo_names"

log_normal "pull_requests: $total email finding(s) across all repos"
