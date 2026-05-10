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
    log_verbose "Scanning issues in $REPO"

    issues=$(api_get_all "https://api.github.com/repos/${USERNAME}/${REPO}/issues?state=all&creator=${USERNAME}&per_page=100")
    issue_count=$(printf '%s' "$issues" | jq 'if type=="array" then length else 0 end')
    [[ "$issue_count" -eq 0 ]] && continue

    while IFS=$'\t' read -r NUM TITLE BODY; do
        for TEXT in "$TITLE" "$BODY"; do
            [[ -z "$TEXT" ]] && continue
            while IFS= read -r EMAIL; do
                [[ -z "$EMAIL" ]] && continue
                emit_finding "issues" "medium" "email_leak" \
                    "repo:$REPO/issue:$NUM" \
                    "$EMAIL" \
                    "Email found in issue #$NUM body" \
                    "https://github.com/$USERNAME/$REPO/issues/$NUM"
                total=$(( total + 1 ))
            done < <(printf '%s' "$TEXT" | grep -oE "$EMAIL_REGEX" || true)
        done

        comments=$(api_get_all "https://api.github.com/repos/${USERNAME}/${REPO}/issues/${NUM}/comments?per_page=100")

        while IFS= read -r CBODY; do
            [[ -z "$CBODY" ]] && continue
            while IFS= read -r EMAIL; do
                [[ -z "$EMAIL" ]] && continue
                emit_finding "issues" "medium" "email_leak" \
                    "repo:$REPO/issue:$NUM" \
                    "$EMAIL" \
                    "Email found in issue #$NUM comment" \
                    "https://github.com/$USERNAME/$REPO/issues/$NUM"
                total=$(( total + 1 ))
            done < <(printf '%s' "$CBODY" | grep -oE "$EMAIL_REGEX" || true)
        done < <(printf '%s' "$comments" | jq -r --arg u "$USERNAME" '.[] | select(.user.login == $u) | .body // empty')
    done < <(printf '%s' "$issues" | jq -r '.[] | [.number, .title // "", .body // ""] | @tsv')
done <<< "$repo_names"

log_normal "issues: $total email finding(s) across all repos"
