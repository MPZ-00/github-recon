#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

: "${USERNAME:?USERNAME must be set}"

log_verbose "forks: fetching repos for $USERNAME"
REPOS=$(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")

while IFS= read -r REPO; do
    log_verbose "forks: checking commits in $REPO"
    COMMITS=$(api_get "https://api.github.com/repos/${USERNAME}/${REPO}/commits?author=${USERNAME}&per_page=10")

    while IFS= read -r EMAIL; do
        [[ "$EMAIL" == *"noreply"* ]] && continue
        emit_finding "forks" "high" "email_leak" "repo:$REPO (fork)" "$EMAIL" \
            "Email exposed in forked repo commits" "https://github.com/$USERNAME/$REPO"
    done < <(printf '%s' "$COMMITS" | jq -r '.[].commit.author.email' 2>/dev/null | sort -u)
done < <(printf '%s' "$REPOS" | jq -r '.[] | select(.fork == true) | .name')
