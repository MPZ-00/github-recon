#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

: "${USERNAME:?USERNAME must be set}"

log_verbose "org_repos: fetching orgs for $USERNAME"
ORGS=$(api_get "https://api.github.com/users/${USERNAME}/orgs")

while IFS= read -r ORG; do
    log_verbose "org_repos: scanning org $ORG"
    ORG_REPOS=$(api_get_all "https://api.github.com/orgs/${ORG}/repos?per_page=100")

    while IFS= read -r REPO; do
        COMMITS=$(api_get "https://api.github.com/repos/${ORG}/${REPO}/commits?author=${USERNAME}&per_page=5")

        while IFS= read -r EMAIL; do
            [[ "$EMAIL" == *"noreply"* ]] && continue
            emit_finding "org_repos" "high" "email_leak" "org:$ORG/repo:$REPO" "$EMAIL" \
                "Email in commit to org repo" "https://github.com/$ORG/$REPO/commits"
        done < <(printf '%s' "$COMMITS" | jq -r '.[].commit.author.email' 2>/dev/null | sort -u)
    done < <(printf '%s' "$ORG_REPOS" | jq -r '.[].name' 2>/dev/null)
done < <(printf '%s' "$ORGS" | jq -r '.[].login' 2>/dev/null)
