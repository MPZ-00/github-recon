#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

: "${USERNAME:?USERNAME must be set}"

log_verbose "wikis: fetching repos for $USERNAME"
REPOS=$(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")

while IFS= read -r REPO; do
    log_verbose "wikis: cloning wiki for $REPO"
    git clone "https://github.com/${USERNAME}/${REPO}.wiki.git" "${TMP_DIR}/wiki-${REPO}" 2>/dev/null || continue

    while IFS= read -r EMAIL; do
        [[ "$EMAIL" == *"noreply"* ]] && continue
        emit_finding "wikis" "medium" "email_leak" "repo:$REPO/wiki" "$EMAIL" \
            "Email in wiki content" "https://github.com/$USERNAME/$REPO/wiki"
    done < <(grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        "${TMP_DIR}/wiki-${REPO}" 2>/dev/null | sort -u)
done < <(printf '%s' "$REPOS" | jq -r '.[] | select(.has_wiki == true) | .name')
