#!/usr/bin/env bash
# Scan annotated git tags for tagger email / PII in tag messages.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

_findings=0

scan_repo_tags() {
    local repo="$1"
    local refs
    refs=$(api_get "https://api.github.com/repos/${USERNAME}/${repo}/git/refs/tags")

    while IFS= read -r ref_obj; do
        local tag_name sha obj_type
        tag_name=$(printf '%s' "$ref_obj" | jq -r '.ref | ltrimstr("refs/tags/")')
        sha=$(printf '%s' "$ref_obj" | jq -r '.object.sha')
        obj_type=$(printf '%s' "$ref_obj" | jq -r '.object.type')

        # Only annotated tags have a "tag" object; lightweight tags point to commits.
        [[ "$obj_type" != "tag" ]] && continue

        local tag_obj
        tag_obj=$(api_get "https://api.github.com/repos/${USERNAME}/${repo}/git/tags/${sha}")

        local tagger_email tag_message
        tagger_email=$(printf '%s' "$tag_obj" | jq -r '.tagger.email // empty')
        tag_message=$(printf '%s' "$tag_obj" | jq -r '.message // empty')

        local url="https://github.com/${USERNAME}/${repo}/releases/tag/${tag_name}"

        if [[ -n "$tagger_email" && "$tagger_email" != *"noreply"* ]]; then
            emit_finding "tags" "high" "email_leak" \
                "repo:${repo}/tag:${tag_name}" \
                "$tagger_email" \
                "Tagger email in annotated tag" \
                "$url"
            _findings=$(( _findings + 1 ))
        fi

        if [[ -n "$tag_message" ]]; then
            local found_email
            while IFS= read -r found_email; do
                [[ -z "$found_email" ]] && continue
                emit_finding "tags" "high" "email_leak" \
                    "repo:${repo}/tag:${tag_name}" \
                    "$found_email" \
                    "Email in tag message" \
                    "$url"
                _findings=$(( _findings + 1 ))
            done < <(extract_emails "$tag_message")
        fi
    done < <(printf '%s' "$refs" | jq -c '.[]?' 2>/dev/null)
}

while IFS= read -r repo_obj; do
    repo=$(printf '%s' "$repo_obj" | jq -r '.name')
    log_verbose "tags: scanning $repo"
    scan_repo_tags "$repo"
done < <(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")

log_normal "tags: $_findings finding(s)"
