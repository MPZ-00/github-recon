#!/usr/bin/env bash
# Scan releases for PII in bodies, sensitive asset names, and uploader identity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

SENSITIVE_ASSET_RE='\.(key|pem|env)$|credentials'
_findings=0

scan_repo_releases() {
    local repo="$1"

    while IFS= read -r release_obj; do
        local tag body author_login author_type url
        tag=$(printf '%s' "$release_obj" | jq -r '.tag_name // empty')
        body=$(printf '%s' "$release_obj" | jq -r '.body // empty')
        author_login=$(printf '%s' "$release_obj" | jq -r '.author.login // empty')
        author_type=$(printf '%s' "$release_obj" | jq -r '.author.type // empty')
        url="https://github.com/${USERNAME}/${repo}/releases/tag/${tag}"

        if [[ -n "$body" ]]; then
            local found_email
            while IFS= read -r found_email; do
                [[ -z "$found_email" ]] && continue
                emit_finding "releases" "medium" "email_leak" \
                    "repo:${repo}/release:${tag}" \
                    "$found_email" \
                    "Email in release body" \
                    "$url"
                _findings=$(( _findings + 1 ))
            done < <(extract_emails "$body")
        fi

        if [[ -n "$author_login" && "$author_type" != "Bot" ]]; then
            local author_email
            author_email=$(printf '%s' "$release_obj" | jq -r '.author.email // empty')
            if [[ -n "$author_email" && "$author_email" != *"noreply"* ]]; then
                emit_finding "releases" "high" "email_leak" \
                    "repo:${repo}/release:${tag}/uploader:${author_login}" \
                    "$author_email" \
                    "Uploader email visible on release" \
                    "$url"
                _findings=$(( _findings + 1 ))
            fi
        fi

        while IFS= read -r asset_obj; do
            local asset_name
            asset_name=$(printf '%s' "$asset_obj" | jq -r '.name // empty')
            if printf '%s' "$asset_name" | grep -qiE "$SENSITIVE_ASSET_RE"; then
                emit_finding "releases" "high" "sensitive_file" \
                    "repo:${repo}/release:${tag}/asset:${asset_name}" \
                    "$asset_name" \
                    "Sensitive asset in release" \
                    "$url"
                _findings=$(( _findings + 1 ))
            fi
        done < <(printf '%s' "$release_obj" | jq -c '.assets[]?' 2>/dev/null)

    done < <(api_get_all "https://api.github.com/repos/${USERNAME}/${repo}/releases?per_page=100")
}

while IFS= read -r repo_obj; do
    repo=$(printf '%s' "$repo_obj" | jq -r '.name')
    log_verbose "releases: scanning $repo"
    scan_repo_releases "$repo"
done < <(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")

log_normal "releases: $_findings finding(s)"
