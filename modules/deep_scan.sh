#!/usr/bin/env bash
# Phase 7: Deep Scan (requires CLONE_MODE=true)
# Inherits: USERNAME, LOG_LEVEL, TMP_DIR, CLONE_MODE from env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/logging.sh
source "$SCRIPT_DIR/../lib/logging.sh"
# shellcheck source=../lib/api.sh
source "$SCRIPT_DIR/../lib/api.sh"
# shellcheck source=../lib/findings.sh
source "$SCRIPT_DIR/../lib/findings.sh"

: "${USERNAME:?USERNAME env var required}"
: "${CLONE_MODE:?CLONE_MODE env var required}"
: "${TMP_DIR:?TMP_DIR env var required}"

if [[ "$CLONE_MODE" != "true" ]]; then
    log_info "deep_scan: skipped (CLONE_MODE is not true)"
    exit 0
fi

log_info "deep_scan: starting for $USERNAME"

HAS_GITLEAKS=false
command -v gitleaks &>/dev/null && HAS_GITLEAKS=true && log_info "deep_scan: gitleaks detected"

REPOS=$(api_get_all "https://api.github.com/users/${USERNAME}/repos?per_page=100")

if ! echo "$REPOS" | jq empty 2>/dev/null; then
    log_err "deep_scan: invalid repo API response"
    exit 1
fi

log_info "deep_scan: $(echo "$REPOS" | jq 'length') repo(s) to scan"

while IFS= read -r repo_name; do
    [[ -z "$repo_name" ]] && continue
    REPO_DIR="$TMP_DIR/$repo_name"
    log_debug "deep_scan: cloning $repo_name"

    git clone --quiet --depth=50 \
        "https://github.com/$USERNAME/$repo_name.git" "$REPO_DIR" 2>/dev/null \
        || { log_warn "deep_scan: clone failed for $repo_name"; continue; }

    while IFS= read -r email; do
        [[ -z "$email" ]] && continue
        [[ "$email" == *"noreply.github.com"* ]] && continue
        emit_finding "deep_scan" "medium" "commit_email" \
            "repo:$repo_name" "$email" \
            "Email found in git commit history" \
            "https://github.com/$USERNAME/$repo_name"
    done < <(git -C "$REPO_DIR" log --all --format='%ae' 2>/dev/null | sort -u || true)

    while IFS= read -r deleted_file; do
        [[ -z "$deleted_file" ]] && continue
        emit_finding "deep_scan" "high" "deleted_sensitive_file" \
            "repo:$repo_name" "$deleted_file" \
            "Sensitive file deleted but still in git history" \
            "https://github.com/$USERNAME/$repo_name"
    done < <(git -C "$REPO_DIR" log --all --diff-filter=D --name-only --pretty=format: \
        -- '*.env' '*.env.*' '*.pem' '*.key' '*credentials*' 2>/dev/null \
        | sort -u | grep -v '^$' || true)

    if $HAS_GITLEAKS; then
        GITLEAKS_OUT="$TMP_DIR/gitleaks-${repo_name}.json"
        gitleaks detect --source="$REPO_DIR" \
            --report-format=json --report-path="$GITLEAKS_OUT" \
            --no-git 2>/dev/null || true

        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            emit_finding "deep_scan" "critical" "gitleaks_secret" \
                "repo:$repo_name" "$entry" \
                "Secret detected by gitleaks" \
                "https://github.com/$USERNAME/$repo_name"
        done < <(jq -r '.[] | (.RuleID // "unknown") + ":" + (.File // "")' "$GITLEAKS_OUT" 2>/dev/null || true)
    else
        PATTERN_HITS=$(git -C "$REPO_DIR" log --all -p 2>/dev/null \
            | grep -cE '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-ant-|sk-proj-|xoxb-|-----BEGIN (RSA |EC )?PRIVATE KEY)' \
            || true)
        if [[ "$PATTERN_HITS" -gt 0 ]]; then
            emit_finding "deep_scan" "high" "pattern_match" \
                "repo:$repo_name" "${PATTERN_HITS} match(es)" \
                "Potential secrets found via pattern scan in git history" \
                "https://github.com/$USERNAME/$repo_name"
        fi
    fi

done < <(echo "$REPOS" | jq -r '.[].name')

log_debug "deep_scan: scan complete"
