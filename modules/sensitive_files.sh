#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

: "${USERNAME:?USERNAME must be set}"

SENSITIVE_PATTERNS=(
    ".env"
    ".env.local"
    ".env.production"
    "docker-compose.yml"
    "Dockerfile"
    ".htaccess"
    ".htpasswd"
    "wp-config.php"
    "config.json"
    "config.yml"
    "credentials"
    "id_rsa"
    "id_ed25519"
    ".npmrc"
    ".pypirc"
    "kubeconfig"
    "terraform.tfvars"
    ".aws/credentials"
)

wait_for_search_slot() {
    while (( $(jobs -pr | wc -l) >= ${SEARCH_CONCURRENCY:-4} )); do sleep 0.5; done
}

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

scan_pattern() {
    local pattern="$1"
    local result_file="$TMP_DIR/$(echo "$pattern" | tr '/.+' '___').txt"
    : > "$result_file"

    local response count
    response=$(api_get "https://api.github.com/search/code?q=filename:${pattern}+user:${USERNAME}" \
        || echo '{"total_count":0,"items":[]}')

    count=$(printf '%s' "$response" | jq -r '.total_count // 0')
    [[ "$count" -le 0 ]] && return 0

    printf '%s' "$response" | jq -r '.items[]?.repository.name // empty' \
        | sort -u \
        | while IFS= read -r repo; do
            printf '%s\t%s\t%s\n' "$repo" "$pattern" "$count" >> "$result_file"
        done
}

for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    wait_for_search_slot
    scan_pattern "$pattern" &
done

wait

FOUND=0
for result_file in "$TMP_DIR"/*.txt; do
    [[ -e "$result_file" ]] || continue
    while IFS=$'\t' read -r repo pattern count; do
        [[ -z "$repo" ]] && continue
        if should_ignore_sensitive_finding "$repo" "$pattern"; then
            log_verbose "ignored: $repo / $pattern"
            continue
        fi
        emit_finding "sensitive_files" "high" "sensitive_file" \
            "repo:$repo" "$pattern" \
            "${count} match(es) in $repo" \
            "https://github.com/$USERNAME/$repo"
        FOUND=$(( FOUND + 1 ))
    done < "$result_file"
done

log_normal "sensitive_files: $FOUND finding(s) for $USERNAME"
