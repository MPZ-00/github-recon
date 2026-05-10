#!/usr/bin/env bash
# Runtime config defaults and ignore-rule helpers.
SEARCH_CONCURRENCY="${SEARCH_CONCURRENCY:-4}"

# Matches a bare email address in free text; used by several modules.
EMAIL_REGEX='[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'

declare -a IGNORE_REPOS=()
declare -a IGNORE_PATTERNS=()
declare -a IGNORE_SECRET_LABELS=()
declare -a IGNORE_REPO_PATTERN_COMBOS=()

array_contains() {
    local needle="$1"; shift
    local item
    for item in "$@"; do [[ "$item" == "$needle" ]] && return 0; done
    return 1
}

should_ignore_sensitive_finding() {
    local repo_name="$1" pattern="$2"
    array_contains "$repo_name" "${IGNORE_REPOS[@]}"         && return 0
    array_contains "$pattern"   "${IGNORE_PATTERNS[@]}"      && return 0
    array_contains "${repo_name}:${pattern}" "${IGNORE_REPO_PATTERN_COMBOS[@]}" && return 0
    return 1
}

load_ignore_file() {
    local ignore_file="$1"
    [[ ! -f "$ignore_file" ]] && return 0
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        
        # Parse rules: repo:NAME, pattern:PATTERN, secret:LABEL, or just REPO/PATTERN
        if [[ "$line" =~ ^repo: ]]; then
            IGNORE_REPOS+=("${line#repo:}")
            elif [[ "$line" =~ ^pattern: ]]; then
            IGNORE_PATTERNS+=("${line#pattern:}")
            elif [[ "$line" =~ ^secret: ]]; then
            IGNORE_SECRET_LABELS+=("${line#secret:}")
            elif [[ "$line" =~ : ]]; then
            IGNORE_REPO_PATTERN_COMBOS+=("$line")
        else
            IGNORE_PATTERNS+=("$line")
        fi
    done < "$ignore_file"
}
