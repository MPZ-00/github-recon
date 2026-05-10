#!/usr/bin/env bash
# Enumerate all public repos for $USERNAME using full pagination.
# Detects email addresses in descriptions and flags sensitive repo names.
# Emits one JSON finding object per line to stdout.
#
# Required env: USERNAME
# Optional env: GITHUB_TOKEN, LOG_LEVEL (verbose)

set -euo pipefail

USERNAME="${USERNAME:?USERNAME env var required}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
LOG_LEVEL="${LOG_LEVEL:-}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_log() { [[ "$LOG_LEVEL" == "verbose" ]] && echo "[repos] $*" >&2 || true; }

_api_headers() {
    local -a h=(-H "Accept: application/vnd.github+json")
    [[ -n "$GITHUB_TOKEN" ]] && h+=(-H "Authorization: token $GITHUB_TOKEN")
    printf '%s\n' "${h[@]}"
}

# Fetch all pages for a list endpoint, concatenating JSON arrays.
api_get_all() {
    local base_url="$1"
    local page=1
    local combined="[]"

    while true; do
        local url="${base_url}?per_page=100&page=${page}"
        _log "GET $url"

        local tmp_headers tmp_body http_code
        tmp_headers=$(mktemp)
        tmp_body=$(mktemp)

        # Build header args
        local -a hdr_args=()
        while IFS= read -r h; do hdr_args+=("$h"); done < <(_api_headers)

        http_code=$(curl -sSL -D "$tmp_headers" -o "$tmp_body" -w '%{http_code}' \
            "${hdr_args[@]}" "$url" || true)

        local body
        body=$(cat "$tmp_body")
        rm -f "$tmp_headers" "$tmp_body"

        if [[ ! "$http_code" =~ ^2 ]]; then
            _log "HTTP $http_code for $url — stopping pagination"
            break
        fi

        local page_len
        page_len=$(printf '%s' "$body" | jq 'if type == "array" then length else 0 end')

        if [[ "$page_len" -eq 0 ]]; then
            break
        fi

        combined=$(printf '%s\n%s' "$combined" "$body" | jq -s 'add')
        _log "page $page: $page_len repos (total so far: $(printf '%s' "$combined" | jq length))"

        [[ "$page_len" -lt 100 ]] && break
        page=$((page + 1))
    done

    printf '%s' "$combined"
}

# Emit a structured JSON finding to stdout.
emit_finding() {
    local type="$1"
    local severity="$2"
    local repo="$3"
    local detail="$4"
    jq -n \
        --arg type     "$type" \
        --arg severity "$severity" \
        --arg repo     "$repo" \
        --arg detail   "$detail" \
        '{type: $type, severity: $severity, repo: $repo, detail: $detail}'
}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Repo names that suggest private/sensitive content.
SENSITIVE_NAME_PATTERNS=(
    secret secrets password passwd credentials creds token api-key apikey
    private internal dotfiles config backup infra infrastructure pentest
    exploit payload shellcode malware rat keylogger
)

# Matches a bare email address in free text.
EMAIL_REGEX='[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_log "Fetching repos for $USERNAME"
REPOS=$(api_get_all "https://api.github.com/users/${USERNAME}/repos")

TOTAL=$(printf '%s' "$REPOS" | jq length)
_log "Total repos: $TOTAL"

printf '%s' "$REPOS" | jq -c '.[]' | while IFS= read -r repo_json; do
    name=$(printf '%s' "$repo_json"    | jq -r '.name')
    desc=$(printf '%s' "$repo_json"    | jq -r '.description // ""')
    is_fork=$(printf '%s' "$repo_json" | jq -r '.fork')

    # --- sensitive repo name check ---
    lower_name="${name,,}"
    for pat in "${SENSITIVE_NAME_PATTERNS[@]}"; do
        if [[ "$lower_name" == *"$pat"* ]]; then
            emit_finding "sensitive_repo_name" "medium" "$name" \
                "Repo name matches sensitive pattern '${pat}'"
            break
        fi
    done

    # --- PII / email in description ---
    if [[ -n "$desc" ]]; then
        # Extract all email-like tokens from the description.
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            emit_finding "email_in_description" "high" "$name" \
                "Email address found in repo description: ${match}"
        done < <(printf '%s' "$desc" | grep -oE "$EMAIL_REGEX" || true)
    fi

    # --- forked repos with suspicious names (lower severity) ---
    if [[ "$is_fork" == "true" ]]; then
        for pat in exploit payload shellcode malware rat keylogger; do
            if [[ "$lower_name" == *"$pat"* ]]; then
                emit_finding "forked_offensive_tool" "low" "$name" \
                    "Forked repo name suggests offensive tooling: '${pat}'"
                break
            fi
        done
    fi
done
