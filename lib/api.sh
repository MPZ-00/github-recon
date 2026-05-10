#!/usr/bin/env bash
# Thin wrapper around curl with rate-limit retry logic.
api_get() {
    local url="$1"
    local attempt=1 max_attempts=5 response_body=""

    while [[ $attempt -le $max_attempts ]]; do
        local headers_file body_file http_code retry_after rate_reset wait_seconds
        headers_file=$(mktemp)
        body_file=$(mktemp)

        if [[ -n "${AUTH_HEADER:-}" ]]; then
            http_code=$(curl -sSL -D "$headers_file" -o "$body_file" -w '%{http_code}' \
                -H "$AUTH_HEADER" -H "Accept: application/vnd.github+json" "$url" || true)
        else
            http_code=$(curl -sSL -D "$headers_file" -o "$body_file" -w '%{http_code}' \
                -H "Accept: application/vnd.github+json" "$url" || true)
        fi

        response_body=$(cat "$body_file")
        retry_after=$(awk 'BEGIN{IGNORECASE=1} /^Retry-After:/{print $2}' "$headers_file" | tail -n1 | tr -d '\r')
        rate_reset=$(awk  'BEGIN{IGNORECASE=1} /^X-RateLimit-Reset:/{print $2}' "$headers_file" | tail -n1 | tr -d '\r')
        rm -f "$headers_file" "$body_file"

        if [[ "$http_code" =~ ^2 ]]; then
            printf '%s' "$response_body"
            return 0
        fi

        if [[ "$http_code" == "403" || "$http_code" == "429" ]]; then
            if [[ -n "$retry_after" ]]; then
                wait_seconds="$retry_after"
            elif [[ -n "$rate_reset" ]]; then
                wait_seconds=$(( rate_reset - $(date +%s) ))
                [[ "$wait_seconds" -lt 1 ]] && wait_seconds=1
            else
                wait_seconds=$(( attempt * 2 ))
            fi
            log_verbose "rate-limit on $url, retrying in ${wait_seconds}s (attempt ${attempt}/${max_attempts})"
            sleep "$wait_seconds"
            attempt=$(( attempt + 1 ))
            continue
        fi

        printf '%s' "$response_body"
        return 0
    done

    printf '%s' "$response_body"
}
