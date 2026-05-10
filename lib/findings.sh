#!/usr/bin/env bash
# Emits a finding as a JSON line to stdout.
emit_finding() {
    local module="$1" severity="$2" type="$3" target="$4" pattern="$5" detail="$6" url="$7"
    printf '{"module":"%s","severity":"%s","type":"%s","target":"%s","pattern":"%s","detail":"%s","url":"%s"}\n' \
        "$module" "$severity" "$type" "$target" "$pattern" "$detail" "$url"
}

# Print each email address found in $1 on its own line.
extract_emails() {
    printf '%s' "$1" | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' || true
}
