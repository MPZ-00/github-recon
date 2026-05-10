#!/usr/bin/env bash
# Logging helpers — all output goes to stderr.
BOLD=$'\033[1m'
NC=$'\033[0m'

log_normal() { echo "[info] $*" >&2; }
log_verbose() { [[ "${LOG_LEVEL:-}" == "verbose" || "${LOG_LEVEL:-}" == "debug" ]] && echo "[verbose] $*" >&2 || true; }
log_error()  { echo "[error] $*" >&2; }
log_progress() {
    local current="$1" total="$2" msg="$3"
    echo "[${current}/${total}] $msg" >&2
}
