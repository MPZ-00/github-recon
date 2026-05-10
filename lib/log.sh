#!/usr/bin/env bash
# Logging helpers — all output goes to stderr.

RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

export RED YELLOW GREEN CYAN BOLD DIM NC

log_normal()  { echo -e "${NC}$*${NC}" >&2; }
log_verbose() { [[ "${LOG_LEVEL:-}" == "verbose" || "${LOG_LEVEL:-}" == "debug" ]] && echo -e "${DIM}$*${NC}" >&2 || true; }
log_error()   { echo -e "${RED}[error]${NC} $*" >&2; }
log_warn()    { echo -e "${YELLOW}[warn]${NC}  $*" >&2; }
log_info()    { echo -e "${GREEN}[info]${NC}  $*" >&2; }
log_progress() {
    local current="$1" total="$2" msg="$3"
    echo -e "${CYAN}[${current}/${total}]${NC} $msg" >&2
}
