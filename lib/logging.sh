#!/usr/bin/env bash
# Compatibility shim — gists.sh and deep_scan.sh use log_err/log_debug;
# forward them to the canonical lib/log.sh equivalents.
_LOGGING_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LOGGING_SH_DIR/log.sh"

log_err()   { log_error "$@"; }
log_debug() { log_verbose "$@"; }
