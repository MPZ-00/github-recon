#!/usr/bin/env bash
# Compatibility shim — gists.sh and deep_scan.sh use the log_info/log_warn/log_err
# naming convention; forward them to the canonical lib/log.sh functions.
_LOGGING_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LOGGING_SH_DIR/log.sh"

log_info()  { log_normal "$@"; }
log_warn()  { log_normal "[warn] $*"; }
log_err()   { log_error "$@"; }
log_debug() { log_verbose "$@"; }
