#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/log.sh"
source "$SCRIPT_DIR/lib/findings.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/api.sh"

usage() {
  cat <<EOF
Usage: $(basename "$0") <github-username> [options]

Options:
  --clone                   Enable deep scan (git clone)
  --email=ADDR              Set primary email for consistency checks
  --log-level=LEVEL         Output verbosity: quiet|normal|verbose|debug (default: normal)
  --status                  Deprecated alias for --log-level=quiet
  --ignore-file=PATH        Load ignore rules from file
  --ignore-repo=NAME        Ignore repo (repeatable)
  --ignore-pattern=PATTERN  Ignore file pattern (repeatable)
  --ignore-secret-label=LBL Ignore secret type (repeatable)
  --help, -h                Show this help
EOF
}

# Argument parsing
[[ $# -lt 1 || "$1" == "--help" || "$1" == "-h" ]] && { usage; exit 0; }
USERNAME="$1"; shift

# Set defaults
CLONE_MODE=false
LOG_LEVEL="${LOG_LEVEL:-normal}"
PRIMARY_EMAIL="${PRIMARY_EMAIL:-}"

for arg in "$@"; do
    case "$arg" in
        --clone)                  CLONE_MODE=true ;;
        --email=*)                PRIMARY_EMAIL="${arg#--email=}" ;;
        --log-level=*)            LOG_LEVEL="${arg#--log-level=}" ;;
        --status)                 LOG_LEVEL=quiet ;;
        --ignore-file=*)          load_ignore_file "${arg#--ignore-file=}" ;;
        --ignore-repo=*)          IGNORE_REPOS+=("${arg#--ignore-repo=}") ;;
        --ignore-pattern=*)       IGNORE_PATTERNS+=("${arg#--ignore-pattern=}") ;;
        --ignore-secret-label=*)  IGNORE_SECRET_LABELS+=("${arg#--ignore-secret-label=}") ;;
        --help|-h)                usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
    esac
done

export USERNAME LOG_LEVEL PRIMARY_EMAIL CLONE_MODE
export IGNORE_REPOS IGNORE_PATTERNS IGNORE_SECRET_LABELS IGNORE_REPO_PATTERN_COMBOS

TMP_DIR="/tmp/github-recon-${USERNAME}"
REPORT_DIR="$TMP_DIR/report"

mkdir -p "$TMP_DIR" "$REPORT_DIR"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
FINDINGS_FILE="${REPORT_DIR}/${USERNAME}-${TIMESTAMP}.json"
REPORT_FILE="${REPORT_DIR}/${USERNAME}-${TIMESTAMP}.md"
export TMP_DIR FINDINGS_FILE REPORT_FILE
touch "$FINDINGS_FILE"

load_ignore_file ".github-recon-ignore"

log_normal "${BOLD}${CYAN}GitHub Recon:${NC} ${BOLD}${USERNAME}${NC} ${DIM}(${LOG_LEVEL} mode)${NC}"

BASH_MODULES=(
    profile repos commit_emails sensitive_files secret_patterns
    gists tags releases issues pull_requests reviews forks org_repos wikis
)
PYTHON_SCANNERS=(discussions actions pages packages)

CLONE_MODULES=(deep_scan)

TOTAL=$(( ${#BASH_MODULES[@]} + ${#PYTHON_SCANNERS[@]} ))
[[ "$CLONE_MODE" == true ]] && TOTAL=$(( TOTAL + ${#CLONE_MODULES[@]} ))
N=0

for mod in "${BASH_MODULES[@]}"; do
    N=$(( N + 1 ))
    MOD="$SCRIPT_DIR/modules/${mod}.sh"
    if [[ -f "$MOD" ]]; then
        log_progress "$N" "$TOTAL" "Scanning ${mod//_/ }..."
        bash "$MOD" >> "$FINDINGS_FILE" || log_verbose "Module $mod exited non-zero"
    else
        log_verbose "Skipping $mod (not found)"
    fi
done

for scanner in "${PYTHON_SCANNERS[@]}"; do
    N=$(( N + 1 ))
    SCAN="$SCRIPT_DIR/scanners/${scanner}.py"
    if [[ -f "$SCAN" ]] && command -v python3 &>/dev/null; then
        log_progress "$N" "$TOTAL" "Scanning ${scanner}..."
        python3 "$SCAN" "$USERNAME" --log-level="$LOG_LEVEL" >> "$FINDINGS_FILE" || log_verbose "Scanner $scanner exited non-zero"
    else
        log_verbose "Skipping $scanner (not found or python3 unavailable)"
    fi
done

if [[ "$CLONE_MODE" == true ]]; then
    for mod in "${CLONE_MODULES[@]}"; do
        N=$(( N + 1 ))
        MOD="$SCRIPT_DIR/modules/${mod}.sh"
        if [[ -f "$MOD" ]]; then
            log_progress "$N" "$TOTAL" "Deep scanning (git clone)..."
            bash "$MOD" >> "$FINDINGS_FILE" || log_verbose "Module $mod exited non-zero"
        fi
    done
fi

TOTAL_FINDINGS=$(wc -l < "$FINDINGS_FILE" || echo 0)
log_normal "Scan complete — ${TOTAL_FINDINGS} finding(s)"
log_normal "Findings JSON: $FINDINGS_FILE"
log_normal "Report:        $REPORT_FILE"

{
    echo "# GitHub Recon Report: ${USERNAME}"
    echo "Date: $(date)"
    echo ""
    echo "## Summary"
    echo ""
    if [[ -s "$FINDINGS_FILE" ]]; then
        { echo "| Severity | Module | Type | Target | Detail |"
          echo "|----------|--------|------|--------|--------|"
          jq -r 'select(.module != null) | "| \(.severity) | \(.module) | \(.type) | \(.target // .repo // "-") | \(.detail) |"' "$FINDINGS_FILE"
        }
    else
        echo "No findings."
    fi
} > "$REPORT_FILE"

if [[ "$LOG_LEVEL" == "quiet" ]]; then
    # Filter to valid JSON objects only before aggregating
    grep -E '^\{' "$FINDINGS_FILE" | \
        jq -s '{total: length, by_severity: (group_by(.severity) | map({(.[0].severity): length}) | add // {}), findings: .}'
fi
