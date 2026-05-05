#!/usr/bin/env bash
# ============================================================================
# github-recon.sh ─ GitHub OSINT & Secrets Scanner
# quick and practical script that gets the job done
# Goal: Check your own GitHub repos for exposed data
# Usage: ./github-recon.sh <github-username> [--clone]
# License: MIT
# Author: MPZ-00
# 
# Flags:
#   --clone    Clones all public repos locally and scans git history
#              (without flag: API-based analysis only, no clone)
# 
# Requirements:
#   - curl, jq, git (standard)
#   - Optional: gitleaks, trufflehog (for deep scans)
#   - Optional: GITHUB_TOKEN env-var for higher API rate limits
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CLONE_REPOS=false
USERNAME=""
PRIMARY_EMAIL=""
WORKDIR=""
REPORT_FILE=""

# --- Argument Parsing ---
for arg in "$@"; do
    case "$arg" in
        --clone) CLONE_REPOS=true ;;
        --email=*) PRIMARY_EMAIL="${arg#*=}" ;;
        --help|-h)
            echo "Usage: $0 <github-username> [--clone] [--email=primary@example.com]"
            echo "  --clone              Clones repos and scans git history (slower, more thorough)"
            echo "  --email=addr         Primary email address for consistency checks"
            exit 0
            ;;
        *) USERNAME="$arg" ;;
    esac
done

if [[ -z "$USERNAME" ]]; then
    echo -e "${RED}Error: Please provide a GitHub username as an argument.${NC}"
    echo "Usage: $0 <github-username> [--clone] [--email=primary@example.com]"
    exit 1
fi

WORKDIR="/tmp/github-recon-${USERNAME}"
REPORT_FILE="${WORKDIR}/recon-report.md"
mkdir -p "$WORKDIR"

# Email consistency info in report
if [[ -n "$PRIMARY_EMAIL" ]]; then
    echo -e "${GREEN}[+] Primary email for consistency checks: $PRIMARY_EMAIL${NC}"
fi

# GitHub API Header
AUTH_HEADER=""
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
    echo -e "${GREEN}[+] GitHub token detected - higher rate limit enabled${NC}"
fi

api_get() {
    local url="$1"
    if [[ -n "$AUTH_HEADER" ]]; then
        curl -sL -H "$AUTH_HEADER" -H "Accept: application/vnd.github+json" "$url"
    else
        curl -sL -H "Accept: application/vnd.github+json" "$url"
    fi
}

# Validate whether string is valid JSON
is_valid_json() {
    echo "$1" | jq empty 2>/dev/null
    return $?
}

# ============================================================================
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           GitHub OSINT Recon ─ $USERNAME"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# --- Initialize report ---
cat > "$REPORT_FILE" << EOF
# GitHub Recon Report: $USERNAME
**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Mode:** $(if $CLONE_REPOS; then echo "Deep scan (with clone)"; else echo "API only (without clone)"; fi)

---

EOF

# Validate API connectivity
echo -e "${BOLD}[0/7] API validation${NC}"
TEST_API=$(api_get "https://api.github.com/users/${USERNAME}")
if ! is_valid_json "$TEST_API"; then
    echo -e "${RED}Error: GitHub API did not return valid data.${NC}"
    echo -e "${RED}Check: 1) username 2) internet connection 3) GITHUB_TOKEN${NC}"
    exit 1
fi

# ============================================================================
# 1. PROFILE ANALYSIS
# ============================================================================
echo -e "${BOLD}[1/7] Profile analysis${NC}"

PROFILE=$(api_get "https://api.github.com/users/${USERNAME}")

# Validate profile response
if ! is_valid_json "$PROFILE"; then
    echo -e "${RED}Error: Could not fetch profile${NC}"
    exit 1
fi

# Check API errors (e.g. "Not Found")
if echo "$PROFILE" | jq -e '.message' >/dev/null 2>&1; then
    ERROR_MSG=$(echo "$PROFILE" | jq -r '.message')
    echo -e "${RED}GitHub API Error: $ERROR_MSG${NC}"
    exit 1
fi

REAL_NAME=$(echo "$PROFILE" | jq -r '.name // empty')
BIO=$(echo "$PROFILE" | jq -r '.bio // empty')
COMPANY=$(echo "$PROFILE" | jq -r '.company // empty')
LOCATION=$(echo "$PROFILE" | jq -r '.location // empty')
BLOG=$(echo "$PROFILE" | jq -r '.blog // empty')
EMAIL_PUBLIC=$(echo "$PROFILE" | jq -r '.email // empty')
TWITTER=$(echo "$PROFILE" | jq -r '.twitter_username // empty')
CREATED=$(echo "$PROFILE" | jq -r '.created_at // empty')
PUBLIC_REPOS=$(echo "$PROFILE" | jq -r '.public_repos // 0')
FOLLOWERS=$(echo "$PROFILE" | jq -r '.followers // 0')

# If PRIMARY_EMAIL is not set and profile has public email, use it as default
if [[ -z "$PRIMARY_EMAIL" ]] && [[ -n "$EMAIL_PUBLIC" ]]; then
    PRIMARY_EMAIL="$EMAIL_PUBLIC"
    echo -e "  ${CYAN}Primary email auto-detected: $PRIMARY_EMAIL${NC}"
fi

echo -e "  Name:       ${REAL_NAME:-"not set"}"
echo -e "  Bio:        ${BIO:-"not set"}"
echo -e "  Company:    ${COMPANY:-"not set"}"
echo -e "  Location:   ${LOCATION:-"not set"}"
echo -e "  Blog:       ${BLOG:-"not set"}"
echo -e "  E-Mail:     ${EMAIL_PUBLIC:-"not set"}"
echo -e "  Twitter:    ${TWITTER:-"not set"}"
echo -e "  Created:    ${CREATED:-"unknown"}"
echo -e "  Repos:      $PUBLIC_REPOS"
echo -e "  Followers:  $FOLLOWERS"

# Profile risk assessment
PROFILE_RISKS=""
[[ -n "$REAL_NAME" ]] && PROFILE_RISKS+="  - ⚠️  Real name visible in profile: $REAL_NAME\n"
[[ -n "$COMPANY" ]] && PROFILE_RISKS+="  - ⚠️  Employer visible: $COMPANY\n"
[[ -n "$LOCATION" ]] && PROFILE_RISKS+="  - ⚠️  Location visible: $LOCATION\n"
[[ -n "$EMAIL_PUBLIC" ]] && PROFILE_RISKS+="  - 🔴 Email is public: $EMAIL_PUBLIC\n"

if [[ -n "$PROFILE_RISKS" ]]; then
    echo -e "\n${YELLOW}  Findings:${NC}"
    echo -e "$PROFILE_RISKS"
fi

cat >> "$REPORT_FILE" << EOF
## 1. Profile Analysis

| Field | Value | Risk |
|------|------|--------|
| Name | ${REAL_NAME:-"not set"} | $(if [[ -n "$REAL_NAME" ]]; then echo "⚠️ Real name exposed"; else echo "✅"; fi) |
| Bio | ${BIO:-"not set"} | Info |
| Company | ${COMPANY:-"not set"} | $(if [[ -n "$COMPANY" ]]; then echo "⚠️ Employer visible"; else echo "✅"; fi) |
| Location | ${LOCATION:-"not set"} | $(if [[ -n "$LOCATION" ]]; then echo "⚠️ Location visible"; else echo "✅"; fi) |
| Blog | ${BLOG:-"not set"} | Info |
| E-Mail | ${EMAIL_PUBLIC:-"not set"} | $(if [[ -n "$EMAIL_PUBLIC" ]]; then echo "🔴 Public"; else echo "✅"; fi) |
| Twitter | ${TWITTER:-"not set"} | Info |
| Created | ${CREATED:-"unknown"} | Info |
| Public Repos | $PUBLIC_REPOS | Info |

EOF

# ============================================================================
# 2. REPOSITORY ANALYSIS
# ============================================================================
echo -e "\n${BOLD}[2/7] Repository analysis${NC}"

REPOS_JSON=$(api_get "https://api.github.com/users/${USERNAME}/repos?per_page=100&sort=updated")

if ! is_valid_json "$REPOS_JSON"; then
    REPO_COUNT=0
    echo -e "  ${YELLOW}API error while fetching repos${NC}"
else
    REPO_COUNT=$(echo "$REPOS_JSON" | jq '[.[] | objects] | length')
fi
echo -e "  Repos found: $REPO_COUNT"

cat >> "$REPORT_FILE" << EOF
## 2. Repositories ($REPO_COUNT found)

| Repo | Stars | Forks | Language | Description |
|------|--------|-------|---------|---------------|
EOF

if [[ "$REPO_COUNT" -gt 0 ]]; then
    echo "$REPOS_JSON" | jq -r '[.[] | objects] | .[] | "| [\(.name)](https://github.com/'"$USERNAME"'/\(.name)) | \(.stargazers_count) | \(.forks_count) | \(.language // "-") | \(.description // "-") |"' >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# ============================================================================
# 3. COMMIT EMAIL EXTRACTION (via API events)
# ============================================================================
echo -e "\n${BOLD}[3/7] Commit email extraction${NC}"

EVENTS=$(api_get "https://api.github.com/users/${USERNAME}/events/public?per_page=100")
COMMIT_EMAILS=$(echo "$EVENTS" | jq -r '
    [.[] | select(.type == "PushEvent") | .payload.commits[]? | .author.email] 
    | unique | .[]' 2>/dev/null || echo "")

COMMIT_NAMES=$(echo "$EVENTS" | jq -r '
    [.[] | select(.type == "PushEvent") | .payload.commits[]? | .author.name] 
    | unique | .[]' 2>/dev/null || echo "")

cat >> "$REPORT_FILE" << EOF
## 3. Commit Metadata (from public events)

### Email addresses in commits
EOF

if [[ -n "$COMMIT_EMAILS" ]]; then
    echo -e "${YELLOW}  Found email addresses:${NC}"
    MISMATCHED_EMAILS=0
    while IFS= read -r email; do
        echo -e "    - $email"
        # Check if this is a noreply address
        if [[ "$email" == *"noreply.github.com"* ]]; then
            echo "- ✅ \`$email\` (GitHub noreply - safe)" >> "$REPORT_FILE"
        else
            # Check against PRIMARY_EMAIL if set
            if [[ -n "$PRIMARY_EMAIL" ]] && [[ "$email" != "$PRIMARY_EMAIL" ]]; then
                # Find repos where this email appears
                REPOS_WITH_EMAIL=$(echo "$EVENTS" | jq -r --arg email "$email" '[
                    .[] | select(.type == "PushEvent" and (.payload.commits[]?.author.email == $email)) | .repo.name
                ] | unique | .[]' 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
                echo -e "    ${RED}[!] 🔴 Email does not match primary: ${email}${NC}"
                echo -e "        Repos: ${REPOS_WITH_EMAIL}"
                echo "- 🔴 \`$email\` (non-primary email!) in repos: ${REPOS_WITH_EMAIL}" >> "$REPORT_FILE"
                MISMATCHED_EMAILS=$((MISMATCHED_EMAILS + 1))
            else
                echo "- 🔴 \`$email\` (personal email exposed!)" >> "$REPORT_FILE"
            fi
        fi
    done <<< "$COMMIT_EMAILS"
    
    if [[ $MISMATCHED_EMAILS -gt 0 ]]; then
        echo -e "\n${YELLOW}  ⚠️  ${MISMATCHED_EMAILS} email(s) do not match the primary address!${NC}"
    fi
else
    echo -e "  ${GREEN}No emails found in public events${NC}"
    echo "No emails found in public events." >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "### Commit author names" >> "$REPORT_FILE"

if [[ -n "$COMMIT_NAMES" ]]; then
    echo -e "\n${YELLOW}  Found commit author names:${NC}"
    while IFS= read -r name; do
        echo -e "    - $name"
        echo "- \`$name\`" >> "$REPORT_FILE"
    done <<< "$COMMIT_NAMES"
fi
echo "" >> "$REPORT_FILE"

# ============================================================================
# 4. SENSITIVE FILE SCAN (via API)
# ============================================================================
echo -e "\n${BOLD}[4/7] Sensitive file scan (API-based)${NC}"

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

cat >> "$REPORT_FILE" << EOF
## 4. Sensitive files

EOF

FOUND_SENSITIVE=0

if [[ "$REPO_COUNT" -gt 0 ]]; then
for repo_name in $(echo "$REPOS_JSON" | jq -r '[.[] | objects] | .[].name'); do
    for pattern in "${SENSITIVE_PATTERNS[@]}"; do
        # GitHub code search API
        SEARCH_RESULT=$(api_get "https://api.github.com/search/code?q=filename:${pattern}+repo:${USERNAME}/${repo_name}" 2>/dev/null || echo '{"total_count":0}')
        COUNT=$(echo "$SEARCH_RESULT" | jq -r '.total_count // 0')
        
        if [[ "$COUNT" -gt 0 ]]; then
            echo -e "  ${RED}[!] ${repo_name}: ${pattern} found (${COUNT}x)${NC}"
            echo "- 🔴 **${repo_name}**: \`${pattern}\` found (${COUNT}x)" >> "$REPORT_FILE"
            FOUND_SENSITIVE=$((FOUND_SENSITIVE + 1))
        fi
    done
    
    # Rate limit protection
    sleep 0.5
done
fi

if [[ "$FOUND_SENSITIVE" -eq 0 ]]; then
    echo -e "  ${GREEN}No obviously sensitive files found${NC}"
    echo "✅ No obviously sensitive files found in repos." >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# ============================================================================
# 5. SECRET PATTERN SCAN (via GitHub code search)
# ============================================================================
echo -e "\n${BOLD}[5/7] Secret pattern scan${NC}"

declare -A SECRET_PATTERNS=(
    ["AWS Access Key"]="AKIA"
    ["GitHub Token"]="ghp_"
    ["GitHub OAuth"]="gho_"
    ["Slack Token"]="xoxb-"
    ["Slack Webhook"]="hooks.slack.com"
    ["Anthropic API Key"]="sk-ant-"
    ["OpenAI API Key"]="sk-proj-"
    ["Stripe Key"]="sk_live_"
    ["Stripe Test Key"]="sk_test_"
    ["Private Key"]="PRIVATE KEY"
    ["Password Assignment"]="password="
    ["DB Connection String"]="postgresql://"
    ["MongoDB URI"]="mongodb+srv://"
    ["JWT Secret"]="JWT_SECRET"
    ["API_KEY variable"]="API_KEY="
    ["Sendgrid"]="SG."
    ["Twilio"]="TWILIO"
)

cat >> "$REPORT_FILE" << EOF
## 5. Secret pattern scan

EOF

FOUND_SECRETS=0

for label in "${!SECRET_PATTERNS[@]}"; do
    pattern="${SECRET_PATTERNS[$label]}"
    SEARCH_RESULT=$(api_get "https://api.github.com/search/code?q=${pattern}+user:${USERNAME}" 2>/dev/null || echo '{"total_count":0}')
    COUNT=$(echo "$SEARCH_RESULT" | jq -r '.total_count // 0')
    
    if [[ "$COUNT" -gt 0 ]]; then
        REPOS_WITH_SECRET=$(echo "$SEARCH_RESULT" | jq -r '.items[].repository.name' 2>/dev/null | sort -u | tr '\n' ', ' | sed 's/,$//')
        echo -e "  ${RED}[!] ${label}: ${COUNT} matches in [${REPOS_WITH_SECRET}]${NC}"
        echo "- 🔴 **${label}** (\`${pattern}\`): ${COUNT} matches in ${REPOS_WITH_SECRET}" >> "$REPORT_FILE"
        FOUND_SECRETS=$((FOUND_SECRETS + 1))
    fi
    
    # Rate limit protection (search API is strictly limited)
    sleep 2
done

if [[ "$FOUND_SECRETS" -eq 0 ]]; then
    echo -e "  ${GREEN}No secret patterns found in code${NC}"
    echo "✅ No secret patterns found in public code." >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# ============================================================================
# 6. GIST ANALYSIS
# ============================================================================
echo -e "\n${BOLD}[6/7] Gist analysis${NC}"

GISTS=$(api_get "https://api.github.com/users/${USERNAME}/gists?per_page=100")

if ! is_valid_json "$GISTS"; then
    echo -e "  ${YELLOW}API error while fetching gists${NC}"
    GIST_COUNT=0
else
    GIST_COUNT=$(echo "$GISTS" | jq '[.[] | objects] | length')
fi
echo -e "  Public gists: $GIST_COUNT"

cat >> "$REPORT_FILE" << EOF
## 6. Public gists ($GIST_COUNT)

EOF

if [[ "$GIST_COUNT" -gt 0 ]]; then
    echo "$GISTS" | jq -r '[.[] | objects] | .[] | "- [\(.description // .id)](\(.html_url)) ─ Dateien: \([.files | objects | keys[]] | join(", "))"' >> "$REPORT_FILE"
    
    # Check gist filenames for sensitive patterns
    GIST_FILES=$(echo "$GISTS" | jq -r '.[] | select(.files != null) | .files | keys[]')
    while IFS= read -r gfile; do
        case "$gfile" in
            *.env*|*credential*|*secret*|*password*|*token*|*.pem|*.key)
                echo -e "  ${RED}[!] Sensitive gist filename: ${gfile}${NC}"
                echo "- 🔴 Sensitive filename: \`${gfile}\`" >> "$REPORT_FILE"
                ;;
        esac
    done <<< "$GIST_FILES"
else
    echo "No public gists." >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# ============================================================================
# 7. DEEP SCAN (only with --clone)
# ============================================================================
if $CLONE_REPOS; then
    echo -e "\n${BOLD}[7/7] Deep scan - git history${NC}"
    
    CLONE_DIR="${WORKDIR}/repos"
    mkdir -p "$CLONE_DIR"
    
    cat >> "$REPORT_FILE" << EOF
## 7. Deep scan - git history

EOF
    
    # Check if gitleaks is available
    HAS_GITLEAKS=false
    if command -v gitleaks &>/dev/null; then
        HAS_GITLEAKS=true
        echo -e "  ${GREEN}gitleaks detected - will be used for deep scan${NC}"
    fi
    
    for repo_name in $(echo "$REPOS_JSON" | jq -r '.[].name'); do
        echo -e "  Scanning: ${CYAN}${repo_name}${NC}"
        REPO_DIR="${CLONE_DIR}/${repo_name}"
        
        if [[ ! -d "$REPO_DIR" ]]; then
            git clone --quiet "https://github.com/${USERNAME}/${repo_name}.git" "$REPO_DIR" 2>/dev/null || continue
        fi
        
        cd "$REPO_DIR"
        
        # Emails from full git history
        HIST_EMAILS=$(git log --all --format='%ae' 2>/dev/null | sort -u)
        HIST_NAMES=$(git log --all --format='%an' 2>/dev/null | sort -u)
        
        NEW_EMAILS=""
        while IFS= read -r e; do
            [[ -z "$e" ]] && continue
            [[ "$e" == *"noreply.github.com"* ]] && continue
            NEW_EMAILS+="$e\n"
        done <<< "$HIST_EMAILS"
        
        if [[ -n "$NEW_EMAILS" ]]; then
            echo -e "    ${YELLOW}Emails: $(echo -e "$NEW_EMAILS" | tr '\n' ', ')${NC}"
            echo "### ${repo_name}" >> "$REPORT_FILE"
            echo "**Commit emails:**" >> "$REPORT_FILE"
            echo -e "$NEW_EMAILS" | while read -r em; do
                [[ -n "$em" ]] && echo "- \`$em\`" >> "$REPORT_FILE"
            done
        fi
        
        # Search for deleted .env files in history
        DELETED_SECRETS=$(git log --all --diff-filter=D --name-only --pretty=format: -- '*.env' '*.env.*' '*.pem' '*.key' '*credentials*' 2>/dev/null | sort -u | grep -v '^$' || true)
        if [[ -n "$DELETED_SECRETS" ]]; then
            echo -e "    ${RED}[!] Deleted sensitive files in history:${NC}"
            echo "**Deleted sensitive files (still in git history!):**" >> "$REPORT_FILE"
            while IFS= read -r df; do
                echo -e "      - $df"
                echo "- 🔴 \`$df\`" >> "$REPORT_FILE"
            done <<< "$DELETED_SECRETS"
        fi
        
        # gitleaks deep scan
        if $HAS_GITLEAKS; then
            GITLEAKS_REPORT="${WORKDIR}/gitleaks-${repo_name}.json"
            gitleaks detect --source="$REPO_DIR" --report-path="$GITLEAKS_REPORT" --report-format=json 2>/dev/null || true
            
            if [[ -f "$GITLEAKS_REPORT" ]] && [[ $(jq length "$GITLEAKS_REPORT") -gt 0 ]]; then
                LEAK_COUNT=$(jq length "$GITLEAKS_REPORT")
                echo -e "    ${RED}[!] gitleaks: ${LEAK_COUNT} potential secrets found${NC}"
                echo "**gitleaks: ${LEAK_COUNT} Findings** (Details in \`gitleaks-${repo_name}.json\`)" >> "$REPORT_FILE"
            fi
        fi
        
        # Manual pattern scan in history (fallback without gitleaks)
        if ! $HAS_GITLEAKS; then
            HISTORY_SECRETS=$(git log --all -p 2>/dev/null | grep -iE '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-ant-|sk-proj-|xoxb-|-----BEGIN (RSA |EC )?PRIVATE KEY)' | head -20 || true)
            if [[ -n "$HISTORY_SECRETS" ]]; then
                MATCH_COUNT=$(echo "$HISTORY_SECRETS" | wc -l)
                echo -e "    ${RED}[!] ${MATCH_COUNT} potential secrets in git history${NC}"
                echo "**Pattern scan: ${MATCH_COUNT} potential secrets in history**" >> "$REPORT_FILE"
            fi
        fi
        
        # Email consistency check in git history
        if [[ -n "$PRIMARY_EMAIL" ]]; then
            echo "### Email consistency in ${repo_name}" >> "$REPORT_FILE"
            HIST_EMAILS=$(git log --all --format='%ae' 2>/dev/null | sort -u)
            NON_PRIMARY_EMAILS=""
            while IFS= read -r em; do
                [[ -z "$em" ]] && continue
                [[ "$em" == *"noreply.github.com"* ]] && continue
                if [[ "$em" != "$PRIMARY_EMAIL" ]]; then
                    NON_PRIMARY_EMAILS+="$em\n"
                fi
            done <<< "$HIST_EMAILS"
            
            if [[ -n "$NON_PRIMARY_EMAILS" ]]; then
                echo -e "    ${RED}[!] Emails do not match the primary address:${NC}"
                echo -e "$NON_PRIMARY_EMAILS" | while read -r em; do
                    [[ -n "$em" ]] && echo -e "      - $em"
                    # Find commit count for this email
                    COMMIT_COUNT=$(git log --all --format='%ae' 2>/dev/null | grep -c "^$em$" || echo "0")
                    echo "- 🔴 \`$em\` ($COMMIT_COUNT Commits)" >> "$REPORT_FILE"
                done
            else
                echo "- ✅ All commits use the primary email" >> "$REPORT_FILE"
            fi
            echo "" >> "$REPORT_FILE"
        fi
        
        cd "$WORKDIR"
    done
else
    echo -e "\n${BOLD}[7/7] Deep scan - skipped (use --clone for git history analysis)${NC}"
    echo "## 7. Deep Scan" >> "$REPORT_FILE"
    echo "Skipped - \`--clone\` flag not set." >> "$REPORT_FILE"
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} Scan completed!${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e " Report: ${GREEN}${REPORT_FILE}${NC}"
echo -e " Workdir: ${WORKDIR}"
echo ""

cat >> "$REPORT_FILE" << EOF

---

## Recommended next steps

1. **Immediate:** Switch all exposed Git emails to noreply: \`git config user.email "user@users.noreply.github.com"\`
2. **Immediate:** Rotate discovered secrets (generate new keys, revoke old ones)
3. **Short-term:** Check \`.gitignore\` in all repos for sensitive files
4. **Short-term:** Clean up GitHub profile (remove real name, company, location if undesired)
5. **Mid-term:** Use \`git filter-branch\` or \`git-filter-repo\` to remove secrets from history
6. **Ongoing:** Enable GitHub Secret Scanning and Push Protection

---
*Generated by github-recon.sh on $(date '+%Y-%m-%d %H:%M:%S')*
EOF

echo -e " ${BOLD}Tip:${NC} For maximum depth:"
echo -e "   1. Install \`gitleaks\`"
echo -e "   2. Run script with \`--clone\`"
echo -e "   3. \`GITHUB_TOKEN=ghp_xxx ./github-recon.sh $USERNAME --clone\`"
