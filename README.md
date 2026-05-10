# GitHub Recon Scanner

Modular Bash tool to audit a GitHub account for exposed private identity data, leaked secrets, and sensitive metadata across the full surface area of a public profile.

## License
MIT License. Copyright (c) 2026 MPZ-00.

## What it detects

| Surface | What is scanned |
|---------|----------------|
| **Profile** | Real name, public email, employer, location, blog, Twitter handle |
| **Repositories** | Email addresses in descriptions, sensitive repo names |
| **Commit events** | Non-noreply author emails in public push events |
| **Sensitive files** | `.env`, `credentials`, SSH keys, cloud configs, and 14 other patterns |
| **Secret patterns** | AWS keys, GitHub tokens, Stripe, OpenAI, Slack, JWT, DB URLs, and more |
| **Gists** | Sensitive filenames and emails in gist descriptions |
| **Tags** | Tagger email in annotated git tags and tag messages |
| **Releases** | Emails in release bodies, sensitive asset names |
| **Issues** | Emails in issue titles, bodies, and comments |
| **Pull requests** | Emails in PR bodies and comments |
| **PR Reviews** | Emails in review bodies |
| **Discussions** | Emails in discussion bodies and comments (via GraphQL) |
| **Wikis** | Emails in wiki content (cloned) |
| **Forks** | Author emails in commits to forked repos |
| **Org repos** | Author emails in commits to org-owned repos |
| **Actions** | Commit author emails in workflow runs, sensitive artifact names |
| **GitHub Pages** | Emails scraped from published Pages sites (depth-2 crawl) |
| **Packages** | Author emails in GitHub Packages, npm, and PyPI registry metadata |
| **Deep scan** | Full git history via `gitleaks` or pattern grep (requires `--clone`) |

## Architecture

```
github-recon.sh          ← orchestrator: arg parsing + module dispatch
lib/
  auth.sh                ← gh CLI / GITHUB_TOKEN auto-detection
  log.sh                 ← log levels: quiet | normal | verbose | debug
  logging.sh             ← compatibility shim (log_info → log_normal etc.)
  api.sh                 ← api_get(), api_get_all() with rate-limit retry
  config.sh              ← shared env vars, ignore rules, EMAIL_REGEX
  findings.sh            ← emit_finding(), extract_emails()
modules/                 ← Bash modules, one responsibility each
  profile.sh  repos.sh  commit_emails.sh  sensitive_files.sh
  secret_patterns.sh  gists.sh  tags.sh  releases.sh
  issues.sh  pull_requests.sh  reviews.sh
  forks.sh  org_repos.sh  wikis.sh  deep_scan.sh
scanners/                ← Python scanners for GraphQL / complex APIs
  discussions.py  actions.py  pages.py  packages.py
reports/                 ← JSON findings and Markdown reports (gitignored)
```

Each module is a standalone bash script that:
- Sources `lib/` for shared helpers
- Inherits config via exported env vars
- Writes NDJSON findings to stdout
- Writes progress/errors to stderr

## Requirements

- `bash` 4+
- `curl`
- `jq`
- `git`
- `python3` (for `scanners/`)

Optional:
- `gh` (GitHub CLI) — preferred auth method; auto-detected
- `gitleaks` — used by `deep_scan` for high-fidelity secret detection

## Authentication

The tool auto-detects the best available auth method in order:

1. **GitHub CLI** — if `gh auth status` passes, uses `gh auth token`
2. **`GITHUB_TOKEN` env var** — bearer token in curl requests
3. **Unauthenticated** — works but rate-limited to 60 requests/hour

```bash
# Option 1 — gh CLI (recommended)
gh auth login
./github-recon.sh <username>

# Option 2 — token
GITHUB_TOKEN=ghp_xxx ./github-recon.sh <username>
```

## Usage

```bash
./github-recon.sh <github-username> [options]
```

| Flag | Description |
|------|-------------|
| `--clone` | Enable deep scan (git clone + history) |
| `--email=ADDR` | Expected primary email for consistency checks |
| `--log-level=LEVEL` | `quiet` \| `normal` \| `verbose` \| `debug` (default: `normal`) |
| `--status` | Deprecated alias for `--log-level=quiet` |
| `--ignore-file=PATH` | Load ignore rules from file |
| `--ignore-repo=NAME` | Ignore a specific repo (repeatable) |
| `--ignore-pattern=PATTERN` | Ignore a filename pattern (repeatable) |
| `--ignore-secret-label=LBL` | Ignore a secret type (repeatable) |
| `--help` | Show help and exit |

### Examples

```bash
# Basic scan
./github-recon.sh torvalds

# Verbose output
./github-recon.sh torvalds --log-level=verbose

# Deep scan with primary email check
./github-recon.sh torvalds --clone --email=torvalds@linux-foundation.org

# Suppress known false positives
./github-recon.sh torvalds \
  --ignore-repo=my-demo-repo \
  --ignore-pattern=.env.example

# Quiet mode — only final JSON summary to stdout
./github-recon.sh torvalds --log-level=quiet | jq .
```

### Ignore file

`.github-recon-ignore` in the current directory is loaded automatically if present.

```text
# Comments are supported
repo:my-demo-repo
pattern:.env.example
secret:Password Assignment
my-demo-repo:.env
```

## Output

Findings are written as NDJSON to `reports/<username>-<timestamp>.json`:

```json
{"module":"profile","severity":"high","type":"email_leak","target":"profile","pattern":"email","detail":"user@example.com","url":"https://github.com/user"}
```

A Markdown summary table is written to `reports/<username>-<timestamp>.md`.

In `--log-level=quiet` mode the final JSON summary is also printed to stdout:

```json
{
  "total": 12,
  "by_severity": {"critical": 1, "high": 5, "medium": 4, "low": 2},
  "findings": [...]
}
```

## Notes

- Designed for auditing your own public GitHub footprint.
- GitHub Search API is rate-limited; authenticated requests are strongly recommended.
- Findings are candidates — manually validate before acting on them.
- `scanners/` require only Python stdlib + no third-party packages.
