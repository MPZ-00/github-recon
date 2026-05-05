# GitHub Recon Scanner
Lightweight Bash tool to audit a GitHub account for exposed metadata, secrets, and risky files.

## License
MIT License. Copyright (c) 2026 MPZ-00.

## What it does
- Reviews profile visibility signals (name, location, company, public email)
- Enumerates repositories and basic repo metadata
- Extracts commit author emails and names from public events
- Scans for sensitive filenames via GitHub Code Search
- Scans for common secret patterns in public code
- Reviews public gists for sensitive filenames
- Optional deep scan mode with local clone and git history checks

## Features
- API-only mode for fast, no-clone analysis
- Deep scan mode for historical exposure checks
- Parallelized search with adaptive rate-limit retry handling
- Primary email consistency check across commits
- Ignore rules for known false positives (file + CLI)
- Status mode for reduced scan noise in terminal output
- Markdown report output with findings and next steps
- Optional token support for better GitHub API limits

## Requirements
- bash
- curl
- jq
- git

Optional:
- gitleaks (recommended for deep scanning)
- trufflehog

## Usage
Basic scan:
```bash
./github-recon.sh <github-username>
```

Deep scan with local clone:
```bash
./github-recon.sh <github-username> --clone
```

Specify expected primary email:
```bash
./github-recon.sh <github-username> --email=primary@example.com
```

With authenticated GitHub API access:
```bash
GITHUB_TOKEN=ghp_xxx ./github-recon.sh <github-username> --clone
```

Help:
```bash
./github-recon.sh --help
```

Status-focused output (reduced finding noise):
```bash
./github-recon.sh <github-username> --status
```

Ignore known false positives from CLI:
```bash
./github-recon.sh <github-username> \
	--ignore-repo=my-demo-repo \
	--ignore-pattern=.env.example \
	--ignore-secret-label="Password Assignment"
```

Use ignore rules from file:
```bash
./github-recon.sh <github-username> --ignore-file=.github-recon-ignore
```

Default ignore file:
- If present, `.github-recon-ignore` in the current directory is loaded automatically.

Ignore file format:
```text
# Comments are supported
repo:my-demo-repo
pattern:.env.example
secret_label:Password Assignment
repo_pattern:my-demo-repo:.env
```

## Output
- Working directory: /tmp/github-recon-\<username>
- Main report: /tmp/github-recon-\<username>/recon-report.md
- Deep scan leak reports (if enabled): /tmp/github-recon-\<username>/gitleaks-\<repo>.json

## Notes
- This tool is designed for auditing your own assets and improving operational security.
- GitHub Search APIs are rate-limited; authenticated requests improve reliability.
- Findings indicate risk candidates and should be manually validated.
