#!/usr/bin/env python3
"""Scan GitHub Actions runs and artifacts for leaked identity data."""
import argparse, base64, json, os, re, subprocess, sys, time
import urllib.request, urllib.error

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@(?!users\.noreply\.github\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
SENSITIVE_NAME_RE = re.compile(r'\.(key|pem|env|p12|pfx)$|credential|secret|password|token', re.IGNORECASE)
SECRET_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}'
    r'|sk-ant-[A-Za-z0-9\-_]{20,}|sk-proj-[A-Za-z0-9\-_]{20,}'
    r'|xoxb-[A-Za-z0-9\-]+'
    r'|-----BEGIN (?:RSA |EC )?PRIVATE KEY)'
)

MODULE = "actions"


def get_token():
    try:
        result = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return os.environ.get('GITHUB_TOKEN', '')


def api_get(url, token, log_level="normal"):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read()), dict(resp.headers)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                retry_after = e.headers.get("Retry-After")
                rate_reset = e.headers.get("X-RateLimit-Reset")
                if retry_after:
                    wait = int(retry_after)
                elif rate_reset:
                    wait = max(1, int(rate_reset) - int(time.time()))
                else:
                    wait = attempt * 2
                log("normal", f"Rate limited on {url}, waiting {wait}s (attempt {attempt}/5)", log_level)
                time.sleep(wait)
                continue
            log("verbose", f"HTTP {e.code} for {url}", log_level)
            return None, {}
        except Exception as exc:
            log("verbose", f"Request error for {url}: {exc}", log_level)
            return None, {}
    return None, {}


def api_get_all(url, token, log_level="normal"):
    """Fetch all pages following Link: rel=next headers, returning a flat list."""
    results = []
    next_url = url
    while next_url:
        data, headers = api_get(next_url, token, log_level)
        if data is None:
            break
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            # Envelope response — extract the first list value (e.g. workflow_runs, artifacts)
            for v in data.values():
                if isinstance(v, list):
                    results.extend(v)
                    break
        link = headers.get("Link", "")
        next_url = None
        for part in link.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                next_url = part.split(";")[0].strip().strip("<>")
                break
    return results


def emit_finding(module, severity, type_, source, detail, context, url):
    print(json.dumps({
        "module": module, "severity": severity, "type": type_,
        "source": source, "detail": detail, "context": context, "url": url
    }), flush=True)


def log(level, msg, log_level):
    levels = ["quiet", "normal", "verbose", "debug"]
    if levels.index(log_level) >= levels.index(level):
        print(f"[{level}] {msg}", file=sys.stderr)


def scan_runs(username, repo, token, log_level):
    log("verbose", f"Scanning workflow runs for {repo}", log_level)
    runs = api_get_all(
        f"https://api.github.com/repos/{username}/{repo}/actions/runs?per_page=100",
        token, log_level
    )
    for run in runs:
        run_id = run.get("id", "?")
        commit = run.get("head_commit") or {}
        for role in ("author", "committer"):
            actor = commit.get(role) or {}
            email = actor.get("email", "")
            if email and EMAIL_RE.fullmatch(email):
                emit_finding(
                    MODULE, "high", "email_leak",
                    f"repo:{repo}/run:{run_id}",
                    email,
                    f"Commit {role} email in Actions run #{run_id}",
                    f"https://github.com/{username}/{repo}/actions/runs/{run_id}"
                )


def scan_artifacts(username, repo, token, log_level):
    log("verbose", f"Scanning artifacts for {repo}", log_level)
    artifacts = api_get_all(
        f"https://api.github.com/repos/{username}/{repo}/actions/artifacts?per_page=100",
        token, log_level
    )
    for artifact in artifacts:
        name = artifact.get("name", "")
        if SENSITIVE_NAME_RE.search(name):
            emit_finding(
                MODULE, "medium", "sensitive_file",
                f"repo:{repo}/artifact:{name}",
                name,
                f"Sensitive artifact name in {repo}",
                f"https://github.com/{username}/{repo}/actions"
            )


def scan_workflow_files(username, repo, token, log_level):
    log("verbose", f"Scanning workflow files for {repo}", log_level)
    data, _ = api_get(
        f"https://api.github.com/repos/{username}/{repo}/contents/.github/workflows",
        token, log_level
    )
    if not isinstance(data, list):
        return

    for entry in data:
        name = entry.get("name", "")
        if not name.endswith((".yml", ".yaml")):
            continue

        file_data, _ = api_get(
            f"https://api.github.com/repos/{username}/{repo}/contents/.github/workflows/{name}",
            token, log_level
        )
        if not isinstance(file_data, dict):
            continue

        raw = file_data.get("content", "")
        try:
            text = base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            continue

        for email in set(EMAIL_RE.findall(text)):
            emit_finding(
                MODULE, "high", "email_leak",
                f"repo:{repo}/workflow:{name}",
                email,
                f"Email in workflow file {name}",
                f"https://github.com/{username}/{repo}/blob/HEAD/.github/workflows/{name}"
            )

        for secret in set(SECRET_RE.findall(text)):
            emit_finding(
                MODULE, "critical", "secret_leak",
                f"repo:{repo}/workflow:{name}",
                secret[:40],
                f"Potential secret in workflow file {name}",
                f"https://github.com/{username}/{repo}/blob/HEAD/.github/workflows/{name}"
            )


def scan_repo(username, repo, token, log_level):
    log("normal", f"Scanning {username}/{repo}", log_level)
    scan_runs(username, repo, token, log_level)
    scan_artifacts(username, repo, token, log_level)
    scan_workflow_files(username, repo, token, log_level)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--log-level", default="normal",
                        choices=["quiet", "normal", "verbose", "debug"])
    args = parser.parse_args()

    token = get_token()
    repos = api_get_all(
        f"https://api.github.com/users/{args.username}/repos?per_page=100",
        token, args.log_level
    )
    if not isinstance(repos, list):
        log("normal", "Failed to fetch repos", args.log_level)
        sys.exit(1)

    for repo in repos:
        scan_repo(args.username, repo["name"], token, args.log_level)


if __name__ == "__main__":
    main()
