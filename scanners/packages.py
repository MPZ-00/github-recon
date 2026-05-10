#!/usr/bin/env python3
"""Scan GitHub Packages and registry metadata for leaked email addresses."""
import argparse, json, os, re, sys
import urllib.request, urllib.error

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@(?!users\.noreply\.github\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_LOG_ORDER = ["quiet", "normal", "verbose", "debug"]


def get_token():
    import subprocess
    try:
        result = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return os.environ.get('GITHUB_TOKEN', '')


def http_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode('utf-8', errors='replace')
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return None


def api_get(url, token):
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    return http_get(url, headers)


def emit_finding(source, detail, context, url):
    print(json.dumps({
        "module": "packages", "severity": "high", "type": "email_leak",
        "source": source, "detail": detail, "context": context, "url": url,
    }), flush=True)


def log(level, msg, log_level):
    if _LOG_ORDER.index(log_level) >= _LOG_ORDER.index(level):
        print(f"[{level}] {msg}", file=sys.stderr)


def check_npm(pkg_name):
    body = http_get(f"https://registry.npmjs.org/{pkg_name}")
    if not body:
        return
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return
    for field in ('author', 'maintainers', 'contributors'):
        entries = data.get(field, [])
        if isinstance(entries, dict):
            entries = [entries]
        for e in (entries or []):
            email = e.get('email', '') if isinstance(e, dict) else ''
            if email and EMAIL_RE.search(email):
                emit_finding(
                    f"npm:{pkg_name}", email,
                    f"Email in npm package '{pkg_name}' metadata",
                    f"https://www.npmjs.com/package/{pkg_name}",
                )


def check_pypi(pkg_name):
    body = http_get(f"https://pypi.org/pypi/{pkg_name}/json")
    if not body:
        return
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return
    info = data.get('info', {})
    for field in ('author_email', 'maintainer_email'):
        raw = info.get(field, '')
        if not raw:
            continue
        for email in EMAIL_RE.findall(raw):
            emit_finding(
                f"pypi:{pkg_name}", email,
                f"Email in PyPI package '{pkg_name}' metadata",
                f"https://pypi.org/project/{pkg_name}/",
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("--log-level", default="normal")
    args = parser.parse_args()

    token = get_token()

    body = api_get(
        f"https://api.github.com/users/{args.username}/packages?per_page=100",
        token,
    )
    if not body:
        log("verbose", "No packages found or not authorized", args.log_level)
        return

    try:
        packages = json.loads(body)
    except json.JSONDecodeError:
        return

    if not isinstance(packages, list):
        return

    for pkg in packages:
        name = pkg.get('name', '')
        pkg_type = pkg.get('package_type', '')
        log("verbose", f"Checking {pkg_type} package: {name}", args.log_level)
        if pkg_type == 'npm':
            check_npm(name)
        elif pkg_type == 'pypi':
            check_pypi(name)


if __name__ == "__main__":
    main()
