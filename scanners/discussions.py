#!/usr/bin/env python3
"""Scan GitHub Discussions for leaked email addresses."""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

DISCUSSIONS_QUERY = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    discussions(first: 50, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title body url
        author { login }
        comments(first: 20) {
          nodes { body author { login } }
        }
      }
    }
  }
}
"""


def log(level, msg, log_level):
    order = ["quiet", "normal", "verbose", "debug"]
    if order.index(log_level) >= order.index(level):
        print(f"[{level}] {msg}", file=sys.stderr, flush=True)


def get_token():
    """Return a GitHub token from gh CLI or GITHUB_TOKEN env var."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return ""


def graphql_query(token, query, variables):
    payload = json.dumps({"query": query, "variables": variables}).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(
        "https://api.github.com/graphql",
        data=payload,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"GraphQL HTTP {exc.code}: {body}") from exc


def get_repos(username, token):
    """Return list of repo names owned by username via REST."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    names = []
    page = 1
    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            break
        if not data:
            break
        names.extend(r["name"] for r in data)
        page += 1
    return names


def get_discussions(username, repo, token, log_level="normal"):
    """Yield discussion dicts (with comments) authored or commented on by username."""
    cursor = None
    while True:
        variables = {"owner": username, "name": repo, "cursor": cursor}
        try:
            result = graphql_query(token, DISCUSSIONS_QUERY, variables)
        except RuntimeError as exc:
            log("verbose", f"discussions: {repo}: {exc}", log_level)
            break

        if "errors" in result:
            log("verbose", f"discussions: {repo}: {result['errors']}", log_level)
            break

        repo_data = result.get("data", {}).get("repository")
        if not repo_data:
            break

        page = repo_data["discussions"]
        for node in page["nodes"]:
            yield node

        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]


def emit_finding(module, severity, type_, source, detail, context, url):
    print(json.dumps({
        "module": module,
        "severity": severity,
        "type": type_,
        "source": source,
        "detail": detail,
        "context": context,
        "url": url,
    }), flush=True)


def scan_text(text, module, source, context, url):
    """Emit one finding per email found in text."""
    for email in EMAIL_RE.findall(text or ""):
        emit_finding(module, "medium", "email_leak", source, email, context, url)


def main():
    parser = argparse.ArgumentParser(description="Scan GitHub Discussions for email leaks.")
    parser.add_argument("username")
    parser.add_argument("--log-level", default="normal",
                        choices=["quiet", "normal", "verbose", "debug"])
    args = parser.parse_args()

    username = args.username
    log_level = args.log_level

    token = get_token()
    if not token:
        log("verbose", "no GitHub token found; unauthenticated requests may be rate-limited", log_level)

    repos = get_repos(username, token)
    log("verbose", f"discussions: found {len(repos)} repos for {username}", log_level)

    for repo in repos:
        log("verbose", f"discussions: scanning {repo}", log_level)
        for discussion in get_discussions(username, repo, token, log_level):
            number = discussion.get("number", "?")
            title = discussion.get("title", "")
            url = discussion.get("url", "")
            author = (discussion.get("author") or {}).get("login", "")

            if author == username:
                scan_text(
                    discussion.get("body", ""),
                    "discussions",
                    f"repo:{repo}/discussion:{number}",
                    f"Email in discussion: {title}",
                    url,
                )

            for comment in (discussion.get("comments") or {}).get("nodes", []):
                comment_author = (comment.get("author") or {}).get("login", "")
                if comment_author == username:
                    scan_text(
                        comment.get("body", ""),
                        "discussions",
                        f"repo:{repo}/discussion:{number}/comment",
                        f"Email in discussion comment: {title}",
                        url,
                    )

    log("verbose", "discussions: done", log_level)


if __name__ == "__main__":
    main()
