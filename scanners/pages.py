#!/usr/bin/env python3
"""Scan GitHub Pages sites for leaked email addresses."""
import argparse, json, os, re, sys, time
import urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
FALSE_POSITIVE_DOMAINS = {
    'users.noreply.github.com',
    'example.com',
    'w3.org',
    'schema.org',
    'sentry.io',
}


def get_token():
    return os.environ.get('GITHUB_TOKEN', '')


def api_get(url, token, log_level="normal"):
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'token {token}'

    for attempt in range(1, 6):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429):
                retry_after = e.headers.get('Retry-After')
                rate_reset = e.headers.get('X-RateLimit-Reset')
                if retry_after:
                    wait = int(retry_after)
                elif rate_reset:
                    wait = max(1, int(rate_reset) - int(time.time()))
                else:
                    wait = attempt * 2
                log("verbose", f"[rate-limit] {url} retry in {wait}s (attempt {attempt}/5)", log_level)
                time.sleep(wait)
                continue
            log("normal", f"[api] HTTP {e.code} for {url}", log_level)
            return None
        except Exception as e:
            log("verbose", f"[api] error fetching {url}: {e}", log_level)
            return None
    return None


def emit_finding(module, severity, type_, source, detail, context, url):
    finding = {
        "module": module,
        "severity": severity,
        "type": type_,
        "source": source,
        "detail": detail,
        "context": context,
        "url": url,
    }
    print(json.dumps(finding))


def log(level, msg, log_level):
    if log_level == "verbose" or level == "normal":
        print(msg, file=sys.stderr)


class LinkParser(HTMLParser):
    """Extract href links from HTML."""
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for k, v in attrs:
                if k == 'href' and v:
                    self.links.append(v)


def crawl_page(url, base_domain, visited, log_level):
    """Fetch a URL and return (emails_found, new_links)."""
    log("verbose", f"[pages] crawling {url}", log_level)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'github-recon/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content_type = resp.headers.get('Content-Type', '')
            if 'html' not in content_type and 'text' not in content_type:
                return [], []
            html = resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        log("verbose", f"[pages] failed to fetch {url}: {e}", log_level)
        return [], []

    emails = list(set(EMAIL_RE.findall(html)))

    parser = LinkParser()
    parser.feed(html)

    links = []
    for href in parser.links:
        absolute = urllib.parse.urljoin(url, href)
        p = urllib.parse.urlparse(absolute)
        if p.netloc == base_domain and p.scheme in ('http', 'https'):
            clean = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ''))
            if clean not in visited:
                links.append(clean)

    return emails, links


def scan_pages_site(username, repo, pages_url, token, log_level):
    """Crawl a Pages site up to depth 2 for emails."""
    base_domain = urllib.parse.urlparse(pages_url).netloc
    visited = set()
    queue = [(pages_url, 0)]
    page_count = 0

    while queue:
        url, depth = queue.pop(0)
        if url in visited or depth > 2 or page_count >= 20:
            continue
        visited.add(url)
        page_count += 1

        if page_count > 1:
            time.sleep(0.5)

        emails, links = crawl_page(url, base_domain, visited, log_level)

        for email in emails:
            domain = email.split('@')[1].lower()
            if domain not in FALSE_POSITIVE_DOMAINS:
                emit_finding(
                    "pages", "high", "email_leak",
                    f"pages:{repo}", email,
                    f"Email found on GitHub Pages: {url}",
                    url,
                )

        if depth < 2:
            queue.extend((link, depth + 1) for link in links)


def main():
    parser = argparse.ArgumentParser(description="Scan GitHub Pages for leaked emails")
    parser.add_argument("username")
    parser.add_argument("--log-level", default="normal")
    args = parser.parse_args()

    token = get_token()

    root_pages_url = f"https://{args.username}.github.io"
    log("verbose", f"[pages] checking root site {root_pages_url}", args.log_level)
    scan_pages_site(args.username, f"{args.username}.github.io", root_pages_url, token, args.log_level)

    repos_raw = api_get(
        f"https://api.github.com/users/{args.username}/repos?per_page=100",
        token, args.log_level,
    )
    if not repos_raw:
        log("normal", "[pages] could not fetch repos", args.log_level)
        return

    repos = json.loads(repos_raw)
    for repo in repos:
        repo_name = repo['name']
        pages_raw = api_get(
            f"https://api.github.com/repos/{args.username}/{repo_name}/pages",
            token, args.log_level,
        )
        if not pages_raw:
            continue
        data = json.loads(pages_raw)
        html_url = data.get('html_url')
        if html_url:
            log("verbose", f"[pages] found Pages site for {repo_name}: {html_url}", args.log_level)
            scan_pages_site(args.username, repo_name, html_url, token, args.log_level)


if __name__ == "__main__":
    main()
