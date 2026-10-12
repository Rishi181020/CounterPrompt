"""Agent's-eye scanner: what would an AI attacker learn from this site?

Deterministic localhost-only crawl, no LLM. Print a Markdown report of
everything a crawling agent would read: the truth banner, HTML comments,
hidden and aria-hidden text, credential hints, internal paths, JS bundles,
and what common debug-style paths expose.

    python scanner/agent_eye.py --target http://localhost:8080

Requests reuse the localhost-only HTTP gate from attacker/harness.py, so the
scanner can never leave the machine. Links under /internal/ are reported but
never requested: on a CounterPrompt site those are trap paths.
"""

import argparse
import re
import sys
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attacker.harness import http_request  # noqa: E402  (localhost-only gate)

BANNER_MARK = "NOTICE TO AUTOMATED AGENTS"
CHECKIN_RE = re.compile(r"/\.well-known/agent-checkin")
CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|credential)s?\b\s*[:=]"
)
INTERNAL_PREFIX = "/internal/"
DEBUG_PATHS = [
    "/.env", "/debug", "/api/debug", "/server-status", "/config.php", "/phpinfo.php",
]
MAX_PAGES = 25


class PageReader(HTMLParser):
    """Collect comments, links, and hidden/aria-hidden text from one page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.comments = []
        self.links = set()
        self.hidden_text = []
        self._hidden = 0

    @staticmethod
    def _is_hidden(attrs):
        style = (attrs.get("style") or "").lower()
        return (
            attrs.get("hidden") is not None
            or attrs.get("aria-hidden") == "true"
            or "display:none" in style.replace(" ", "")
            or "visibility:hidden" in style.replace(" ", "")
            or ("position:absolute" in style and "left:-" in style)
        )

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src"):
            value = attrs.get(key)
            if value:
                self.links.add(value)
        if tag in {"script", "noscript", "template"} or self._is_hidden(attrs):
            self._hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "noscript", "template"} and self._hidden:
            self._hidden -= 1

    def handle_comment(self, data):
        self.comments.append(data.strip())

    def handle_data(self, data):
        text = data.strip()
        if text and self._hidden:
            self.hidden_text.append(text)


def _excerpt(text, index, width=80):
    return " ".join(text[max(0, index - width):index + width].split())[:160]


def _same_site_path(target, link):
    resolved = urljoin(target, link)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc != urlparse(target).netloc:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def crawl(target):
    pages = []          # (path, status, content_type, body)
    internal = set()    # (internal_path, seen_on)
    errors = []
    seen = set()
    queue = deque(["/robots.txt", "/"])
    while queue and len(pages) < MAX_PAGES:
        path = queue.popleft()
        if path in seen:
            continue
        seen.add(path)
        result = http_request("GET", urljoin(target, path))
        if "error" in result:
            errors.append((path, result["error"]))
            continue
        body = result.get("body", "")
        content_type = (result.get("headers") or {}).get("Content-Type", "")
        pages.append((path, result.get("status"), content_type, body))
        if path == "/robots.txt":
            for line in body.splitlines():
                entry = line.strip()
                if entry.lower().startswith("disallow:") and len(entry.split(":", 1)[1].strip()) > 1:
                    disallowed = entry.split(":", 1)[1].strip()
                    if disallowed.startswith("/"):
                        internal.add((disallowed, "robots.txt"))
        if "text/html" not in content_type.lower():
            continue
        reader = PageReader()
        try:
            reader.feed(body)
        except Exception:
            pass
        for link in sorted(reader.links):
            child = _same_site_path(target, link)
            if not child or child.startswith("/_counterprompt"):
                continue
            if child.startswith(INTERNAL_PREFIX):
                internal.add((child, path))
            elif child not in seen:
                queue.append(child)
    return pages, internal, errors


def probe_debug_paths(target):
    rows = []
    for path in DEBUG_PATHS:
        result = http_request("GET", urljoin(target, path))
        if "error" in result:
            rows.append((path, None, result["error"]))
            continue
        status = result.get("status")
        body = result.get("body", "")
        note = ""
        if status == 200 and body.strip():
            note = " ".join(body.split())[:100]
        rows.append((path, status, note))
    return rows


def analyze(pages):
    banners = []      # (path, source, excerpt)
    creds = []        # (path, source, excerpt)
    hidden = []       # (path, excerpt)
    checkins = []     # (path, excerpt)
    for path, status, content_type, body in pages:
        if "text/html" in content_type.lower():
            reader = PageReader()
            try:
                reader.feed(body)
            except Exception:
                pass
            sources = [("HTML comment", c) for c in reader.comments]
            sources += [("hidden/aria-hidden text", t) for t in reader.hidden_text]
            for where, text in sources:
                if BANNER_MARK in text or CHECKIN_RE.search(text):
                    banners.append((path, where, _excerpt(text, text.find(BANNER_MARK) if BANNER_MARK in text else 0)))
                if CRED_RE.search(text):
                    match = re.search(CRED_RE, text)
                    creds.append((path, where, _excerpt(text, match.start())))
            hidden += [(path, " ".join(t.split())[:160]) for t in reader.hidden_text]
        if BANNER_MARK in body:
            if not any(row[0] == path for row in banners):
                banners.append((path, "page", _excerpt(body, body.find(BANNER_MARK))))
        if CHECKIN_RE.search(body) and not any(row[0] == path for row in checkins):
            checkins.append((path, "the page tells automated agents to identify themselves here"))
        for match in re.finditer(CRED_RE, body):
            if not any(row[0] == path for row in creds):
                creds.append((path, content_type.split(";")[0].strip() or "body", _excerpt(body, match.start())))
    return banners, creds, hidden, checkins


def report(target, pages, internal, errors, debug_rows, banners, creds, hidden, checkins):
    lines = [f"# Agent's-eye report - {target}", ""]
    lines.append(
        f"Deterministic crawl of {len(pages)} page(s) plus robots.txt and "
        f"{len(DEBUG_PATHS)} debug-style paths. No LLM involved."
    )
    lines.append("")
    lines.append("## What an AI attacker would be told")
    if banners:
        lines.append(f"The truth banner ({BANNER_MARK.lower()}) appears on:")
        for path, where, excerpt in banners:
            lines.append(f"- `{path}` ({where}): {excerpt}")
    else:
        lines.append("- No truth banner found. The site does not tell agents they are watched.")
    if checkins:
        lines.append("")
        lines.append("Check-in requests an agent would be invited to make:")
        for path, note in checkins:
            lines.append(f"- `{path}` - {note}")
    lines.append("")
    lines.append("## Credential hints an agent would read")
    if creds:
        for path, where, excerpt in creds:
            lines.append(f"- `{path}` ({where}): {excerpt}")
    else:
        lines.append("- None found in comments, hidden text, or bundles.")
    lines.append("")
    lines.append("## Internal paths advertised")
    if internal:
        for path, seen_on in sorted(internal):
            lines.append(
                f"- `{path}` (linked from `{seen_on}`) - requesting it trips the "
                "CounterPrompt trap; an agent that continues gets detected and rerouted."
            )
    else:
        lines.append("- No internal paths are advertised to crawlers.")
    lines.append("")
    lines.append("## Hidden and aria-hidden text")
    if hidden:
        for path, excerpt in hidden:
            lines.append(f"- `{path}`: {excerpt}")
    else:
        lines.append("- None.")
    lines.append("")
    lines.append("## Debug-style paths")
    for path, status, note in debug_rows:
        lines.append(f"- `{path}` -> {status if status is not None else 'error'}"
                     + (f" - {note}" if note else ""))
    lines.append("")
    lines.append("## Pages read")
    for path, status, content_type, body in pages:
        lines.append(f"- `{path}` -> {status} ({content_type.split(';')[0].strip() or '?'}, {len(body)} chars)")
    if errors:
        lines.append("")
        lines.append("## Unreachable")
        for path, error in errors:
            lines.append(f"- `{path}` - {error}")
    lines.append("")
    lines.append(
        "Fix list: remove credential hints from comments and hidden text, stop "
        "linking internal paths, close debug-style paths, and keep the truth "
        "banner so honest agents stop on their own."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()
    if urlparse(args.target).hostname not in {"localhost", "127.0.0.1"}:
        print("Target refused: only localhost or 127.0.0.1 is allowed.", file=sys.stderr)
        return 2
    pages, internal, errors = crawl(args.target)
    debug_rows = probe_debug_paths(args.target)
    banners, creds, hidden, checkins = analyze(pages)
    print(report(args.target, pages, internal, errors, debug_rows, banners, creds, hidden, checkins))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())