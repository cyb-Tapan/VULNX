"""
endpoint_discovery.py

Same-origin crawling: links, forms, JS asset discovery, and conservative
extraction of API-like routes from accessible (same-origin) JavaScript.
No brute forcing of directories — this module only follows what it can
actually see referenced in fetched pages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from modules.safety import SafeHTTPClient, ScopeViolation, TargetScope

_JS_ROUTE_PATTERN = re.compile(r"""["'](/[A-Za-z0-9_\-/]{2,}(?:api)?[A-Za-z0-9_\-/]*)["']""")
_JS_EXCLUDE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|woff2?|ttf|css)$", re.I)


@dataclass
class DiscoveredForm:
    action: str
    method: str
    inputs: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    pages_visited: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    forms: List[DiscoveredForm] = field(default_factory=list)
    js_assets: Set[str] = field(default_factory=set)
    js_routes: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)


def _extract_links(base_url: str, html: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"), ("img", "src")):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                links.add(urljoin(base_url, val))
    return links


def _extract_forms(base_url: str, html: str) -> List[DiscoveredForm]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or base_url)
        method = (form.get("method") or "GET").upper()
        inputs = [
            el.get("name")
            for el in form.find_all(["input", "textarea", "select"])
            if el.get("name")
        ]
        forms.append(DiscoveredForm(action=action, method=method, inputs=inputs))
    return forms


def crawl(
    client: SafeHTTPClient,
    scope: TargetScope,
    start_url: str,
    max_pages: int,
    stats=None,
) -> CrawlResult:
    result = CrawlResult()
    queue = [start_url]
    seen = set()

    while queue and len(result.pages_visited) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        if not scope.is_in_scope(url):
            continue

        resp, err = client.get(url)
        if err and resp is None:
            result.errors.append(f"{url}: {err}")
            continue
        if resp is None or resp.status_code >= 400:
            continue

        content_type = resp.headers.get("Content-Type", "")
        result.pages_visited.add(url)
        if stats is not None:
            stats.pages_inspected = len(result.pages_visited)

        if "html" not in content_type and "javascript" not in content_type:
            continue

        body = resp.text

        if "javascript" in content_type:
            for match in _JS_ROUTE_PATTERN.finditer(body):
                route = match.group(1)
                if not _JS_EXCLUDE_EXT.search(route):
                    result.js_routes.add(route)
            continue

        for link in _extract_links(url, body):
            parsed = urlsplit(link)
            if not scope.is_in_scope(link):
                continue
            if parsed.path.lower().endswith(".js"):
                result.js_assets.add(link)
                if link not in seen:
                    queue.append(link)
                continue
            result.endpoints.add(link)
            if link not in seen and len(seen) + len(queue) < max_pages * 3:
                queue.append(link)

        for form in _extract_forms(url, body):
            if scope.is_in_scope(form.action):
                result.forms.append(form)
                result.endpoints.add(form.action)

    if stats is not None:
        stats.endpoints_discovered = len(result.endpoints)
    return result
