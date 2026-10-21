"""
parameter_discovery.py

Builds an inventory of testable inputs (query-string parameters and form
fields) from already-discovered endpoints/forms. Performs no additional
network requests of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import parse_qs, urlsplit

from modules.endpoint_discovery import CrawlResult


@dataclass
class ParamTarget:
    url: str
    method: str
    param: str


def discover_parameters(crawl_result: CrawlResult) -> List[ParamTarget]:
    targets: List[ParamTarget] = []
    seen: Set[tuple] = set()

    for endpoint in crawl_result.endpoints:
        qs = parse_qs(urlsplit(endpoint).query)
        base = endpoint.split("?")[0]
        for param in qs:
            key = (base, "GET", param)
            if key not in seen:
                seen.add(key)
                targets.append(ParamTarget(url=base, method="GET", param=param))

    for form in crawl_result.forms:
        for field_name in form.inputs:
            key = (form.action, form.method, field_name)
            if key not in seen:
                seen.add(key)
                targets.append(ParamTarget(url=form.action, method=form.method, param=field_name))

    return targets
