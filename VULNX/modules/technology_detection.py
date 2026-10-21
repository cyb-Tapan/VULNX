"""
technology_detection.py

Passive technology indicators derived from response headers and page
content. This is heuristic and explicitly NOT a fingerprint-confirmed
inventory — results should be reported as indicators, not facts.
"""

from __future__ import annotations

import re
from typing import Dict, List

_HEADER_HINTS = {
    "server": None,
    "x-powered-by": None,
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
}

_BODY_PATTERNS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"/sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla!", re.I), "Joomla"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react-dom", re.I), "React"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
]


def detect_from_headers(headers: Dict[str, str]) -> List[str]:
    indicators = []
    for key, label in _HEADER_HINTS.items():
        value = headers.get(key)
        if value:
            indicators.append(label or f"{key}: {value}")
    return indicators


def detect_from_body(body: str) -> List[str]:
    indicators = []
    for pattern, label in _BODY_PATTERNS:
        if pattern.search(body or ""):
            indicators.append(label)
    return sorted(set(indicators))


def detect(headers: Dict[str, str], body: str) -> List[str]:
    return sorted(set(detect_from_headers(headers) + detect_from_body(body)))
