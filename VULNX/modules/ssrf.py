"""
ssrf.py

Conservative identification of URL-fetching input parameters. This module
does NOT send requests to cloud metadata endpoints or arbitrary internal
services — doing so would itself be an unsafe, potentially harmful probe.
It only flags parameters whose name/value shape suggests the application
fetches a URL server-side, and reports them as review items for a human
tester to verify in a controlled lab with an explicit, authorized
callback target.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlsplit

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget

_URL_LIKE_PARAM_NAME = re.compile(
    r"(?i)^(url|uri|link|src|source|target|dest|destination|callback|webhook|feed|path|redirect|next|return|image|img|file|fetch|proxy)$"
)


def review_target(target: ParamTarget) -> List[Finding]:
    findings: List[Finding] = []
    if _URL_LIKE_PARAM_NAME.match(target.param or ""):
        findings.append(
            Finding(
                category="Potential SSRF Input (Naming Heuristic)",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Parameter name {target.param!r} is commonly associated with server-side URL fetching.",
                remediation=(
                    "If this parameter is used server-side to fetch a URL, restrict it to an "
                    "allow-list of destinations, block requests to private/loopback/link-local "
                    "ranges and cloud metadata addresses, and verify in a controlled lab with an "
                    "authorized callback listener."
                ),
                module="ssrf",
                note=(
                    "Naming heuristic only — no outbound probe request was sent by VULNX. A URL-"
                    "shaped parameter name is not evidence of an actual SSRF vulnerability."
                ),
            )
        )
    return findings


def review_value_for_url_shape(target: ParamTarget, sample_value: str) -> List[Finding]:
    """Optional: if a discovered value already looks like a URL (e.g. a query
    string default), note it without ever dereferencing a third-party URL."""
    findings: List[Finding] = []
    try:
        parts = urlsplit(sample_value)
    except ValueError:
        return findings
    if parts.scheme in ("http", "https") and parts.hostname:
        findings.append(
            Finding(
                category="Potential SSRF Input (URL-Shaped Value Observed)",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Existing value for this parameter is itself a URL (host: {parts.hostname}).",
                remediation="Review server-side handling of this parameter for SSRF exposure as above.",
                module="ssrf",
            )
        )
    return findings
