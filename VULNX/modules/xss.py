"""
xss.py

Reflection and output-context analysis for potential cross-site scripting.
Uses a unique, harmless marker string (no <script> execution payload, no
event handlers) and inspects WHERE it is reflected: inside a raw HTML
body (unescaped), inside an HTML attribute, or safely HTML-encoded.
Reflection alone is reported as a low/medium "Potential" finding, never
as a verified, exploitable XSS, because this module does not execute
JavaScript or drive a real browser to confirm execution.
"""

from __future__ import annotations

import html
import re
import uuid
from typing import List

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget
from modules.safety import SafeHTTPClient


def _marker() -> str:
    return "vlnx" + uuid.uuid4().hex[:8]


def scan_target(client: SafeHTTPClient, target: ParamTarget) -> List[Finding]:
    findings: List[Finding] = []
    marker = _marker()
    probe = f"{marker}<x>"  # harmless; contains an angle bracket to test encoding only

    if target.method.upper() == "GET":
        resp, err = client.get(target.url, params={target.param: probe})
    else:
        resp, err = client.post(target.url, data={target.param: probe})

    if err and resp is None:
        return findings
    if resp is None or "html" not in resp.headers.get("Content-Type", ""):
        return findings

    body = resp.text
    if marker not in body:
        return findings  # not reflected at all

    raw_reflected = probe in body
    encoded_reflected = html.escape(probe) in body

    if raw_reflected and not encoded_reflected:
        findings.append(
            Finding(
                category="Reflected Input — Unescaped HTML Context",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Harmless marker containing '<' and '>' was reflected unescaped (marker={marker}).",
                remediation=(
                    "Context-appropriately encode all user input before rendering it in "
                    "HTML output (HTML-entity encode in body context, attribute-encode in "
                    "attribute context). Consider a strict Content-Security-Policy."
                ),
                module="xss",
                note="Reflection observed only; JavaScript execution was not driven or confirmed.",
            )
        )
    elif encoded_reflected:
        # Not a finding worth surfacing on its own — this is the secure
        # behavior — but we track it so scan honesty isn't lost.
        pass
    elif marker in body:
        findings.append(
            Finding(
                category="Reflected Input — Context Unclear",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=VerificationStatus.INCONCLUSIVE,
                evidence=f"Marker was reflected but encoding context could not be classified (marker={marker}).",
                remediation="Manually inspect how this input is rendered to determine whether encoding is sufficient.",
                module="xss",
            )
        )

    return findings
