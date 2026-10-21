"""
sqli.py

Conservative SQL-injection indicator detection via differential response
analysis. This module never attempts to dump data, enumerate schemas, or
run destructive statements. It compares a baseline response against the
response to a single harmless syntax-perturbing character, and flags
database error signatures — nothing more. Findings are reported as
"Potential" (or "Inconclusive"), never "Verified", because confirming
exploitability safely is out of scope for an automated, non-destructive
scanner.
"""

from __future__ import annotations

import re
from typing import List, Optional

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget
from modules.safety import SafeHTTPClient

# A single quote is the standard, non-destructive syntax probe used to
# reveal unescaped input in a SQL context via an error message. No
# stacked queries, no UNION payloads, no boolean/time-based brute forcing.
_PROBE = "'"
_CONTROL = "VULNX_CTRL_1"

_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysqli?", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\)|postgresql.*error", re.I),
    re.compile(r"sqlite3\.OperationalError|sqlite syntax error", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"sqlstate\[", re.I),
]


def _looks_like_sql_error(body: str) -> Optional[str]:
    for pattern in _ERROR_SIGNATURES:
        m = pattern.search(body or "")
        if m:
            return m.group(0)
    return None


def scan_target(client: SafeHTTPClient, target: ParamTarget) -> List[Finding]:
    findings: List[Finding] = []

    baseline_resp, baseline_err = _send(client, target, _CONTROL)
    if baseline_err and baseline_resp is None:
        return findings
    baseline_body = baseline_resp.text if baseline_resp is not None else ""
    baseline_status = baseline_resp.status_code if baseline_resp is not None else None

    probe_resp, probe_err = _send(client, target, _CONTROL + _PROBE)
    if probe_err and probe_resp is None:
        return findings
    probe_body = probe_resp.text if probe_resp is not None else ""
    probe_status = probe_resp.status_code if probe_resp is not None else None

    error_match = _looks_like_sql_error(probe_body)
    baseline_had_error = _looks_like_sql_error(baseline_body) is not None

    if error_match and not baseline_had_error:
        findings.append(
            Finding(
                category="SQL Injection Indicator (Error-Based)",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Injecting a single quote produced a database error signature: {error_match!r}",
                remediation=(
                    "Use parameterized queries / prepared statements for all database "
                    "access involving this input, and disable verbose database error "
                    "output in responses."
                ),
                module="sqli",
                note="Not independently verified against a known-vulnerable response; manual confirmation recommended.",
            )
        )
    elif probe_status != baseline_status and probe_status in (500,) and baseline_status not in (500,):
        findings.append(
            Finding(
                category="SQL Injection Indicator (Status Code Anomaly)",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                status=VerificationStatus.INCONCLUSIVE,
                evidence=f"Baseline status {baseline_status}, single-quote probe status {probe_status}.",
                remediation="Investigate server error handling for this input; confirm manually whether this reflects a SQL error.",
                module="sqli",
            )
        )

    return findings


def _send(client: SafeHTTPClient, target: ParamTarget, value: str):
    if target.method.upper() == "GET":
        return client.get(target.url, params={target.param: value})
    return client.post(target.url, data={target.param: value})
