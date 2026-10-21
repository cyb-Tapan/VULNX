"""
directory_traversal.py

Identifies parameters whose name suggests file-path handling (naming
heuristic — always safe to run). Optionally, ONLY in local-lab mode
against the authorized local-lab target, performs a single harmless
traversal probe using a canary marker file that the lab operator placed
themselves; it never attempts to read real operating-system files such as
/etc/passwd, and never runs outside local-lab mode.

Status: Experimental. The active probe is deliberately narrow and will
report "Not tested" when local-lab mode is off, which is the default.
"""

from __future__ import annotations

import re
from typing import List, Optional

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget
from modules.safety import SafeHTTPClient

_FILE_LIKE_PARAM_NAME = re.compile(
    r"(?i)^(file|filename|path|filepath|doc|document|page|template|include|dir|folder|report|download)$"
)

# A harmless marker the lab operator is expected to place at a known,
# documented relative path inside their own local-lab fixture. VULNX never
# invents or assumes the existence of a real OS file.
LOCAL_LAB_CANARY_RELATIVE_PATH = "vulnx_canary.txt"
LOCAL_LAB_CANARY_CONTENT_MARKER = "VULNX_TRAVERSAL_CANARY"


def review_target(target: ParamTarget) -> List[Finding]:
    findings: List[Finding] = []
    if _FILE_LIKE_PARAM_NAME.match(target.param or ""):
        findings.append(
            Finding(
                category="Potential Directory Traversal Input (Naming Heuristic)",
                affected_url=target.url,
                parameter=target.param,
                http_method=target.method,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Parameter name {target.param!r} is commonly associated with server-side file-path handling.",
                remediation=(
                    "If this parameter selects a file path server-side, validate it against an "
                    "allow-list, reject path-traversal sequences, and resolve paths within a "
                    "fixed base directory before use."
                ),
                module="directory_traversal",
                note="Naming heuristic only — no traversal payload was sent unless local-lab mode was enabled.",
            )
        )
    return findings


def active_canary_probe(
    client: SafeHTTPClient,
    target: ParamTarget,
    local_lab_enabled: bool,
) -> Optional[Finding]:
    """Only runs in local-lab mode, against a canary file the operator placed
    themselves. Never attempts to access real system files."""
    if not local_lab_enabled:
        return None

    probe_value = f"../{LOCAL_LAB_CANARY_RELATIVE_PATH}"
    if target.method.upper() == "GET":
        resp, err = client.get(target.url, params={target.param: probe_value})
    else:
        resp, err = client.post(target.url, data={target.param: probe_value})

    if err and resp is None:
        return None
    if resp is None:
        return None

    if LOCAL_LAB_CANARY_CONTENT_MARKER in resp.text:
        return Finding(
            category="Directory Traversal — Canary File Retrieved (Local Lab)",
            affected_url=target.url,
            parameter=target.param,
            http_method=target.method,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=VerificationStatus.VERIFIED,
            evidence="Response body contained the local-lab canary marker after a relative-path probe.",
            remediation="Validate and canonicalize file paths server-side; reject traversal sequences.",
            module="directory_traversal",
        )
    return None
