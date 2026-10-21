"""
models.py

Structured, in-memory data model for VULNX. Nothing in this module writes
to disk. Findings exist only for the lifetime of the running process and
are printed to the terminal by terminal_output.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VerificationStatus(str, Enum):
    POTENTIAL = "Potential"
    VERIFIED = "Verified"
    INCONCLUSIVE = "Inconclusive"
    NOT_TESTED = "Not tested"


# Patterns of data that must never be shown in evidence strings.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*)(bearer\s+)?[a-z0-9\-_\.=]+"),
    re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|passwd|password)\s*=\s*)[^&\s'\"]+"),
    re.compile(r"(?i)\beyJ[a-z0-9_\-\.]{10,}\b"),  # JWT-shaped values
]


def sanitize_evidence(text: Optional[str], max_len: int = 220) -> str:
    """
    Redact credentials/cookies/tokens/secrets from a piece of evidence text
    and clamp its length. This is the single choke point every module must
    use before a finding's evidence field is populated.
    """
    if not text:
        return ""
    cleaned = text
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub(lambda m: m.group(1) + "[REDACTED]" if m.groups() else "[REDACTED]", cleaned)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + "...[truncated]"
    return cleaned


@dataclass
class Finding:
    category: str
    affected_url: str
    severity: Severity
    confidence: Confidence
    status: VerificationStatus
    evidence: str
    remediation: str
    parameter: Optional[str] = None
    http_method: Optional[str] = None
    module: Optional[str] = None
    note: Optional[str] = None

    def __post_init__(self) -> None:
        self.evidence = sanitize_evidence(self.evidence)

    def dedupe_key(self) -> tuple:
        return (
            self.category,
            self.affected_url,
            self.parameter,
            self.http_method,
        )


@dataclass
class ScanStats:
    """Runtime counters used for the final summary. All real, all mutated
    in place as the scan runs — never fabricated after the fact."""

    ports_discovered: int = 0
    pages_inspected: int = 0
    endpoints_discovered: int = 0
    requests_sent: int = 0
    findings_total: int = 0
    findings_verified: int = 0
    findings_potential: int = 0
    findings_inconclusive: int = 0
    modules_run: list = field(default_factory=list)
    modules_skipped: list = field(default_factory=list)
    modules_failed: list = field(default_factory=list)
    interrupted: bool = False

    def record_finding(self, finding: Finding) -> None:
        self.findings_total += 1
        if finding.status == VerificationStatus.VERIFIED:
            self.findings_verified += 1
        elif finding.status == VerificationStatus.POTENTIAL:
            self.findings_potential += 1
        elif finding.status == VerificationStatus.INCONCLUSIVE:
            self.findings_inconclusive += 1
