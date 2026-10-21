"""
misconfiguration.py

Reviews security headers, cookie attributes, server-information
disclosure, and TLS certificate indicators. Severity is contextual: a
single missing header is Informational/Low, never reported as confirmed
exploitation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.recon import ReconResult


def review(recon: ReconResult, tls_info: Optional[dict], url: str) -> List[Finding]:
    findings: List[Finding] = []

    if recon.missing_security_headers:
        findings.append(
            Finding(
                category="Security Configuration Review — Missing Security Headers",
                affected_url=url,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                status=VerificationStatus.POTENTIAL,
                evidence="Missing: " + ", ".join(recon.missing_security_headers),
                remediation=(
                    "Add the missing security headers appropriate to this application "
                    "(e.g. Content-Security-Policy, Strict-Transport-Security, "
                    "X-Content-Type-Options, X-Frame-Options, Referrer-Policy)."
                ),
                module="misconfiguration",
            )
        )

    server_header = recon.headers.get("server")
    if server_header and any(ch.isdigit() for ch in server_header):
        findings.append(
            Finding(
                category="Security Configuration Review — Server Version Disclosure",
                affected_url=url,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                status=VerificationStatus.POTENTIAL,
                evidence=f"Server header discloses version information: {server_header}",
                remediation="Suppress detailed version information in the Server response header.",
                module="misconfiguration",
            )
        )

    for cookie in recon.cookies:
        issues = []
        if not cookie.get("secure"):
            issues.append("missing Secure attribute")
        if not cookie.get("httponly"):
            issues.append("missing HttpOnly attribute")
        if issues:
            findings.append(
                Finding(
                    category="Security Configuration Review — Cookie Attributes",
                    affected_url=url,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=VerificationStatus.POTENTIAL,
                    evidence=f"Cookie {cookie.get('name')!r}: " + ", ".join(issues),
                    remediation="Set Secure and HttpOnly on session/auth cookies; set SameSite appropriately.",
                    module="misconfiguration",
                )
            )

    if tls_info and not tls_info.get("error"):
        not_after = tls_info.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 14:
                    findings.append(
                        Finding(
                            category="Security Configuration Review — TLS Certificate Expiry",
                            affected_url=url,
                            severity=Severity.MEDIUM if days_left < 0 else Severity.LOW,
                            confidence=Confidence.HIGH,
                            status=VerificationStatus.VERIFIED,
                            evidence=f"Certificate notAfter={not_after} ({days_left} days from now).",
                            remediation="Renew the TLS certificate before expiry.",
                            module="misconfiguration",
                        )
                    )
            except ValueError:
                pass

    return findings
