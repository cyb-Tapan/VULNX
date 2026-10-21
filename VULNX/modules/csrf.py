"""
csrf.py

Reviews state-changing forms for the presence of anti-CSRF token fields
and observable cookie protections (SameSite). This is a review, not a
confirmed-exploit detector: a missing token is reported as something to
investigate, not as proof that CSRF is exploitable (server-side checks
such as Origin/Referer validation are invisible to a passive crawler).
"""

from __future__ import annotations

import re
from typing import List

from modules.endpoint_discovery import DiscoveredForm
from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.recon import ReconResult

_TOKEN_FIELD_PATTERN = re.compile(r"(?i)(csrf|xsrf|_token|authenticity_token|nonce)")

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def review_forms(forms: List[DiscoveredForm], recon: ReconResult) -> List[Finding]:
    findings: List[Finding] = []
    samesite_values = {c.get("samesite") for c in recon.cookies if c.get("samesite")}
    has_strict_samesite = any(
        str(v).lower() in ("strict", "lax") for v in samesite_values
    )

    for form in forms:
        if form.method.upper() not in _STATE_CHANGING_METHODS:
            continue
        has_token_field = any(_TOKEN_FIELD_PATTERN.search(name or "") for name in form.inputs)
        if has_token_field:
            continue

        findings.append(
            Finding(
                category="Cross-Site Request Forgery — Review",
                affected_url=form.action,
                http_method=form.method,
                severity=Severity.LOW if has_strict_samesite else Severity.MEDIUM,
                confidence=Confidence.LOW,
                status=VerificationStatus.POTENTIAL,
                evidence=(
                    f"State-changing form (method={form.method}) has no field name matching "
                    f"common anti-CSRF token conventions."
                    + (" Session cookies do set SameSite." if has_strict_samesite else " No SameSite cookie attribute observed.")
                ),
                remediation=(
                    "Confirm server-side anti-CSRF controls (synchronizer token, double-submit "
                    "cookie, or strict Origin/Referer validation) are actually enforced for this "
                    "form, even if no token field is visible in the HTML."
                ),
                module="csrf",
                note="Absence of a visible token field is not, by itself, proof of an exploitable CSRF vulnerability.",
            )
        )
    return findings
