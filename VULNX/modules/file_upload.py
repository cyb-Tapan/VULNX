"""
file_upload.py

Passive review of discovered file-upload forms: visible `accept`
attributes, method, and presence/absence of a client-side type
restriction. This module never uploads any file — payload, harmless, or
otherwise — to a live target. Use local, intentionally vulnerable lab
fixtures if active upload-handling testing is ever required; that is out
of scope for this automated module.

Status: Review-only (passive). No active testing implemented.
"""

from __future__ import annotations

from typing import List

from bs4 import BeautifulSoup

from modules.models import Confidence, Finding, Severity, VerificationStatus


def review_html(url: str, html: str) -> List[Finding]:
    findings: List[Finding] = []
    soup = BeautifulSoup(html or "", "html.parser")

    for form in soup.find_all("form"):
        file_inputs = form.find_all("input", attrs={"type": "file"})
        if not file_inputs:
            continue

        enctype = (form.get("enctype") or "").lower()
        if enctype and enctype != "multipart/form-data":
            continue  # not a real upload form

        for finput in file_inputs:
            accept = finput.get("accept")
            findings.append(
                Finding(
                    category="File Upload Form — Review",
                    affected_url=url,
                    parameter=finput.get("name"),
                    http_method=(form.get("method") or "GET").upper(),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    status=VerificationStatus.NOT_TESTED,
                    evidence=(
                        f"Upload input found (accept={accept!r})."
                        if accept
                        else "Upload input found with no client-side 'accept' restriction."
                    ),
                    remediation=(
                        "Server-side, validate file type by content (not extension or client-"
                        "supplied MIME type), enforce size limits, store uploads outside the "
                        "web root or with randomized non-executable names, and scan content "
                        "where appropriate. Client-side 'accept' is a UX hint only, not a "
                        "security control."
                    ),
                    module="file_upload",
                    note="Passive review only — no file was uploaded and upload handling was not actively tested.",
                )
            )
    return findings
