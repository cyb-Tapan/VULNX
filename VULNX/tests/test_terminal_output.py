import io
import os

from modules.models import Confidence, Finding, Severity, VerificationStatus, sanitize_evidence
from modules.terminal_output import console, print_finding, print_summary
from modules.models import ScanStats


def test_sanitize_redacts_bearer_token():
    text = "Authorization: Bearer abc.def.ghi leaked here"
    cleaned = sanitize_evidence(text)
    assert "abc.def.ghi" not in cleaned
    assert "REDACTED" in cleaned


def test_sanitize_redacts_cookie():
    text = "Set-Cookie: session=supersecretvalue; Path=/"
    cleaned = sanitize_evidence(text)
    assert "supersecretvalue" not in cleaned


def test_sanitize_redacts_api_key_param():
    text = "request used api_key=sk_live_12345ABCDE in the URL"
    cleaned = sanitize_evidence(text)
    assert "sk_live_12345ABCDE" not in cleaned


def test_sanitize_truncates_long_text():
    cleaned = sanitize_evidence("A" * 500, max_len=50)
    assert len(cleaned) <= 65
    assert cleaned.endswith("...[truncated]")


def test_finding_auto_sanitizes_on_construction():
    f = Finding(
        category="Test",
        affected_url="http://x/",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        status=VerificationStatus.POTENTIAL,
        evidence="token=abcdef123456",
        remediation="fix it",
    )
    assert "abcdef123456" not in f.evidence


def test_print_finding_does_not_raise():
    f = Finding(
        category="Test Finding",
        affected_url="http://x/",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        status=VerificationStatus.POTENTIAL,
        evidence="some evidence",
        remediation="fix it",
    )
    buf = io.StringIO()
    with console.capture() as capture:
        print_finding(f)
    assert "Test Finding" in capture.get()


def test_print_summary_reports_interrupted_honestly():
    stats = ScanStats(interrupted=True, findings_total=2, findings_potential=2)
    with console.capture() as capture:
        print_summary(stats, "http://x/")
    output = capture.get()
    assert "interrupted" in output.lower()


def test_no_scan_result_files_created(tmp_path, monkeypatch):
    # Running the summary/finding printers must never touch the filesystem.
    monkeypatch.chdir(tmp_path)
    f = Finding(
        category="Test",
        affected_url="http://x/",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        status=VerificationStatus.POTENTIAL,
        evidence="evidence",
        remediation="fix",
    )
    stats = ScanStats()
    stats.record_finding(f)
    with console.capture():
        print_finding(f)
        print_summary(stats, "http://x/")
    assert os.listdir(tmp_path) == []
