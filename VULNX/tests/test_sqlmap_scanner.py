"""
Tests for modules/sqlmap_scanner.py.

These never shell out to a real sqlmap binary and never touch the network:
subprocess.run is monkeypatched. That keeps the suite fast, deterministic,
and safe to run anywhere (consistent with the rest of VULNX's tests, which
only ever hit the in-process fixture_server, never a real site).
"""

from __future__ import annotations

import subprocess

import pytest

from modules.models import Confidence, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget
from modules.sqlmap_scanner import (
    _parse_dbms,
    _parse_sqlmap_output,
    run_sqlmap_scan,
    to_findings,
)

_SAMPLE_OUTPUT = """
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: id=1 AND (SELECT 2*(IF((1=1),SLEEP(0),8))) -- -

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(0x716,0x71)-- -
---
Parameter: user (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: user=admin' AND 1=1-- -

back-end DBMS: MySQL >= 5.0
"""


def test_parse_sqlmap_output_multiple_types_same_parameter():
    findings = _parse_sqlmap_output(_SAMPLE_OUTPUT)
    assert len(findings) == 3
    assert findings[0].parameter == "id" and findings[0].method == "GET"
    assert findings[1].parameter == "id" and findings[1].injection_type == "UNION query"
    assert findings[2].parameter == "user" and findings[2].method == "POST"


def test_parse_sqlmap_output_no_injection_found():
    clean_output = "\n[INFO] testing parameter 'id'\n[INFO] all tested parameters do not appear injectable\n"
    assert _parse_sqlmap_output(clean_output) == []


def test_parse_dbms():
    assert _parse_dbms(_SAMPLE_OUTPUT) == "MySQL >= 5.0"
    assert _parse_dbms("no dbms line here") is None


def test_to_findings_maps_to_verified_critical():
    target = ParamTarget(url="https://authorized.example/product", method="GET", param="id")
    findings = _parse_sqlmap_output(_SAMPLE_OUTPUT)

    class FakeResult:
        def __init__(self, findings, dbms):
            self.findings = findings
            self.dbms = dbms

    fake_result = FakeResult(findings, "MySQL >= 5.0")
    out = to_findings(fake_result, target)
    assert len(out) == 3
    for f in out:
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH
        assert f.status == VerificationStatus.VERIFIED
        assert f.module == "sqlmap"
        assert "MySQL" in f.note


def test_run_sqlmap_scan_reports_unavailable_when_binary_missing(monkeypatch):
    import modules.sqlmap_scanner as sm

    monkeypatch.setattr(sm, "sqlmap_available", lambda: False)
    target = ParamTarget(url="https://authorized.example/product", method="GET", param="id")
    result = run_sqlmap_scan(target)
    assert result.available is False
    assert result.ran is False
    assert "not found on PATH" in result.error


def test_run_sqlmap_scan_never_includes_destructive_flags_and_clamps_risk(monkeypatch):
    import modules.sqlmap_scanner as sm

    monkeypatch.setattr(sm, "sqlmap_available", lambda: True)

    captured = {}

    class FakeCompletedProcess:
        stdout = _SAMPLE_OUTPUT
        stderr = ""
        returncode = 0

    def fake_run(args, shell, capture_output, text, timeout):
        captured["args"] = args
        assert shell is False
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    target = ParamTarget(url="https://authorized.example/product", method="GET", param="id")
    # Intentionally request over-limit, risky values — the module must clamp them.
    result = run_sqlmap_scan(target, level=99, risk=3)

    args = captured["args"]
    assert "--dump" not in args
    assert "--os-shell" not in args
    assert "--sql-shell" not in args
    assert "--crawl" not in args
    assert args[args.index("--risk") + 1] == "1"          # hard-capped regardless of input
    assert int(args[args.index("--level") + 1]) <= 3       # hard-capped regardless of input
    assert "S" not in args[args.index("--technique") + 1]  # no stacked queries
    assert result.ran is True
    assert len(result.findings) == 3


def test_run_sqlmap_scan_post_target_uses_data_flag(monkeypatch):
    import modules.sqlmap_scanner as sm

    monkeypatch.setattr(sm, "sqlmap_available", lambda: True)
    captured = {}

    class FakeCompletedProcess:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(args, shell, capture_output, text, timeout):
        captured["args"] = args
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    target = ParamTarget(url="https://authorized.example/login", method="POST", param="user")
    run_sqlmap_scan(target)
    args = captured["args"]
    assert "--data" in args
    assert args[args.index("--data") + 1] == "user=1"


def test_run_sqlmap_scan_handles_timeout(monkeypatch):
    import modules.sqlmap_scanner as sm

    monkeypatch.setattr(sm, "sqlmap_available", lambda: True)

    def fake_run(args, shell, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(subprocess, "run", fake_run)

    target = ParamTarget(url="https://authorized.example/product", method="GET", param="id")
    result = run_sqlmap_scan(target, subprocess_timeout_seconds=5)
    assert result.ran is False
    assert "timed out" in result.error
