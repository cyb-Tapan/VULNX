import subprocess
import sys

import pytest

import vulnx


def test_version_flag(capsys):
    rc = vulnx.main(["--version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "VULNX" in captured.out
    assert vulnx.VERSION in captured.out


def test_help_flag_exits_zero():
    proc = subprocess.run(
        [sys.executable, "vulnx.py", "--help"],
        cwd=".",
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "--url" in proc.stdout
    assert "--authorized" in proc.stdout


def test_missing_url_errors():
    with pytest.raises(SystemExit):
        vulnx.main([])


def test_missing_authorized_errors():
    with pytest.raises(SystemExit):
        vulnx.main(["-u", "http://127.0.0.1:1/"])


def test_invalid_timeout_rejected():
    with pytest.raises(SystemExit):
        vulnx.main(["-u", "http://127.0.0.1:1/", "--authorized", "--timeout", "0"])


def test_invalid_max_pages_rejected():
    with pytest.raises(SystemExit):
        vulnx.main(["-u", "http://127.0.0.1:1/", "--authorized", "--max-pages", "0"])


def test_invalid_scan_profile_rejected():
    with pytest.raises(SystemExit):
        vulnx.main(["-u", "http://127.0.0.1:1/", "--authorized", "--scan", "nonsense"])


def test_unsafe_target_blocked_without_lab_profile(capsys):
    rc = vulnx.main(
        ["-u", "http://127.0.0.1:1/", "--authorized", "--scan", "recon", "--profile", "safe"]
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "ERROR" in captured.out or "private" in captured.out.lower()


def test_full_scan_against_local_lab_fixture(fixture_server, capsys):
    rc = vulnx.main(
        [
            "-u", fixture_server,
            "--authorized",
            "--scan", "full",
            "--profile", "lab",
            "--batch",
            "--max-pages", "10",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "SUMMARY" in captured.out
    assert "interrupted" not in captured.out.lower()
