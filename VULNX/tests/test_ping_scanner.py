"""
Tests for modules/ping_scanner.py. subprocess.run is mocked throughout —
no real `ping` binary or network access is required.
"""

from __future__ import annotations

import subprocess

import pytest

from modules.ping_scanner import _parse_avg_rtt, _parse_packet_stats, _parse_resolved_ip, run_ping

_MACOS_SUCCESS = """PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=55 time=12.123 ms

--- example.com ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 12.123/14.160/16.012/1.234 ms
"""

_LINUX_SUCCESS = """PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=55 time=12.1 ms

--- example.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 12.123/14.345/16.012/1.234 ms
"""

_UNREACHABLE = """PING 10.0.0.99 (10.0.0.99): 56 data bytes

--- 10.0.0.99 ping statistics ---
3 packets transmitted, 0 packets received, 100.0% packet loss
"""


def test_parse_packet_stats_macos_and_linux():
    assert _parse_packet_stats(_MACOS_SUCCESS) == (3, 3, 0.0)
    assert _parse_packet_stats(_LINUX_SUCCESS) == (3, 3, 0.0)
    assert _parse_packet_stats(_UNREACHABLE) == (3, 0, 100.0)


def test_parse_avg_rtt_macos_and_linux():
    assert _parse_avg_rtt(_MACOS_SUCCESS) == 14.16
    assert _parse_avg_rtt(_LINUX_SUCCESS) == 14.345
    assert _parse_avg_rtt(_UNREACHABLE) is None


def test_parse_resolved_ip_macos_linux_ipv6_and_bare_ip():
    assert _parse_resolved_ip(_MACOS_SUCCESS) == "93.184.216.34"
    assert _parse_resolved_ip(_LINUX_SUCCESS) == "93.184.216.34"
    assert _parse_resolved_ip("PING 93.184.216.34 (93.184.216.34): 56 data bytes\n") == "93.184.216.34"
    assert _parse_resolved_ip("PING example.com(2606:2800:220:1:248:1893:25c8:1946) 56 data bytes\n") == \
        "2606:2800:220:1:248:1893:25c8:1946"
    assert _parse_resolved_ip("ping: cannot resolve foo.invalid: Unknown host\n") is None


def test_run_ping_reports_unavailable_when_binary_missing(monkeypatch):
    import modules.ping_scanner as pm

    monkeypatch.setattr(pm, "ping_available", lambda: False)
    result = run_ping("example.com")
    assert result.available is False
    assert result.ran is False
    assert "not found on PATH" in result.error


def test_run_ping_success(monkeypatch):
    import modules.ping_scanner as pm

    monkeypatch.setattr(pm, "ping_available", lambda: True)

    captured = {}

    class FakeCompletedProcess:
        stdout = _MACOS_SUCCESS
        stderr = ""
        returncode = 0

    def fake_run(args, shell, capture_output, text, timeout):
        captured["args"] = args
        assert shell is False
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_ping("example.com", count=3)
    assert captured["args"] == ["ping", "-c", "3", "example.com"]
    assert result.reachable is True
    assert result.packets_sent == 3
    assert result.packets_received == 3
    assert result.packet_loss_pct == 0.0
    assert result.avg_rtt_ms == 14.16
    assert result.resolved_ip == "93.184.216.34"
    assert result.error is None


def test_run_ping_unreachable_sets_reachable_false(monkeypatch):
    import modules.ping_scanner as pm

    monkeypatch.setattr(pm, "ping_available", lambda: True)

    class FakeCompletedProcess:
        stdout = _UNREACHABLE
        stderr = ""
        returncode = 1  # BSD/Linux ping exits non-zero when nothing is received

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompletedProcess())

    result = run_ping("10.0.0.99")
    assert result.ran is True
    assert result.reachable is False
    assert result.packet_loss_pct == 100.0
    assert result.error  # should carry a human-readable explanation


def test_run_ping_clamps_count(monkeypatch):
    import modules.ping_scanner as pm

    monkeypatch.setattr(pm, "ping_available", lambda: True)
    captured = {}

    class FakeCompletedProcess:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(args, **kwargs):
        captured["args"] = args
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    run_ping("example.com", count=999)  # way over the 10 ceiling
    assert captured["args"][2] == "10"  # clamped, never flooded


def test_run_ping_handles_timeout(monkeypatch):
    import modules.ping_scanner as pm

    monkeypatch.setattr(pm, "ping_available", lambda: True)

    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kwargs.get("timeout"))

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_ping("example.com", subprocess_timeout_seconds=5)
    assert result.ran is False
    assert "timed out" in result.error
