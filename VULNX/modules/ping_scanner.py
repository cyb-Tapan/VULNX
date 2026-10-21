"""
ping_scanner.py

Safe, conservative host-reachability check via the system `ping` binary.
Same safety model as nmap_scanner.py: a fixed argument list, `shell=False`
— the target host is never interpolated into a shell string — and a hard
subprocess timeout so an unreachable host can't hang the scan.

`ping` is a near-universal system binary (no extra install needed on macOS
or Linux), used here purely as an early, lightweight "is this host alive"
signal before the heavier nmap port scan runs. A failed or blocked ping
does NOT abort the scan — many servers/firewalls drop ICMP entirely while
still serving HTTP perfectly well — it's reported and the scan continues.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class PingResult:
    available: bool
    ran: bool = False
    reachable: bool = False
    resolved_ip: Optional[str] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None
    packet_loss_pct: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    raw_stdout: str = ""
    error: Optional[str] = None
    command: Optional[list] = None


def ping_available() -> bool:
    return shutil.which("ping") is not None


def run_ping(host: str, *, count: int = 3, subprocess_timeout_seconds: int = 15) -> PingResult:
    """
    Ping `host` `count` times. `host` must already be a validated,
    scope-approved hostname (e.g. TargetScope.host) — this function does
    no scope checking of its own.
    """
    if not ping_available():
        return PingResult(available=False, error="ping binary not found on PATH.")

    safe_count = max(1, min(int(count), 10))  # never let a flag turn this into a flood
    args = ["ping", "-c", str(safe_count), host]

    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=subprocess_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            available=True, ran=False,
            error=f"ping of {host!r} timed out after {subprocess_timeout_seconds}s.",
            command=args,
        )
    except OSError as exc:
        return PingResult(available=True, ran=False, error=f"Failed to run ping: {exc}", command=args)

    result = PingResult(available=True, ran=True, raw_stdout=proc.stdout, command=args)
    result.reachable = proc.returncode == 0
    result.resolved_ip = _parse_resolved_ip(proc.stdout)
    result.packets_sent, result.packets_received, result.packet_loss_pct = _parse_packet_stats(proc.stdout)
    result.avg_rtt_ms = _parse_avg_rtt(proc.stdout)
    if not result.reachable and not result.error:
        if result.resolved_ip:
            result.error = "Host did not respond to ICMP ping (may be filtered by a firewall)."
        else:
            # ping couldn't even resolve the name — surface stderr, since that's
            # usually where "cannot resolve"/"Name or service not known" lives.
            result.error = (proc.stderr or "").strip() or "ping could not resolve the hostname."
    return result


def _parse_resolved_ip(output: str) -> Optional[str]:
    # First line of ping's output always has the form:
    #   macOS:  "PING example.com (93.184.216.34): 56 data bytes"
    #   Linux:  "PING example.com (93.184.216.34) 56(84) bytes of data."
    # and the same even when `host` passed to ping was already a bare IP
    # ("PING 93.184.216.34 (93.184.216.34): ..."). Matches IPv4 and IPv6.
    m = re.search(r"^PING\s+\S+?\s*\(([0-9a-fA-F:.]+)\)", output, re.M)
    if m:
        return m.group(1)
    return None


def _parse_packet_stats(output: str):
    # Matches both BSD/macOS ("3 packets transmitted, 3 packets received, 0.0% packet loss")
    # and Linux/iputils ("3 packets transmitted, 3 received, 0% packet loss, ...") phrasing.
    m = re.search(
        r"(\d+)\s*packets?\s*transmitted,\s*(\d+)\s*(?:packets\s*)?received.*?([\d.]+)%\s*packet\s*loss",
        output, re.S,
    )
    if not m:
        return None, None, None
    return int(m.group(1)), int(m.group(2)), float(m.group(3))


def _parse_avg_rtt(output: str) -> Optional[float]:
    # BSD/macOS: "round-trip min/avg/max/stddev = 12.1/14.3/16.0/1.2 ms"
    # Linux:     "rtt min/avg/max/mdev = 12.123/14.345/16.012/1.234 ms"
    m = re.search(r"(?:round-trip|rtt)\s+min/avg/max\S*\s*=\s*[\d.]+/([\d.]+)/", output)
    if m:
        return float(m.group(1))
    return None
