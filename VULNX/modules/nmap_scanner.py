"""
nmap_scanner.py

Safe, conservative Nmap integration. Nmap is invoked with a fixed argument
list and shell=False — target input is never interpolated into a shell
string. Nmap is an optional system dependency; its absence is handled
gracefully.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

COMMON_TCP_PORTS = "21,22,25,53,80,110,143,443,445,465,587,993,995,3306,3389,5432,6379,8000,8080,8443"


def _nmap_install_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return "Install it with Homebrew: brew install nmap"
    if system == "Linux":
        return "Install it with: sudo apt update && sudo apt install nmap"
    return "Install nmap from https://nmap.org/download.html for your platform."


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None


@dataclass
class NmapResult:
    available: bool
    ran: bool = False
    ports: List[PortResult] = field(default_factory=list)
    raw_stdout: str = ""
    error: Optional[str] = None
    command: Optional[List[str]] = None


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap_scan(
    host: str,
    *,
    service_version_detection: bool = False,
    timeout_seconds: int = 60,
) -> NmapResult:
    """
    Conservative scan of a fixed, documented list of common TCP ports
    against a single host. `host` must already have passed VULNX's safety
    validation before this function is called.
    """
    if not nmap_available():
        return NmapResult(
            available=False,
            error=f"nmap binary not found on PATH. {_nmap_install_hint()}",
        )

    args = ["nmap", "-Pn", "-T3", "-p", COMMON_TCP_PORTS]
    if service_version_detection:
        args.append("-sV")
    args.append(host)

    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return NmapResult(available=True, ran=False, error="nmap scan timed out.", command=args)
    except OSError as exc:
        return NmapResult(available=True, ran=False, error=f"Failed to run nmap: {exc}", command=args)

    result = NmapResult(available=True, ran=True, raw_stdout=proc.stdout, command=args)
    if proc.returncode != 0:
        result.error = f"nmap exited with status {proc.returncode}: {proc.stderr.strip()[:300]}"
        return result

    result.ports = _parse_nmap_output(proc.stdout)
    return result


def _parse_nmap_output(output: str) -> List[PortResult]:
    ports: List[PortResult] = []
    for line in output.splitlines():
        line = line.strip()
        if "/tcp" not in line and "/udp" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        port_proto = parts[0]
        state = parts[1]
        if "/" not in port_proto:
            continue
        port_str, proto = port_proto.split("/", 1)
        if not port_str.isdigit():
            continue
        if state not in ("open", "closed", "filtered", "open|filtered"):
            continue
        service = parts[2] if len(parts) >= 3 else None
        version = " ".join(parts[3:]) if len(parts) > 3 else None
        ports.append(
            PortResult(port=int(port_str), protocol=proto, state=state, service=service, version=version)
        )
    return ports
