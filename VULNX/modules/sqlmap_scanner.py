"""
sqlmap_scanner.py

Optional, opt-in integration with sqlmap (https://sqlmap.org /
https://github.com/sqlmapproject/sqlmap) for deeper SQL-injection
*detection*. This module never installs or ships sqlmap — it only shells
out to a pre-existing `sqlmap` binary on PATH, the same way
nmap_scanner.py shells out to `nmap`.

Safety model (read this before changing the flags below):
  - `shell=False` with a fixed, explicitly-built argument list. The only
    untrusted-ish input is the already-scope-validated target URL and a
    parameter name discovered by VULNX itself; neither is ever passed
    through a shell, so there is no command-injection surface.
  - Detection only. We never pass `--dump`, `--dump-all`, `--tables`,
    `--columns`, `--passwords`, `--os-shell`, `--os-cmd`, `--os-pwn`,
    `--sql-shell`, `--file-read`, `--file-write`, `--reg-read`, or any
    other data-extraction / code-execution flag. Default sqlmap behavior
    without those flags is to identify and report injectable parameters
    only.
  - `--risk` is hard-capped at 1 in code (not just by default), regardless
    of what a caller requests. Risk 2-3 payloads include OR-based and
    heavier time-based requests that can affect UPDATE/DELETE statements
    on a live database; that's out of scope for an authorized-but-still
    non-destructive scanner.
  - `--technique` is restricted to B,E,U,T (boolean, error-based, UNION,
    time-based). Stacked queries (S) are excluded: they let the back end
    execute a second, arbitrary statement, which is a materially
    different (and riskier) capability than the read-only detection
    techniques.
  - `--batch` forces non-interactive mode so a hung prompt can never block
    the scan or silently escalate to something destructive.
  - `--threads 1` plus an explicit per-request `--timeout`, matching
    VULNX's single-connection, rate-limited philosophy elsewhere.
  - A hard subprocess `timeout` bounds total run time per parameter so one
    slow target can't hang the whole scan.
  - Only tests the single parameter VULNX already discovered (`-p`), never
    every parameter sqlmap can find on its own, and only the single URL
    passed in — never crawls on its own (`--crawl` is never set).

Caveat worth knowing: sqlmap makes its own HTTP connections rather than
going through VULNX's SafeHTTPClient, so VULNX's own rate limiter and
per-redirect-hop DNS re-resolution do not apply to sqlmap's traffic.
Scope is still enforced at the call site (see vulnx.py) by checking the
target URL against the already-validated TargetScope before this module
is ever invoked.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from modules.models import Confidence, Finding, Severity, VerificationStatus
from modules.parameter_discovery import ParamTarget

_MAX_RISK = 1          # hard ceiling, independent of any caller-supplied value
_MAX_LEVEL = 3          # sqlmap's own range is 1-5; cap how invasive the test payload set gets
_ALLOWED_TECHNIQUES = "BEUT"  # Boolean, Error-based, UNION, Time-based. No Stacked (S), no inline (Q).

_FORBIDDEN_FLAG_MARKERS = (
    "--dump", "--dump-all", "--tables", "--columns", "--passwords",
    "--os-shell", "--os-cmd", "--os-pwn", "--sql-shell", "--file-read",
    "--file-write", "--reg-read", "--reg-add", "--reg-del", "--crawl",
    "--eval",
)


def _sqlmap_install_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return (
            "Install it with: brew install sqlmap  (or clone the official repo: "
            "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git and "
            "run python3 sqlmap/sqlmap.py)"
        )
    if system == "Linux":
        return (
            "Install it with: sudo apt update && sudo apt install sqlmap  "
            "(or clone the official repo: git clone --depth 1 "
            "https://github.com/sqlmapproject/sqlmap.git)"
        )
    return "Get it from the official repo: https://github.com/sqlmapproject/sqlmap"


@dataclass
class SqlmapFinding:
    parameter: str
    method: str
    injection_type: str
    title: str
    payload: str


@dataclass
class SqlmapResult:
    available: bool
    ran: bool = False
    findings: List[SqlmapFinding] = field(default_factory=list)
    dbms: Optional[str] = None
    raw_stdout: str = ""
    error: Optional[str] = None
    command: Optional[List[str]] = None


def sqlmap_available() -> bool:
    return shutil.which("sqlmap") is not None


def run_sqlmap_scan(
    target: ParamTarget,
    *,
    level: int = 1,
    risk: int = 1,
    request_timeout_seconds: int = 10,
    subprocess_timeout_seconds: int = 120,
    random_agent: bool = False,
) -> SqlmapResult:
    """
    Run sqlmap's detection-only pipeline against a single already-discovered
    parameter. `target` must already have passed VULNX's scope checks
    before this is called — this function does not re-validate scope.
    """
    if not sqlmap_available():
        return SqlmapResult(
            available=False,
            error=f"sqlmap binary not found on PATH. {_sqlmap_install_hint()}",
        )

    safe_level = max(1, min(int(level), _MAX_LEVEL))
    safe_risk = max(1, min(int(risk), _MAX_RISK))

    args = [
        "sqlmap",
        "-u", target.url if target.method.upper() == "GET" else target.url,
        "--batch",
        "--level", str(safe_level),
        "--risk", str(safe_risk),
        "--technique", _ALLOWED_TECHNIQUES,
        "-p", target.param,
        "--threads", "1",
        "--timeout", str(request_timeout_seconds),
        "--retries", "1",
        "--disable-coloring",
    ]

    if target.method.upper() == "GET":
        sep = "&" if "?" in target.url else "?"
        args[2] = f"{target.url}{sep}{target.param}=1"
    else:
        args += ["--data", f"{target.param}=1"]

    if random_agent:
        args.append("--random-agent")

    # Defense in depth: assert none of the destructive/escalating flags ever
    # made it into the final command, even though we built it ourselves from
    # a fixed template above.
    for forbidden in _FORBIDDEN_FLAG_MARKERS:
        if forbidden in args:
            return SqlmapResult(
                available=True, ran=False,
                error=f"Internal safety check blocked flag {forbidden!r}; refusing to run.",
                command=args,
            )

    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=subprocess_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return SqlmapResult(
            available=True, ran=False,
            error=f"sqlmap scan of parameter {target.param!r} timed out after {subprocess_timeout_seconds}s.",
            command=args,
        )
    except OSError as exc:
        return SqlmapResult(available=True, ran=False, error=f"Failed to run sqlmap: {exc}", command=args)

    result = SqlmapResult(available=True, ran=True, raw_stdout=proc.stdout, command=args)
    result.findings = _parse_sqlmap_output(proc.stdout)
    result.dbms = _parse_dbms(proc.stdout)
    return result


def _parse_sqlmap_output(output: str) -> List[SqlmapFinding]:
    """
    Parse sqlmap's human-readable stdout for its injection-point summary
    block, e.g.:

        Parameter: id (GET)
            Type: error-based
            Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
            Payload: id=1 AND ...
    """
    findings: List[SqlmapFinding] = []
    param_re = re.compile(r"^Parameter:\s*(\S+)\s*\(([A-Z]+)\)\s*$")
    type_re = re.compile(r"^\s*Type:\s*(.+)$")
    title_re = re.compile(r"^\s*Title:\s*(.+)$")
    payload_re = re.compile(r"^\s*Payload:\s*(.+)$")

    # sqlmap prints one "Parameter: x (GET)" header per parameter, then one or
    # more Type/Title/Payload triples underneath it (e.g. both error-based AND
    # UNION-based for the same parameter). The header is NOT repeated for each
    # triple, so we keep the parameter/method "sticky" across triples and only
    # reset the in-progress triple fields on each new Payload line.
    param_ctx = None
    cur_type = cur_title = ""
    for line in output.splitlines():
        m = param_re.match(line.strip())
        if m:
            param_ctx = {"parameter": m.group(1), "method": m.group(2)}
            cur_type = cur_title = ""
            continue
        if param_ctx is None:
            continue
        m = type_re.match(line)
        if m:
            cur_type = m.group(1).strip()
            continue
        m = title_re.match(line)
        if m:
            cur_title = m.group(1).strip()
            continue
        m = payload_re.match(line)
        if m:
            findings.append(
                SqlmapFinding(
                    parameter=param_ctx["parameter"],
                    method=param_ctx["method"],
                    injection_type=cur_type,
                    title=cur_title,
                    payload=m.group(1).strip(),
                )
            )
            cur_type = cur_title = ""
            continue
        # A blank line or "---" separator ends the parameter block in sqlmap's
        # output; a stray unrelated line shouldn't let us bleed into keeping
        # (harmless either way since only Type/Title/Payload lines are acted
        # on, but reset defensively at explicit separators).
        if line.strip() in ("---", "") and cur_type == "" and cur_title == "":
            continue
    return findings


def _parse_dbms(output: str) -> Optional[str]:
    m = re.search(r"back-end DBMS:\s*(.+)", output)
    if m:
        return m.group(1).strip()
    return None


def to_findings(result: SqlmapResult, target: ParamTarget) -> List[Finding]:
    """Convert sqlmap's parsed output into VULNX's shared Finding model."""
    out: List[Finding] = []
    for sf in result.findings:
        evidence = f"sqlmap confirmed {sf.injection_type}: {sf.title}. Payload: {sf.payload}"
        out.append(
            Finding(
                category="SQL Injection (sqlmap-confirmed)",
                affected_url=target.url,
                parameter=sf.parameter,
                http_method=sf.method,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                status=VerificationStatus.VERIFIED,
                evidence=evidence,
                remediation=(
                    "Use parameterized queries / prepared statements for all database "
                    "access involving this input, apply least-privilege DB credentials, "
                    "and disable verbose database error output in responses."
                ),
                module="sqlmap",
                note=(
                    f"Back-end DBMS: {result.dbms}. " if result.dbms else ""
                ) + "Confirmed via sqlmap detection-only run; no data was extracted.",
            )
        )
    return out
