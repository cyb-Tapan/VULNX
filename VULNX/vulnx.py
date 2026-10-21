#!/usr/bin/env python3
"""
vulnx.py

VULNX — Web Security Assessment CLI
Entry point: argument parsing and scan orchestration only. All detection
logic lives in modules/. Nothing in this file writes scan results to
disk; results exist only in memory for the duration of the process and
are printed live to the terminal.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys

# --- Defensive import setup ------------------------------------------------
# Guarantee this script's own directory is first on sys.path, regardless of
# how it was invoked (symlink, different cwd, PATH shenanigans, an IDE's
# "run" button, etc). This also lets us detect, with a clear message instead
# of a raw traceback, the one scenario that reliably produces
# "ModuleNotFoundError: No module named 'modules.models'" while a top-level
# `modules` package still imports fine: a *different*, unrelated package
# also named `modules` is installed (e.g. via pip) and is shadowing the
# local modules/ directory that ships with VULNX.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR in sys.path:
    sys.path.remove(_SCRIPT_DIR)
sys.path.insert(0, _SCRIPT_DIR)

_expected_modules_dir = os.path.join(_SCRIPT_DIR, "modules")
if not os.path.isdir(_expected_modules_dir):
    sys.exit(
        f"[ERROR] Could not find the modules/ directory next to vulnx.py.\n"
        f"        Expected it at: {_expected_modules_dir}\n"
        f"        This usually means the project wasn't extracted/copied completely.\n"
        f"        Re-download or re-extract VULNX and make sure the 'modules' folder\n"
        f"        sits in the same directory as vulnx.py."
    )

_expected_models_file = os.path.join(_expected_modules_dir, "models.py")
if not os.path.isfile(_expected_models_file):
    sys.exit(
        f"[ERROR] modules/models.py is missing from {_expected_modules_dir}.\n"
        f"        The modules/ folder exists but is incomplete (likely a partial\n"
        f"        copy or extraction). Re-extract the original VULNX archive into\n"
        f"        a clean, empty folder rather than merging it into an existing one."
    )

try:
    import modules as _modules_probe
except ImportError as exc:
    sys.exit(f"[ERROR] Failed to import the local 'modules' package: {exc}")

_resolved_modules_dir = os.path.dirname(os.path.abspath(_modules_probe.__file__))
if os.path.normcase(_resolved_modules_dir) != os.path.normcase(_expected_modules_dir):
    sys.exit(
        f"[ERROR] A different 'modules' package is shadowing VULNX's own modules/ folder.\n"
        f"        Python is loading 'modules' from: {_resolved_modules_dir}\n"
        f"        Expected it to load from:         {_expected_modules_dir}\n"
        f"        Likely cause: a pip-installed package also named 'modules' is on your\n"
        f"        Python path. Check with:  pip show modules\n"
        f"        If that prints anything, remove it with:  pip uninstall modules\n"
        f"        then run VULNX again."
    )
del _modules_probe

from modules import terminal_output as out
from modules.endpoint_discovery import crawl
from modules.models import ScanStats
from modules.nmap_scanner import run_nmap_scan
from modules.ping_scanner import run_ping
from modules.parameter_discovery import discover_parameters
from modules.recon import run_http_recon, run_tls_recon
from modules.safety import (
    SafeHTTPClient,
    SafetyConfig,
    ScopeViolation,
    TargetScope,
    UnsafeTargetError,
)
from modules.technology_detection import detect as detect_technology

VERSION = "1.0.0"

PROFILES = ["recon", "headers", "endpoints", "passive", "sqli", "xss", "full"]

MAX_PAGES_CEILING = 500
MAX_CONCURRENCY_CEILING = 20


class ScanInterrupted(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnx.py",
        description="VULNX — Web Security Assessment CLI (authorized use only).",
    )
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://authorized.example)")
    parser.add_argument("--scan", choices=PROFILES, default="recon", help="Scan profile.")
    parser.add_argument("--batch", action="store_true", help="Disable interactive prompts.")
    parser.add_argument(
        "--random-agent", action="store_true", help="Choose a User-Agent from a maintained list."
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Request read timeout in seconds.")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages crawled.")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Maximum requests per second.")
    parser.add_argument("--concurrency", type=int, default=1, help="Bounded concurrency (currently sequential=1 enforced).")
    parser.add_argument(
        "--profile", choices=["safe", "lab"], default="safe",
        help="'safe' blocks private/loopback targets; 'lab' permits an explicit local-lab target.",
    )
    parser.add_argument(
        "--authorized", action="store_true",
        help="Acknowledge you are authorized to test this target. Required for any scan.",
    )
    parser.add_argument(
        "--sqlmap", action="store_true",
        help="Also run detection-only sqlmap checks (requires sqlmap on PATH) on the "
             "sqli/full profiles. Opt-in: heavier and noisier than the built-in probe. "
             "Never dumps data; only confirms whether a parameter is injectable.",
    )
    parser.add_argument(
        "--sqlmap-level", type=int, default=1,
        help="sqlmap test-payload level, 1-3 (hard-capped at 3 regardless of value given).",
    )
    parser.add_argument(
        "--sqlmap-max-targets", type=int, default=5,
        help="Maximum number of discovered parameters to run sqlmap against (keeps scan time bounded).",
    )
    parser.add_argument(
        "--skip-ping", action="store_true",
        help="Skip the initial ICMP ping reachability check (it never blocks the scan either way).",
    )
    parser.add_argument(
        "--ping-count", type=int, default=3,
        help="Number of ICMP echo requests to send in the initial reachability check (1-10).",
    )
    parser.add_argument(
        "--skip-portscan", action="store_true",
        help="Skip the nmap port scan step (runs for every profile by default; requires nmap on PATH).",
    )
    parser.add_argument("--verbose", action="store_true", help="Detailed diagnostics.")
    parser.add_argument("--version", action="store_true", help="Display version and exit.")
    return parser


_RANDOM_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]


def validate_args(args: argparse.Namespace) -> None:
    if args.version:
        return
    if not args.url:
        raise SystemExit("[ERROR] --url is required (use --version for version info).")
    if not args.authorized:
        raise SystemExit(
            "[ERROR] --authorized is required. This acknowledges you are authorized to "
            "test the specified target; it is not proof of authorization."
        )
    if args.timeout <= 0 or args.timeout > 120:
        raise SystemExit("[ERROR] --timeout must be between 0 and 120 seconds.")
    if args.max_pages <= 0 or args.max_pages > MAX_PAGES_CEILING:
        raise SystemExit(f"[ERROR] --max-pages must be between 1 and {MAX_PAGES_CEILING}.")
    if args.rate_limit <= 0 or args.rate_limit > 50:
        raise SystemExit("[ERROR] --rate-limit must be between 0 and 50 requests/second.")
    if args.concurrency <= 0 or args.concurrency > MAX_CONCURRENCY_CEILING:
        raise SystemExit(f"[ERROR] --concurrency must be between 1 and {MAX_CONCURRENCY_CEILING}.")
    if args.sqlmap_level <= 0 or args.sqlmap_level > 5:
        raise SystemExit("[ERROR] --sqlmap-level must be between 1 and 5 (effective max enforced is 3).")
    if args.sqlmap_max_targets <= 0 or args.sqlmap_max_targets > 50:
        raise SystemExit("[ERROR] --sqlmap-max-targets must be between 1 and 50.")
    if args.ping_count <= 0 or args.ping_count > 10:
        raise SystemExit("[ERROR] --ping-count must be between 1 and 10.")
    if args.sqlmap and args.scan not in ("sqli", "full"):
        raise SystemExit("[ERROR] --sqlmap only applies to --scan sqli or --scan full.")


def run_scan(args: argparse.Namespace) -> ScanStats:
    stats = ScanStats()

    config = SafetyConfig(
        allow_local_lab=(args.profile == "lab"),
        read_timeout=args.timeout,
        max_requests_per_second=args.rate_limit,
        max_pages=args.max_pages,
    )
    if args.random_agent:
        import random

        config.user_agent = random.choice(_RANDOM_AGENTS)

    out.info("Validating target and authorization...")
    scope = TargetScope(args.url, config)  # raises UnsafeTargetError; handled by caller

    client = SafeHTTPClient(scope, stats=stats)

    try:
        _run_profile(args, scope, client, stats)
    except ScanInterrupted:
        stats.interrupted = True
        out.warning("Scan interrupted by user (Ctrl+C). Finalizing partial results...")

    return stats


def _run_profile(args, scope: TargetScope, client: SafeHTTPClient, stats: ScanStats) -> None:
    profile = args.scan
    base_url = scope.base_url

    # Step 1 of every scan, regardless of profile: ping, then port scan.
    # Neither failing here aborts the scan — they're reported and the scan
    # continues into the profile-specific work below.
    _run_ping_step(args, scope, stats)
    _check_interrupted()
    _run_portscan_step(args, scope, stats)
    _check_interrupted()

    if profile in ("recon", "headers", "endpoints", "passive", "sqli", "xss", "full"):
        out.info("Starting reconnaissance...")
        stats.modules_run.append("recon")
        recon_result = run_http_recon(client, base_url)
        if recon_result.error:
            out.error(f"HTTP recon failed: {recon_result.error}")
            stats.modules_failed.append("recon")
        else:
            out.success(f"HTTP status: {recon_result.status_code}")
            for hop in recon_result.redirect_chain[:-1]:
                out.info(f"Redirect: {hop}")

        tls_info = None
        if scope.scheme == "https":
            tls_info = run_tls_recon(scope.host, scope.port)
            if tls_info and not tls_info.get("error"):
                out.success(f"TLS certificate subject: {tls_info.get('subject')}")

        if profile == "recon":
            _report_misconfig(client, recon_result, tls_info, base_url, stats)
            return

        if profile == "headers":
            _report_misconfig(client, recon_result, tls_info, base_url, stats)
            return

    _check_interrupted()

    if profile in ("endpoints", "passive", "sqli", "xss", "full"):
        out.info("Discovering endpoints...")
        stats.modules_run.append("endpoint_discovery")
        crawl_result = crawl(client, scope, base_url, args.max_pages, stats=stats)
        for ep in sorted(crawl_result.endpoints):
            out.endpoint(ep)
        for route in sorted(crawl_result.js_routes):
            out.endpoint(f"(from JS) {route}")

        if crawl_result.pages_visited:
            sample_resp, _ = client.get(base_url)
            body = sample_resp.text if sample_resp is not None else ""
            headers = {k.lower(): v for k, v in (sample_resp.headers.items() if sample_resp is not None else [])}
            tech = detect_technology(headers, body)
            if tech:
                out.info("Technology indicators: " + ", ".join(tech))

        if profile == "endpoints":
            return

        _check_interrupted()

        from modules.csrf import review_forms
        from modules.file_upload import review_html
        from modules.misconfiguration import review as review_misconfig

        stats.modules_run.append("csrf")
        for f in review_forms(crawl_result.forms, recon_result):
            stats.record_finding(f)
            out.print_finding(f)

        stats.modules_run.append("file_upload")
        if crawl_result.pages_visited:
            sample_resp, _ = client.get(base_url)
            if sample_resp is not None:
                for f in review_html(base_url, sample_resp.text):
                    stats.record_finding(f)
                    out.print_finding(f)

        if profile == "passive":
            _report_misconfig(client, recon_result, tls_info, base_url, stats, already_announced=True)
            return

        from modules.ssrf import review_target as ssrf_review
        from modules.directory_traversal import review_target as dt_review

        param_targets = discover_parameters(crawl_result)
        out.info(f"Discovered {len(param_targets)} testable parameter(s).")

        stats.modules_run.append("ssrf")
        stats.modules_run.append("directory_traversal")
        for t in param_targets:
            for f in ssrf_review(t):
                stats.record_finding(f)
                out.print_finding(f)
            for f in dt_review(t):
                stats.record_finding(f)
                out.print_finding(f)

        if profile in ("sqli", "full"):
            from modules.sqli import scan_target as sqli_scan

            out.info("Running SQL injection indicator checks (non-destructive)...")
            stats.modules_run.append("sqli")
            for t in param_targets:
                _check_interrupted()
                for f in sqli_scan(client, t):
                    stats.record_finding(f)
                    out.print_finding(f)

            if args.sqlmap:
                _run_sqlmap_pass(args, scope, param_targets, stats)

        if profile in ("xss", "full"):
            from modules.xss import scan_target as xss_scan

            out.info("Running XSS reflection checks...")
            stats.modules_run.append("xss")
            for t in param_targets:
                _check_interrupted()
                for f in xss_scan(client, t):
                    stats.record_finding(f)
                    out.print_finding(f)

        _report_misconfig(client, recon_result, tls_info, base_url, stats, already_announced=True)


def _run_ping_step(args, scope: TargetScope, stats: ScanStats) -> None:
    if args.skip_ping:
        out.skipped("Ping: skipped (--skip-ping).")
        stats.modules_skipped.append("ping")
        return

    out.info(f"Pinging {scope.host}...")
    result = run_ping(scope.host, count=args.ping_count)

    if not result.available:
        out.skipped(f"Ping: {result.error}")
        stats.modules_skipped.append("ping")
        return
    if not result.ran:
        out.error(f"Ping: {result.error}")
        stats.modules_failed.append("ping")
        return

    stats.modules_run.append("ping")
    ip_part = f" [{result.resolved_ip}]" if result.resolved_ip else ""
    if result.reachable:
        rtt = f", avg RTT {result.avg_rtt_ms:.1f}ms" if result.avg_rtt_ms is not None else ""
        loss = f", {result.packet_loss_pct:.0f}% packet loss" if result.packet_loss_pct is not None else ""
        out.success(f"Host {scope.host}{ip_part} is reachable (ICMP){rtt}{loss}")
    else:
        out.warning(
            f"Host {scope.host}{ip_part} did not respond to ICMP ping ({result.error or 'no reply'}). "
            "This is common behind firewalls/CDNs and does not necessarily mean the "
            "host is down — continuing with the rest of the scan."
        )


def _run_portscan_step(args, scope: TargetScope, stats: ScanStats) -> None:
    if args.skip_portscan:
        out.skipped("Port scan: skipped (--skip-portscan).")
        stats.modules_skipped.append("nmap")
        return

    out.info("Running port scan (nmap)...")
    nmap_result = run_nmap_scan(scope.host)
    if not nmap_result.available:
        out.skipped(f"Nmap: {nmap_result.error}")
        stats.modules_skipped.append("nmap")
        return
    if not nmap_result.ran:
        out.error(f"Nmap: {nmap_result.error}")
        stats.modules_failed.append("nmap")
        return

    stats.modules_run.append("nmap")
    stats.ports_discovered = len([p for p in nmap_result.ports if p.state == "open"])
    for p in nmap_result.ports:
        if p.state == "open":
            label = f"{p.port}/{p.protocol}"
            if p.service:
                label += f" {p.service}"
            out.open_port(label)
    if stats.ports_discovered == 0:
        out.info("Port scan: no open ports found among the common ports checked.")


def _run_sqlmap_pass(args, scope: TargetScope, param_targets, stats: ScanStats) -> None:
    from modules.sqlmap_scanner import run_sqlmap_scan, sqlmap_available, to_findings

    if not sqlmap_available():
        out.skipped(
            "sqlmap: binary not found on PATH. Install it, then re-run with --sqlmap. "
            "(macOS: brew install sqlmap  |  Debian/Kali: sudo apt install sqlmap  |  "
            "or clone https://github.com/sqlmapproject/sqlmap)"
        )
        stats.modules_skipped.append("sqlmap")
        return

    # Only ever test parameters on URLs that are still inside the operator-approved
    # scope, even though param_targets already come from an in-scope crawl.
    in_scope_targets = [t for t in param_targets if scope.is_in_scope(t.url)]
    targets_to_run = in_scope_targets[: args.sqlmap_max_targets]
    skipped_count = len(in_scope_targets) - len(targets_to_run)

    out.info(
        f"Running sqlmap detection-only checks on {len(targets_to_run)} "
        f"parameter(s) (level={min(args.sqlmap_level, 3)}, risk=1, no data extraction)..."
    )
    stats.modules_run.append("sqlmap")

    for t in targets_to_run:
        _check_interrupted()
        result = run_sqlmap_scan(
            t,
            level=args.sqlmap_level,
            risk=1,
            request_timeout_seconds=int(args.timeout),
            random_agent=args.random_agent,
        )
        if not result.ran:
            if result.error:
                out.skipped(f"sqlmap ({t.param} @ {t.url}): {result.error}")
            continue
        for f in to_findings(result, t):
            stats.record_finding(f)
            out.print_finding(f)
        if not result.findings:
            out.info(f"sqlmap: no injection confirmed for parameter {t.param!r} on {t.url}")

    if skipped_count > 0:
        out.info(
            f"sqlmap: {skipped_count} additional discovered parameter(s) were not tested "
            f"(raise --sqlmap-max-targets to cover more; current cap: {args.sqlmap_max_targets})."
        )


def _report_misconfig(client, recon_result, tls_info, base_url, stats, already_announced=False):
    from modules.misconfiguration import review as review_misconfig

    if not already_announced:
        out.info("Checking security headers...")
    stats.modules_run.append("misconfiguration")
    if recon_result.error:
        return
    for f in review_misconfig(recon_result, tls_info, base_url):
        stats.record_finding(f)
        out.print_finding(f)


_interrupted = False


def _sigint_handler(signum, frame):
    global _interrupted
    _interrupted = True


def _check_interrupted():
    if _interrupted:
        raise ScanInterrupted()


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"VULNX {VERSION}")
        return 0

    out.print_banner()
    validate_args(args)

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        stats = run_scan(args)
    except (ScopeViolation, UnsafeTargetError) as exc:
        out.error(str(exc))
        return 1

    out.print_summary(stats, args.url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
