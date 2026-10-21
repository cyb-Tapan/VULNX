# Changelog

All notable changes to this project are documented here.
This project does not yet follow a formal versioning cadence beyond simple
major.minor.patch tags.

## [Unreleased] — Ping now shows the resolved IP; sqlmap usage clarified

### Fixed
- `modules/ping_scanner.py` now parses the resolved IP address out of
  `ping`'s own output (handles macOS/BSD, Linux/iputils, bare-IP targets,
  and both IPv6 spacing variants) and `vulnx.py` prints it on the ping
  line, e.g. `Host example.com [93.184.216.34] is reachable (ICMP)...`.
  Previously only reachability/RTT/loss were shown, not the IP itself.
- When ping can't even resolve the hostname (distinct from "resolved but
  no reply"), the warning now surfaces `ping`'s own stderr instead of the
  generic firewall-filtering message, since that's a different failure
  mode worth distinguishing.
- `tests/test_ping_scanner.py`: added coverage for IP parsing across all
  of the above formats.

### Note
- `--sqlmap` is opt-in and requires both the flag AND `sqlmap` on PATH;
  seeing `sqlmap` under "Modules skipped" with nothing under "Modules
  run" means one of those two conditions isn't met — check
  `which sqlmap` and confirm `--sqlmap` is actually in the command.

## [Unreleased] — Ping + port scan now run first, for every profile

### Changed
- `vulnx.py` now runs an ICMP reachability check (`modules/ping_scanner.py`,
  new) followed by the Nmap port scan **unconditionally as step 1, before
  HTTP recon, for every scan profile** — including `headers` and `passive`,
  which previously skipped the port scan entirely. Order for any command is
  now always: ping → port scan → HTTP/TLS recon → the profile's own task
  (header review, endpoint discovery, sqli, xss, etc).
- Neither ping nor the port scan can abort a scan: an unreachable ping
  (common behind firewalls/CDNs that drop ICMP) or a missing/failed nmap
  are reported via the existing modules_run/skipped/failed bookkeeping and
  the scan continues into the profile-specific work regardless.
- New CLI flags: `--skip-ping`, `--ping-count` (1–10, default 3),
  `--skip-portscan`.

### Added
- `modules/ping_scanner.py`: safe wrapper around the system `ping` binary,
  same conservative pattern as `nmap_scanner.py` (`shell=False`, fixed
  argument list, hard subprocess timeout, count clamped to 1–10
  regardless of the value requested). Parses both BSD/macOS and
  Linux/iputils `ping` output formats for packet loss and average RTT.
- `tests/test_ping_scanner.py`: covers output parsing for both ping output
  formats, the unreachable case, missing-binary handling, count clamping,
  and timeout handling. All subprocess calls are mocked.

## [Unreleased] — Optional sqlmap integration

### Added
- `modules/sqlmap_scanner.py`: optional, opt-in wrapper around an
  externally-installed `sqlmap` binary for deeper SQL-injection
  *detection*. Enabled with the new `--sqlmap` flag on the `sqli`/`full`
  profiles. Follows the same safe-subprocess pattern as the existing nmap
  integration (`shell=False`, fixed argument list) with additional
  hardening specific to sqlmap:
  - `--risk` hard-capped at 1 in code (not just by default).
  - `--technique` restricted to boolean/error-based/UNION/time-based;
    stacked queries are excluded.
  - Never passes `--dump`, `--os-shell`, `--sql-shell`, `--file-read`,
    `--crawl`, or any other data-extraction / code-execution / scope
    -expanding flag — a defense-in-depth assertion checks the built
    command for these before every run.
  - Only tests parameters VULNX itself already discovered, one at a time,
    capped by the new `--sqlmap-max-targets` (default 5), with a hard
    per-parameter subprocess timeout so one slow target can't hang the
    scan.
  - Confirmed findings are reported as `VERIFIED`/`CRITICAL` (sqlmap
    actually elicited the error/behavior), distinct from the existing
    lightweight probe in `modules/sqli.py`, which only ever reports
    `POTENTIAL`/`INCONCLUSIVE`.
  - Gracefully reports and skips (does not fail the scan) when `sqlmap`
    isn't installed, with a platform-aware install hint.
- New CLI flags: `--sqlmap`, `--sqlmap-level` (1-3, enforced), 
  `--sqlmap-max-targets`.
- `tests/test_sqlmap_scanner.py`: covers output parsing (including
  multiple injection types under one parameter), DBMS extraction, the
  Finding conversion, and — critically — that destructive flags are never
  present in the built command and that risk/level are clamped even when
  a caller requests more. All subprocess calls are mocked; no real
  `sqlmap` binary or network access is required to run the suite.

## [Unreleased] — Cross-platform fixes (Kali Linux + macOS)

### Fixed
- `vulnx.py` now pins its own directory to the front of `sys.path` at
  startup and verifies the local `modules` package actually resolves to
  the local `modules/` folder before importing from it, instead of letting
  Python silently pick up a same-named package from elsewhere on the path
  (e.g. an unrelated pip-installed `modules` package, or stale `PYTHONPATH`
  state). If the project directory is incomplete (a partial copy/extract),
  it now fails with a clear, specific `[ERROR]` instead of a raw
  `ModuleNotFoundError` traceback.
- `modules/nmap_scanner.py`'s "nmap not found" message is now
  platform-aware: it suggests `brew install nmap` on macOS and
  `sudo apt install nmap` on Debian/Kali, rather than a generic message.
- README installation instructions now have separate, correct steps for
  Kali Linux (`apt`, `python3-venv`) and macOS (Homebrew, no
  `python3-venv` package needed since `venv` ships with `python3` there),
  plus a Troubleshooting section covering the import/dependency issues
  seen during real-world setup on both platforms.

## [1.0.0] — Initial build

### Added
- CLI entry point (`vulnx.py`) with `-u/--url`, `--scan`, `--batch`,
  `--random-agent`, `--timeout`, `--max-pages`, `--rate-limit`,
  `--concurrency`, `--profile`, `--authorized`, `--verbose`, `--version`.
- Scan profiles: `recon`, `headers`, `endpoints`, `passive`, `sqli`, `xss`,
  `full`.
- Centralized safety engine (`modules/safety.py`): URL normalization,
  credential-in-URL rejection, private/loopback/link-local/cloud-metadata
  blocking (with narrow, explicit local-lab exception), DNS re-resolution
  on every redirect hop, scope enforcement, response-size cap, bounded
  redirects, request rate limiting.
- HTTP/TLS reconnaissance (`modules/recon.py`).
- Safe Nmap integration via `subprocess` with `shell=False` and a fixed
  argument list (`modules/nmap_scanner.py`).
- Passive technology detection (`modules/technology_detection.py`).
- Same-origin crawling, form discovery, and JS route extraction
  (`modules/endpoint_discovery.py`).
- Parameter inventory (`modules/parameter_discovery.py`).
- Detectors: SQL injection (error-based, non-destructive), XSS
  (reflection/context), SSRF (naming heuristic, no live probing), CSRF
  (token-field review), security misconfiguration (headers/cookies/TLS
  expiry/server disclosure), directory traversal (naming heuristic + local
  -lab-only canary probe), file upload (passive form review).
- Structured in-memory finding model with evidence sanitization
  (`modules/models.py`).
- Live terminal output via Rich, including an honest interrupted-scan
  summary on Ctrl+C (`modules/terminal_output.py`).
- Automated test suite (pytest) covering CLI parsing, safety engine, scope
  enforcement, endpoint/parameter discovery, each detector's positive and
  negative cases, and terminal-output sanitization — run only against a
  local in-process HTTP fixture, never a public site.
- GitHub-ready documentation: README, LICENSE (MIT), SECURITY.md,
  config.example.json, .gitignore.

### Known limitations
- SQLi detection is error-signature-based only; no boolean/time-based/UNION
  techniques are implemented.
- XSS detection confirms reflection and encoding context only; it does not
  drive a browser and cannot confirm actual script execution.
- SSRF and directory-traversal "potential" findings from naming heuristics
  are not independently verified against the target.
- File upload review is passive only; no active upload-handling testing is
  implemented.
- `--concurrency` is accepted and validated but scans currently execute
  sequentially; true concurrent request dispatch is not yet implemented.
