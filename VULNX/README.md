# VULNX

A modular, evidence-driven web security assessment CLI for Kali Linux,
inspired by SQLmap's usability and Nmap's reconnaissance style.

**Author:** cyb-Tapan · **Version:** 1.0.0 · **Platform:** Kali Linux (Python 3) · **Interface:** CLI only

> ⚠️ **Authorized use only.** Run VULNX only against systems you own or have
> explicit, documented permission to test. `--authorized` is an
> acknowledgement of that fact, not proof of it — it does not grant you
> permission and does not shield you from the consequences of testing
> something you aren't authorized to test. See [SECURITY.md](SECURITY.md).

---

## What VULNX is (and isn't)

VULNX performs reconnaissance and conservative, non-destructive vulnerability
*indicator* detection against a single authorized target origin, and prints
findings live to your terminal as it works.

VULNX deliberately does **not**:

- store scan history, write report files (JSON/HTML/TXT/PDF/CSV), or expose
  `--output`/`--format` options — results live only in memory for the
  process's lifetime and are printed, never saved
- run a GUI, web dashboard, or database
- attempt WAF evasion, authentication bypass, rate-limit bypass, or DoS
- dump databases, run destructive queries, read arbitrary OS files, or
  upload real payloads anywhere

If you want to keep a copy of the output, redirect your terminal (`| tee
scan.log`) yourself — VULNX will never do it silently.

## Installation

VULNX is pure Python and runs the same way on Kali Linux and macOS. Pick
your platform below.

### Kali Linux

```bash
sudo apt update
sudo apt install python3 python3-venv nmap git

cd VULNX
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python3 vulnx.py --help
```

### macOS

macOS ships `python3` and `git` (via Xcode Command Line Tools, prompted
automatically the first time you run `git` or `python3` if missing). `venv`
is part of the standard library, so there's no separate `python3-venv`
package to install. Use [Homebrew](https://brew.sh) for `nmap`:

```bash
xcode-select --install   # only if prompted; installs git/python3 if missing
brew install nmap        # optional — see "Nmap dependency" below

cd VULNX
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python3 vulnx.py --help
```

### Nmap dependency (both platforms)

Nmap is an **optional system dependency**, not a pip package:

- Kali/Debian: `sudo apt update && sudo apt install nmap`
- macOS: `brew install nmap`
- Anything else: https://nmap.org/download.html

If `nmap` isn't on `PATH`, VULNX skips port scanning, logs a `[SKIPPED]`
line that names the correct install command for your OS, and continues the
rest of the scan — it never pretends a port scan happened.

## CLI arguments

| Argument | Purpose |
|---|---|
| `-u`, `--url` | Target URL (required) |
| `--scan` | Scan profile: `recon`, `headers`, `endpoints`, `passive`, `sqli`, `xss`, `full` |
| `--batch` | Disable interactive prompts |
| `--random-agent` | Choose a User-Agent from a small maintained list |
| `--timeout` | Request read timeout in seconds (0–120) |
| `--max-pages` | Maximum pages crawled (1–500) |
| `--rate-limit` | Maximum requests per second (0–50) |
| `--concurrency` | Bounded concurrency (currently sequential execution is enforced) |
| `--profile` | `safe` (default; blocks private/loopback targets) or `lab` (permits an explicit local-lab target) |
| `--authorized` | Required acknowledgement that you are authorized to test the target |
| `--sqlmap` | Opt-in: also run detection-only [sqlmap](https://sqlmap.org) checks on `sqli`/`full` (requires `sqlmap` on PATH; never dumps data) |
| `--sqlmap-level` | sqlmap payload level, 1–3 (enforced; sqlmap's own range is 1–5) |
| `--sqlmap-max-targets` | Max discovered parameters to run sqlmap against, default 5 (1–50) |
| `--skip-ping` | Skip the initial ICMP ping reachability check |
| `--ping-count` | Number of ICMP echo requests sent, default 3 (1–10) |
| `--skip-portscan` | Skip the Nmap port scan step |
| `--verbose` | Detailed diagnostics |
| `--version` | Print version and exit |
| `--help` | Print usage and exit |

`--batch` and `--random-agent` never bypass safety controls — they only
affect prompting and the outbound User-Agent string.

### Scan profiles

Every profile below runs the same two steps first, in this order, before
anything profile-specific starts: **(1) ICMP ping reachability check**,
then **(2) Nmap common-port scan**. Neither step can fail or abort the
scan — an unreachable ping or missing/failed nmap is reported and the
scan proceeds regardless. Skip either with `--skip-ping` / `--skip-portscan`.

- `recon` — ping, port scan, then HTTP/TLS recon + security-header review
- `headers` — ping, port scan, then header/cookie/TLS review only
- `endpoints` — ping, port scan, recon, then same-origin crawling and endpoint listing
- `passive` — ping, port scan, recon, endpoints, then CSRF review + file-upload review + misconfiguration, no active payload sending
- `sqli` — everything in `passive`, plus non-destructive SQL injection indicator checks
  (always), plus optional [sqlmap](https://sqlmap.org)-backed confirmation if
  `--sqlmap` is passed and `sqlmap` is installed
- `xss` — everything in `passive`, plus reflection-based XSS checks
- `full` — everything above combined

So for any command, the order is always:
**ping → port scan → recon → the task you asked for (headers/endpoints/sqli/xss/etc).**

### Built-in SQLi probe vs. `--sqlmap`

Two independent layers, both non-destructive:

1. **Always-on, built-in** (`modules/sqli.py`): sends one baseline request
   and one single-quote probe per parameter, looks for a database error
   signature or a status-code anomaly. Fast, zero external dependencies.
   Reports findings as `Potential`/`Inconclusive` — it never claims to have
   confirmed exploitability.
2. **Opt-in** (`--sqlmap`, `modules/sqlmap_scanner.py`): shells out to a
   separately-installed `sqlmap` binary for a proper detection run —
   boolean-based, error-based, UNION, and time-based techniques — without
   ever enabling data extraction (`--dump`), command execution
   (`--os-shell`), file access, or stacked queries. Risk is hard-capped at
   1 in code regardless of any value passed. Findings sqlmap actually
   confirms are reported as `Verified`/`Critical`. This is heavier and
   noisier than the built-in probe, which is why it's opt-in rather than
   automatic, and it's capped to `--sqlmap-max-targets` parameters per scan
   so it can't silently turn a quick scan into a very long one.

Install sqlmap separately — it's not a Python package pulled in by
`requirements.txt`:

```bash
# macOS
brew install sqlmap
# Debian / Kali
sudo apt update && sudo apt install sqlmap
# Or, on any platform, from the official source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

Then:

```bash
python3 vulnx.py -u https://authorized.example \
  --authorized --scan sqli --batch --sqlmap
```

If `sqlmap` isn't found on PATH, VULNX reports it as skipped (with the
install hint above) and the rest of the scan continues normally — it never
fails the whole run.

Note: sqlmap makes its own HTTP connections rather than going through
VULNX's `SafeHTTPClient`, so VULNX's own rate limiter and per-redirect-hop
re-resolution don't apply to sqlmap's traffic. The target's scope (host,
port, scheme) is still validated before `--sqlmap` ever runs, using the
same `TargetScope` check as everything else.

### Usage examples

```bash
python3 vulnx.py --help
python3 vulnx.py --version

python3 vulnx.py -u https://authorized.example \
  --authorized --scan recon

python3 vulnx.py -u https://authorized.example \
  --authorized --scan headers --batch

python3 vulnx.py -u https://authorized.example \
  --authorized --scan endpoints --max-pages 30

python3 vulnx.py -u https://authorized.example \
  --authorized --scan full --batch --random-agent

python3 vulnx.py -u http://127.0.0.1:8080 \
  --authorized --profile lab --scan sqli

python3 vulnx.py -u https://authorized.example \
  --authorized --scan sqli --batch --sqlmap --sqlmap-max-targets 3
```

These are illustrative usage examples only — they are not claims that any of
these domains have been scanned.

## Illustrative terminal output

```
[VULNX] Initializing...
[INFO] Validating target and authorization...
[INFO] Starting reconnaissance...
[OPEN] 443/tcp HTTPS
[INFO] Discovering endpoints...
[ENDPOINT] /api/
[ENDPOINT] /search?q=
[INFO] Checking security headers...

[FOUND] Security Configuration Review
URL: <actual URL>
Severity: Informational
Confidence: High
Status: Potential
Evidence: <sanitized evidence>
Remediation: <relevant recommendation>

[SUMMARY] Scan finished
Ports discovered: <actual count>
Pages inspected: <actual count>
Endpoints discovered: <actual count>
Findings: <actual count>
Verified: <actual count>
Potential: <actual count>
Inconclusive: <actual count>
Skipped modules: <actual count>
```

All values above are illustrative. A real run prints the actual counts from
that run's own execution — nothing is fabricated or templated in.

## Detector limitations (read this)

Every detector trades completeness for safety. None of this is a substitute
for a human penetration tester:

- **SQL Injection** — single-quote differential + database error-signature
  matching only. No boolean-based, time-based, or UNION-based testing. Never
  marked `Verified`; always `Potential`/`Inconclusive` pending manual review.
- **XSS** — reflection and HTML-encoding-context analysis only. No headless
  browser, so JavaScript execution is never actually confirmed.
- **SSRF** — naming/value heuristics only (e.g. a parameter called `url` or
  `webhook`). VULNX never dereferences a third-party URL or probes cloud
  metadata/internal services to "confirm" SSRF.
- **CSRF** — flags state-changing forms with no visible anti-CSRF token
  field. Cannot see server-side Origin/Referer checks, so this is a review
  finding, not a confirmed exploit.
- **Misconfiguration** — security headers, cookie attributes, server-version
  disclosure, TLS expiry. Context-dependent severity; a missing header alone
  is never reported as "exploited."
- **Directory traversal** — naming heuristic always runs. An *active* probe
  exists but only fires in `--profile lab` against a canary file the lab
  operator places themselves; it never targets real OS files.
- **File upload** — passive review of discovered `<input type="file">`
  forms and their `accept` attribute only. No file is ever uploaded.

Endpoint discovery does not brute-force directories and cannot see
authenticated, undocumented, or dynamically generated routes it was never
given a path to.

## Troubleshooting

**`sudo: apt: command not found`** — `apt` is Debian/Kali-only. On macOS,
use the macOS install steps above (Homebrew, no `apt`).

**`ModuleNotFoundError: No module named 'modules.models'`** (or any other
`modules.*` submodule) — almost always one of:
1. The project was extracted/merged into an existing folder and some files
   from an older copy got left in place. Fix: delete the project folder
   entirely and re-extract the zip fresh into an empty directory.
2. A different, unrelated package also named `modules` is installed and is
   shadowing the local `modules/` folder. `vulnx.py` detects this
   automatically on startup and will tell you exactly which directory it
   loaded `modules` from and how to fix it — read the `[ERROR]` message it
   prints rather than the raw traceback.

**`ModuleNotFoundError: No module named 'bs4'`** (or `rich`, `colorama`,
etc.) — a dependency didn't get installed. Run `pip install -r
requirements.txt` again inside your activated virtual environment, and
confirm with `pip list` that `beautifulsoup4`, `rich`, and `colorama` are
all present. If `requirements.txt` in your copy looks different from the
one in this repo (wrong line count/contents), your copy is stale — re-
extract the project fresh.

**Finder on macOS only shows a `modules` folder after unzipping** — this is
almost always Finder merging into a pre-existing folder of the same name
from an earlier, incomplete extraction. Delete the old folder first, then
extract via Terminal (`unzip VULNX.zip`) so you can see every file land.

**Target rejected with "resolves to a private/loopback address"** — this is
the safety engine working as intended: by default VULNX refuses to touch
private/loopback addresses. Pass `--profile lab` only when you are
intentionally testing a local lab target you control.

## Testing

```bash
pip install -r requirements.txt
pytest -q
```

All tests run against either pure unit logic or a local, in-process HTTP
fixture server (`tests/conftest.py`) bound to `127.0.0.1`. No test ever
contacts a public website.

## Responsible disclosure

If you discover a real vulnerability in a system using VULNX, follow that
system's own responsible-disclosure process or coordinate directly with its
owner. VULNX does not manage disclosure for you. For vulnerabilities in
VULNX's own code, see [SECURITY.md](SECURITY.md).

## Contributing

Issues and PRs are welcome. Please keep contributions inside the guardrails
this project is built around:

- No new feature that writes scan results to disk
- No WAF/auth/rate-limit bypass, no DoS behavior
- New detectors need: documented purpose, real detection logic, error
  handling, positive *and* negative tests against the local fixture, and a
  clearly stated limitations section
- If a detector can't reliably detect something yet, mark it
  `Experimental`/`Not implemented` rather than faking a result

## License

MIT — see [LICENSE](LICENSE).
