# Security Policy

## Authorized Use Only

VULNX is a web security assessment tool. Running it against any system you
do not own and do not have explicit, documented authorization to test is
illegal in most jurisdictions and is explicitly against the intent of this
project.

The `--authorized` flag is an **acknowledgement**, not proof of permission.
VULNX has no way to verify you actually hold authorization for a target.
That responsibility is entirely yours.

## What VULNX Will Not Do

By design, VULNX does not implement:

- WAF, rate-limit, or authentication bypass techniques
- Denial-of-service or load/stress testing
- Data exfiltration, database dumping, or destructive queries
- Automatic export of findings to disk (no report files, no history, no DB)
- Requests to cloud metadata services or arbitrary internal/private
  addresses outside explicit local-lab mode

If you believe a contribution would cross these lines, please do not submit
it — see CONTRIBUTING expectations in the README.

## Reporting a Vulnerability in VULNX Itself

If you find a security issue in VULNX's own code (e.g., a scope-enforcement
bypass, a way to make the safe HTTP client contact a disallowed address, or
a way to make it write files it shouldn't), please report it privately
rather than opening a public issue:

1. Open a GitHub Security Advisory on this repository ("Report a
   vulnerability" under the Security tab), or
2. Contact the maintainer directly through the contact method listed on
   their GitHub profile.

Please include:

- A description of the issue and its impact
- Steps to reproduce (ideally against a local fixture, not a live site)
- Any suggested fix, if you have one

We aim to acknowledge reports within a reasonable timeframe and will credit
reporters in the CHANGELOG unless you ask us not to.

## Supported Versions

Only the latest released version of VULNX receives security fixes.
