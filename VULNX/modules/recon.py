"""
recon.py

HTTP and TLS reconnaissance: status/redirect chain, headers, cookie
attributes, and certificate metadata. All requests go through the
SafeHTTPClient supplied by the caller.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from modules.safety import SafeHTTPClient

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


@dataclass
class ReconResult:
    status_code: Optional[int] = None
    redirect_chain: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    cookies: List[dict] = field(default_factory=list)
    tls_info: Optional[dict] = None
    error: Optional[str] = None


def run_http_recon(client: SafeHTTPClient, base_url: str) -> ReconResult:
    result = ReconResult()
    resp, err = client.get(base_url, allow_redirects=True)
    if err and resp is None:
        result.error = err
        return result

    result.status_code = resp.status_code
    result.redirect_chain = [r.url for r in resp.history] + [resp.url]
    result.headers = {k.lower(): v for k, v in resp.headers.items()}
    result.missing_security_headers = [
        h for h in SECURITY_HEADERS if h not in result.headers
    ]

    for cookie in resp.cookies:
        result.cookies.append(
            {
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly")),
                "samesite": cookie._rest.get("SameSite"),
            }
        )
    return result


def run_tls_recon(hostname: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    """Fetch certificate metadata only. Never used to probe non-target hosts."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName"),
                }
    except Exception as exc:  # noqa: BLE001 - recon must never crash the scan
        return {"error": f"{type(exc).__name__}: {exc}"}
