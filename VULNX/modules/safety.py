"""
safety.py

Centralized safety engine. Every network request VULNX makes against a
target must go through SafeHTTPClient so that scope, redirect validation,
DNS re-resolution, and private-network blocking cannot be bypassed by an
individual module.

This module does not implement, and must never be extended to implement,
WAF evasion, authentication bypass, rate-limit bypass, or denial-of-service
behavior.
"""

from __future__ import annotations

import ipaddress
import socket
import time
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import requests


class ScopeViolation(Exception):
    """Raised when a request would leave the authorized target scope."""


class UnsafeTargetError(Exception):
    """Raised when a target resolves to a disallowed network destination."""


@dataclass
class SafetyConfig:
    allow_local_lab: bool = False
    max_response_bytes: int = 5 * 1024 * 1024  # 5 MB
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    max_redirects: int = 5
    max_requests_per_second: float = 5.0
    max_concurrency: int = 5
    max_pages: int = 50
    user_agent: str = "VULNX/1.0.0 (+authorized-security-assessment)"


def normalize_url(raw_url: str) -> str:
    """
    Normalize a URL: enforce http/https, reject embedded credentials,
    lowercase the host, strip default ports and fragments.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Empty URL.")
    raw_url = raw_url.strip()
    parts = urlsplit(raw_url)

    if parts.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parts.scheme!r}. Only http/https are allowed.")

    if not parts.hostname:
        raise ValueError("URL has no hostname.")

    if parts.username or parts.password:
        raise ValueError("URLs with embedded credentials are not allowed.")

    host = parts.hostname.lower()
    port = parts.port
    default_port = 443 if parts.scheme == "https" else 80
    netloc = host if (port is None or port == default_port) else f"{host}:{port}"

    path = parts.path or "/"
    normalized = urlunsplit((parts.scheme, netloc, path, parts.query, ""))
    return normalized


def _is_disallowed_ip(ip_str: str) -> bool:
    """Return True if an IP must never be contacted, even in local-lab mode
    for anything other than the exact approved loopback/private target."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> treat as unsafe

    # Cloud metadata endpoints (IMDS) — never allowed, in any mode.
    if ip_str == "169.254.169.254" or ip_str == "fd00:ec2::254":
        return True

    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    return False


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local


def resolve_all(hostname: str) -> List[str]:
    """Resolve a hostname to all its A/AAAA addresses. Raises UnsafeTargetError
    on resolution failure so callers fail closed."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"DNS resolution failed for {hostname!r}: {exc}")
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise UnsafeTargetError(f"No addresses resolved for {hostname!r}.")
    return addrs


class RateLimiter:
    """Simple thread-safe token-bucket-ish limiter for outbound requests."""

    def __init__(self, max_per_second: float):
        self.min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class TargetScope:
    """
    Defines and enforces the approved scope: a single origin (scheme + host
    + port) chosen by the operator at scan start. Anything outside that
    origin — including redirect destinations — is rejected.
    """

    def __init__(self, base_url: str, config: SafetyConfig):
        self.config = config
        self.base_url = normalize_url(base_url)
        parts = urlsplit(self.base_url)
        self.scheme = parts.scheme
        self.host = parts.hostname.lower()
        self.port = parts.port or (443 if self.scheme == "https" else 80)

        self._validate_host_network()

    def _validate_host_network(self) -> None:
        addrs = resolve_all(self.host)
        for addr in addrs:
            if _is_disallowed_ip(addr):
                raise UnsafeTargetError(
                    f"Target {self.host!r} resolves to a disallowed address ({addr})."
                )
            if _is_private_or_loopback(addr) and not self.config.allow_local_lab:
                raise UnsafeTargetError(
                    f"Target {self.host!r} resolves to a private/loopback address "
                    f"({addr}). Re-run with local-lab mode enabled if this is an "
                    f"intentional local test target."
                )

    def is_in_scope(self, url: str) -> bool:
        try:
            normalized = normalize_url(url)
        except ValueError:
            return False
        parts = urlsplit(normalized)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return (
            parts.scheme == self.scheme
            and parts.hostname
            and parts.hostname.lower() == self.host
            and port == self.port
        )

    def require_in_scope(self, url: str) -> str:
        if not self.is_in_scope(url):
            raise ScopeViolation(f"URL is outside the authorized scope: {url}")
        return normalize_url(url)


class SafeHTTPClient:
    """
    The only sanctioned way for modules to talk to the target. Enforces
    scope, revalidates DNS on every redirect hop, blocks private/metadata
    destinations outside local-lab mode, applies timeouts, response-size
    limits, a bounded redirect count, and a rate limiter.
    """

    def __init__(self, scope: TargetScope, stats=None):
        self.scope = scope
        self.config = scope.config
        self._rate_limiter = RateLimiter(self.config.max_requests_per_second)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.config.user_agent})
        self.stats = stats

    def _validate_hop(self, url: str) -> None:
        self.scope.require_in_scope(url)
        host = urlsplit(url).hostname
        addrs = resolve_all(host)
        for addr in addrs:
            if _is_disallowed_ip(addr):
                raise UnsafeTargetError(f"Redirect to disallowed address blocked ({addr}).")
            if _is_private_or_loopback(addr) and not self.config.allow_local_lab:
                raise UnsafeTargetError(f"Redirect to private/loopback address blocked ({addr}).")

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        allow_redirects: bool = True,
        extra_headers: Optional[dict] = None,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Returns (response, error). Never raises for ordinary network/HTTP
        failures — callers check the error string. Raises ScopeViolation /
        UnsafeTargetError only for safety-policy violations, which callers
        should treat as fatal for that request path.
        """
        current_url = self.scope.require_in_scope(url)
        hops = 0
        headers = dict(extra_headers or {})

        while True:
            self._validate_hop(current_url)
            self._rate_limiter.wait()
            try:
                resp = self._session.request(
                    method,
                    current_url,
                    params=params if hops == 0 else None,
                    data=data if hops == 0 else None,
                    headers=headers,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    allow_redirects=False,
                    stream=True,
                )
            except requests.exceptions.RequestException as exc:
                return None, f"{type(exc).__name__}: {exc}"

            if self.stats is not None:
                self.stats.requests_sent += 1

            # Enforce response size limit while reading the body.
            try:
                content = b""
                for chunk in resp.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > self.config.max_response_bytes:
                        resp.close()
                        return None, "Response exceeded maximum allowed size; aborted."
                resp._content = content  # populate .text/.content without re-reading
            except requests.exceptions.RequestException as exc:
                return None, f"{type(exc).__name__}: {exc}"

            if (
                allow_redirects
                and resp.is_redirect
                and "Location" in resp.headers
                and hops < self.config.max_redirects
            ):
                next_url = requests.compat.urljoin(current_url, resp.headers["Location"])
                try:
                    next_url = normalize_url(next_url)
                except ValueError:
                    return resp, None
                if not self.scope.is_in_scope(next_url):
                    return resp, f"Redirect left authorized scope (blocked): {next_url}"
                current_url = next_url
                hops += 1
                continue

            return resp, None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)
