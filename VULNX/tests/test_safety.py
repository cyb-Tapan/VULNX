import pytest

from modules.safety import (
    ScopeViolation,
    SafeHTTPClient,
    SafetyConfig,
    TargetScope,
    UnsafeTargetError,
    normalize_url,
)


def test_normalize_url_rejects_bad_scheme():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_normalize_url_rejects_credentials():
    with pytest.raises(ValueError):
        normalize_url("http://user:pass@example.com")


def test_normalize_url_strips_default_port():
    assert normalize_url("http://example.com:80/path") == "http://example.com/path"


def test_normalize_url_lowercases_host():
    assert normalize_url("http://EXAMPLE.com/Path") == "http://example.com/Path"


def test_private_target_blocked_without_local_lab():
    config = SafetyConfig(allow_local_lab=False)
    with pytest.raises(UnsafeTargetError):
        TargetScope("http://127.0.0.1:9/", config)


def test_private_target_allowed_with_local_lab(fixture_server):
    config = SafetyConfig(allow_local_lab=True)
    scope = TargetScope(fixture_server, config)
    assert scope.host == "127.0.0.1"


def test_metadata_ip_always_blocked():
    config = SafetyConfig(allow_local_lab=True)
    with pytest.raises(UnsafeTargetError):
        TargetScope("http://169.254.169.254/", config)


def test_scope_enforcement_rejects_offsite_url(fixture_server):
    config = SafetyConfig(allow_local_lab=True)
    scope = TargetScope(fixture_server, config)
    assert scope.is_in_scope(fixture_server + "/anything") is True
    assert scope.is_in_scope("http://example.org/") is False
    with pytest.raises(ScopeViolation):
        scope.require_in_scope("http://example.org/")


def test_client_blocks_offsite_redirect(fixture_server):
    config = SafetyConfig(allow_local_lab=True)
    scope = TargetScope(fixture_server, config)
    client = SafeHTTPClient(scope)
    resp, err = client.get(fixture_server + "/redirect-offsite")
    assert err is not None
    assert "scope" in err.lower()


def test_client_follows_onsite_redirect(fixture_server):
    config = SafetyConfig(allow_local_lab=True)
    scope = TargetScope(fixture_server, config)
    client = SafeHTTPClient(scope)
    resp, err = client.get(fixture_server + "/redirect-onsite")
    assert err is None
    assert resp.status_code == 200


def test_rate_limiter_respects_interval():
    from modules.safety import RateLimiter
    import time

    limiter = RateLimiter(max_per_second=10)
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.15  # ~2 intervals of 0.1s
