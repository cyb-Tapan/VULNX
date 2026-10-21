from modules.csrf import review_forms
from modules.directory_traversal import active_canary_probe, review_target as dt_review
from modules.endpoint_discovery import DiscoveredForm
from modules.misconfiguration import review as review_misconfig
from modules.models import VerificationStatus
from modules.parameter_discovery import ParamTarget
from modules.recon import run_http_recon
from modules.safety import SafeHTTPClient, SafetyConfig, TargetScope
from modules.ssrf import review_target as ssrf_review
from modules.sqli import scan_target as sqli_scan
from modules.xss import scan_target as xss_scan


def _client(base_url, local_lab=True):
    config = SafetyConfig(allow_local_lab=local_lab, max_pages=10)
    scope = TargetScope(base_url, config)
    return scope, SafeHTTPClient(scope)


# --- SQLi ---------------------------------------------------------------

def test_sqli_positive_on_vulnerable_endpoint(fixture_server):
    scope, client = _client(fixture_server)
    target = ParamTarget(url=fixture_server + "/search", method="GET", param="q")
    findings = sqli_scan(client, target)
    assert len(findings) == 1
    assert findings[0].status == VerificationStatus.POTENTIAL
    assert "error" in findings[0].evidence.lower() or "syntax" in findings[0].evidence.lower()


def test_sqli_negative_on_safe_endpoint(fixture_server):
    scope, client = _client(fixture_server)
    target = ParamTarget(url=fixture_server + "/echo", method="GET", param="x")
    findings = sqli_scan(client, target)
    assert findings == []


# --- XSS ------------------------------------------------------------------

def test_xss_reflected_unescaped(fixture_server):
    scope, client = _client(fixture_server)
    target = ParamTarget(url=fixture_server + "/echo", method="GET", param="x")
    findings = xss_scan(client, target)
    assert len(findings) == 1
    assert findings[0].status == VerificationStatus.POTENTIAL
    assert "unescaped" in findings[0].category.lower()


def test_xss_no_finding_when_not_reflected(fixture_server):
    scope, client = _client(fixture_server)
    target = ParamTarget(url=fixture_server + "/noreflect", method="GET", param="q")
    findings = xss_scan(client, target)
    assert findings == []


# --- CSRF -----------------------------------------------------------------

def test_csrf_flags_form_without_token(fixture_server):
    scope, client = _client(fixture_server)
    recon_result = run_http_recon(client, fixture_server + "/")
    form = DiscoveredForm(action=fixture_server + "/login", method="POST", inputs=["username", "password"])
    findings = review_forms([form], recon_result)
    assert len(findings) == 1
    assert findings[0].status == VerificationStatus.POTENTIAL


def test_csrf_skips_get_forms(fixture_server):
    scope, client = _client(fixture_server)
    recon_result = run_http_recon(client, fixture_server + "/")
    form = DiscoveredForm(action=fixture_server + "/search", method="GET", inputs=["q"])
    findings = review_forms([form], recon_result)
    assert findings == []


def test_csrf_skips_form_with_token_field(fixture_server):
    scope, client = _client(fixture_server)
    recon_result = run_http_recon(client, fixture_server + "/")
    form = DiscoveredForm(action=fixture_server + "/login", method="POST", inputs=["username", "csrf_token"])
    findings = review_forms([form], recon_result)
    assert findings == []


# --- Misconfiguration -------------------------------------------------------

def test_misconfig_flags_missing_headers(fixture_server):
    scope, client = _client(fixture_server)
    recon_result = run_http_recon(client, fixture_server + "/")
    findings = review_misconfig(recon_result, None, fixture_server + "/")
    assert any("Missing Security Headers" in f.category for f in findings)


def test_misconfig_clean_on_secure_endpoint(fixture_server):
    scope, client = _client(fixture_server)
    recon_result = run_http_recon(client, fixture_server + "/secure")
    findings = review_misconfig(recon_result, None, fixture_server + "/secure")
    assert not any("Missing Security Headers" in f.category for f in findings)
    assert not any("Cookie Attributes" in f.category for f in findings)


# --- SSRF naming heuristic ---------------------------------------------------

def test_ssrf_flags_url_like_param_name():
    target = ParamTarget(url="http://x/fetch", method="GET", param="url")
    findings = ssrf_review(target)
    assert len(findings) == 1
    assert findings[0].status == VerificationStatus.POTENTIAL


def test_ssrf_ignores_unrelated_param_name():
    target = ParamTarget(url="http://x/fetch", method="GET", param="page_number")
    findings = ssrf_review(target)
    assert findings == []


# --- Directory traversal ---------------------------------------------------

def test_directory_traversal_heuristic():
    target = ParamTarget(url="http://x/view", method="GET", param="file")
    findings = dt_review(target)
    assert len(findings) == 1


def test_directory_traversal_active_probe_requires_local_lab(fixture_server):
    # A lab-enabled client is needed just to construct a scope/client against
    # a loopback fixture; the probe function itself must still refuse to run
    # when local_lab_enabled=False is passed explicitly.
    scope, client = _client(fixture_server, local_lab=True)
    target = ParamTarget(url=fixture_server + "/download", method="GET", param="file")
    result = active_canary_probe(client, target, local_lab_enabled=False)
    assert result is None


def test_directory_traversal_active_probe_detects_canary(fixture_server):
    scope, client = _client(fixture_server, local_lab=True)
    target = ParamTarget(url=fixture_server + "/download", method="GET", param="file")
    result = active_canary_probe(client, target, local_lab_enabled=True)
    assert result is not None
    assert result.status == VerificationStatus.VERIFIED
