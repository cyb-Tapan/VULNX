from modules.endpoint_discovery import crawl
from modules.parameter_discovery import discover_parameters
from modules.safety import SafeHTTPClient, SafetyConfig, TargetScope


def _scope_and_client(base_url):
    config = SafetyConfig(allow_local_lab=True, max_pages=10)
    scope = TargetScope(base_url, config)
    client = SafeHTTPClient(scope)
    return scope, client


def test_crawl_discovers_forms_and_js(fixture_server):
    scope, client = _scope_and_client(fixture_server)
    result = crawl(client, scope, fixture_server + "/", max_pages=10)
    assert len(result.pages_visited) >= 1
    assert any(f.action.endswith("/login") for f in result.forms)
    assert any("/api/widgets" in r or "/api/internal/users" in r for r in result.js_routes)


def test_crawl_does_not_leave_scope(fixture_server):
    scope, client = _scope_and_client(fixture_server)
    result = crawl(client, scope, fixture_server + "/", max_pages=10)
    for ep in result.endpoints:
        assert scope.is_in_scope(ep)


def test_crawl_respects_max_pages(fixture_server):
    scope, client = _scope_and_client(fixture_server)
    result = crawl(client, scope, fixture_server + "/", max_pages=1)
    assert len(result.pages_visited) <= 1


def test_parameter_discovery_from_forms(fixture_server):
    scope, client = _scope_and_client(fixture_server)
    result = crawl(client, scope, fixture_server + "/", max_pages=10)
    targets = discover_parameters(result)
    names = {t.param for t in targets}
    assert "username" in names
    assert "password" in names
