"""Tests for the optional local web UI (network-free)."""

import csv
import time

import pytest

pytest.importorskip("flask")  # web extra is optional

from domain_security_analyzer.analyzer import CSV_COLUMNS, write_results_csv
from domain_security_analyzer.web import app as web_app
from domain_security_analyzer.web import runs as runs_mod
from domain_security_analyzer.web.app import create_app, parse_domains


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    """Point run storage at a temp directory for every test."""
    monkeypatch.setenv("DSA_DATA_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


# --- parse_domains -----------------------------------------------------------

def test_parse_domains_strips_blanks_comments_and_dedupes():
    text = "example.com\n\n# a comment\nEXAMPLE.com\nexample.org\n"
    assert parse_domains(text) == ["example.com", "example.org"]


# --- diff logic --------------------------------------------------------------

def _row(domain, **overrides):
    row = {col: "" for col in CSV_COLUMNS}
    row["Domain"] = domain
    row.update(overrides)
    return row


def test_diff_detects_regression_improvement_added_removed():
    old = {
        "a.com": _row("a.com", **{"SPF Exists": "True", "SRI Coverage %": "80"}),
        "gone.com": _row("gone.com"),
    }
    new = {
        "a.com": _row("a.com", **{"SPF Exists": "False", "SRI Coverage %": "90"}),
        "fresh.com": _row("fresh.com"),
    }
    diff = runs_mod.diff_runs(old, new)

    assert diff["added"] == ["fresh.com"]
    assert diff["removed"] == ["gone.com"]
    assert diff["regression_count"] == 1   # SPF dropped
    assert diff["improvement_count"] == 1  # SRI coverage rose

    changed = {c["domain"]: c for c in diff["changed"]}["a.com"]
    assert any(r["field"] == "SPF Exists" for r in changed["regressions"])
    assert any(i["field"] == "SRI Coverage %" for i in changed["improvements"])


def test_timestamp_change_is_ignored():
    old = {"a.com": _row("a.com", Timestamp="2026-01-01")}
    new = {"a.com": _row("a.com", Timestamp="2026-06-25")}
    diff = runs_mod.diff_runs(old, new)
    assert diff["changed"] == []


# --- HTTP routes -------------------------------------------------------------

def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Analyze domains" in resp.data


def test_run_without_domains_returns_400(client):
    resp = client.post("/run", data={"domains": "   \n# only a comment"})
    assert resp.status_code == 400
    assert b"No domains found" in resp.data


def _fake_analyze(monkeypatch, rows):
    """Replace the engine with a synchronous CSV writer for the web worker."""
    def fake(input_file, output_file, max_workers=10, progress_callback=None, **kw):
        write_results_csv(rows, output_file)
        if progress_callback:
            progress_callback(len(rows), len(rows))
    monkeypatch.setattr(web_app, "analyze_domains_from_file", fake)


def _result(domain, **overrides):
    base = {
        "domain": domain,
        "timestamp": "2026-06-25T00:00:00",
        "soa": {"exists": True, "parent_domain": domain, "record": None, "primary_ns": None, "admin_email": None},
        "spf": {"exists": True, "record": "v=spf1 -all"},
        "dkim": {"exists": False, "records": []},
        "dmarc": {"exists": True, "record": "v=DMARC1; p=none"},
        "subdomains": {"subdomains": [], "cname_records": {}, "has_wildcard_dns": False, "hosting_provider": None},
        "http_redirect": {"http_accessible": True, "redirects_to_https": True, "final_url": "https://" + domain, "error": "", "redirect_chain": []},
        "sri": {"sri_enabled": True, "total_external_resources": 1, "resources_with_sri": 1, "sri_coverage_percentage": 100, "missing_sri_count": 0, "sri_algorithms_used": ["sha384"], "error": ""},
    }
    base.update(overrides)
    return base


def _wait_for_redirect(client, location, tries=50):
    for _ in range(tries):
        resp = client.get(location)
        if resp.status_code == 302:
            return resp
        time.sleep(0.02)
    return resp


def test_full_run_flow_produces_downloadable_result(client, monkeypatch):
    _fake_analyze(monkeypatch, [_result("example.com")])

    resp = client.post("/run", data={"domains": "example.com"})
    assert resp.status_code == 302
    progress_url = resp.headers["Location"]

    # The job finishes quickly; the progress page then redirects to results.
    resp = _wait_for_redirect(client, progress_url)
    assert resp.status_code == 302
    results_url = resp.headers["Location"]

    page = client.get(results_url)
    assert page.status_code == 200
    assert b"example.com" in page.data

    # A run CSV was persisted and is downloadable.
    runs = runs_mod.list_runs()
    assert len(runs) == 1
    dl = client.get("/download/" + runs[0].name)
    assert dl.status_code == 200
    assert dl.headers["Content-Type"].startswith("text/csv")


def test_download_rejects_path_traversal(client):
    assert client.get("/download/../secret").status_code == 404
    assert client.get("/download/notarun.csv").status_code == 404


def test_changes_needs_two_runs(client):
    resp = client.get("/changes")
    assert resp.status_code == 200
    assert b"at least two runs" in resp.data
