"""Unit tests for DomainAnalyzer pure logic (no network required)."""

import csv

import pytest

from domain_security_analyzer import DomainAnalyzer
from domain_security_analyzer import analyzer as analyzer_mod


@pytest.fixture
def analyzer():
    return DomainAnalyzer()


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
    ],
)
def test_get_parent_domain(analyzer, domain, expected):
    assert analyzer.get_parent_domain(domain) == expected


@pytest.mark.parametrize(
    "url,domain,expected",
    [
        ("https://cdn.other.com/a.js", "example.com", True),
        ("https://example.com/a.js", "example.com", False),
        ("https://www.example.com/a.js", "example.com", False),
        ("/local/a.js", "example.com", False),  # relative -> not external
        ("", "example.com", False),
    ],
)
def test_is_external_resource(analyzer, url, domain, expected):
    assert analyzer._is_external_resource(url, domain) is expected


@pytest.mark.parametrize(
    "integrity,expected",
    [
        ("sha256-abc", "sha256"),
        ("sha384-abc", "sha384"),
        ("sha512-abc", "sha512"),
        ("md5-abc", "unknown"),
        (None, None),
    ],
)
def test_extract_hash_algorithm(analyzer, integrity, expected):
    assert analyzer._extract_hash_algorithm(integrity) == expected


def test_check_sri_counts_and_coverage(analyzer):
    html = """
    <html><head>
      <script src="https://cdn.other.com/a.js" integrity="sha384-xyz"></script>
      <script src="https://cdn.other.com/b.js"></script>
      <link rel="stylesheet" href="https://cdn.other.com/c.css">
      <script src="https://example.com/local.js"></script>
    </head></html>
    """
    result = analyzer.check_sri("example.com", html)
    assert result["total_external_resources"] == 3  # local.js excluded
    assert result["resources_with_sri"] == 1
    assert result["missing_sri_count"] == 2
    assert result["sri_coverage_percentage"] == pytest.approx(33.3, abs=0.1)
    assert result["sri_enabled"] is True
    assert result["sri_algorithms_used"] == ["sha384"]
    assert result["error"] is None


def test_check_sri_empty_html(analyzer):
    result = analyzer.check_sri("example.com", "")
    assert result["error"] == "No HTML content available"
    assert result["total_external_resources"] == 0


def test_analyze_domains_from_file_writes_29_columns(tmp_path, monkeypatch):
    """End-to-end CSV writing with analyze_domain stubbed (no network)."""
    canned = {
        "domain": "example.com",
        "timestamp": "2026-06-21T00:00:00",
        "soa": {"exists": True, "parent_domain": "example.com", "record": "ns rec",
                "primary_ns": "ns", "admin_email": "rec"},
        "spf": {"exists": True, "record": '"v=spf1 -all"'},
        "dkim": {"exists": False, "records": []},
        "dmarc": {"exists": True, "record": "v=DMARC1; p=reject"},
        "subdomains": {"subdomains": ["www.example.com"], "cname_records": {},
                       "has_wildcard_dns": False, "hosting_provider": None,
                       "filtered_subdomains": []},
        "http_redirect": {"http_accessible": True, "redirects_to_https": True,
                          "final_url": "https://example.com", "error": None,
                          "redirect_chain": []},
        "sri": {"sri_enabled": False, "total_external_resources": 0,
                "resources_with_sri": 0, "sri_coverage_percentage": 0,
                "missing_sri_count": 0, "sri_algorithms_used": [], "error": None},
    }
    monkeypatch.setattr(
        analyzer_mod.DomainAnalyzer, "analyze_domain",
        lambda self, domain: dict(canned, domain=domain),
    )

    input_file = tmp_path / "in.txt"
    input_file.write_text("example.com\n")
    output_file = tmp_path / "out.csv"

    analyzer_mod.analyze_domains_from_file(str(input_file), str(output_file), max_workers=1)

    with open(output_file, newline="") as f:
        rows = list(csv.reader(f))

    assert len(rows[0]) == 29  # header column count
    assert rows[0][0] == "Domain"
    assert len(rows) == 2  # header + one data row
    assert rows[1][0] == "example.com"
