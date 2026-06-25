"""Unit tests for SRI analysis pure logic (no network required)."""

import pytest
from bs4 import BeautifulSoup

from domain_security_analyzer import SRIParser, UnsafeResource, scan_url
from domain_security_analyzer import sri as sri_mod


@pytest.fixture
def parser():
    return SRIParser("https://example.com")


def _tag(html):
    """Parse a single HTML fragment into its first tag."""
    return BeautifulSoup(html, "html.parser").find(True)


def test_public_api_exports():
    # The convenience API named in issue #18 must be importable.
    assert callable(scan_url)
    assert SRIParser is sri_mod.SRIParser
    assert UnsafeResource is sri_mod.UnsafeResource


def test_bare_domain_gets_https_scheme():
    p = SRIParser("example.com")
    assert p.base_url == "https://example.com"
    assert p.base_netloc == "example.com"


def test_invalid_base_url_rejected():
    with pytest.raises(ValueError):
        SRIParser("")


def test_same_origin_resource_is_ignored(parser):
    tag = _tag('<script src="https://example.com/app.js"></script>')
    assert parser._analyze_resource(tag, "script", "https://example.com/") is None


def test_external_script_missing_integrity(parser):
    tag = _tag('<script src="https://cdn.example.org/app.js"></script>')
    result = parser._analyze_resource(tag, "script", "https://example.com/")
    assert isinstance(result, UnsafeResource)
    assert "missing-integrity" in result.reasons
    assert result.tag_type == "script"


def test_external_resource_with_valid_integrity_is_safe(parser):
    valid = "sha384-" + "A" * 64
    tag = _tag(
        f'<script src="https://cdn.example.org/app.js" '
        f'integrity="{valid}" crossorigin="anonymous"></script>'
    )
    assert parser._analyze_resource(tag, "script", "https://example.com/") is None


def test_invalid_integrity_hash_flagged(parser):
    tag = _tag(
        '<script src="https://cdn.example.org/app.js" '
        'integrity="md5-deadbeef" crossorigin="anonymous"></script>'
    )
    result = parser._analyze_resource(tag, "script", "https://example.com/")
    assert "invalid-integrity-hash" in result.reasons


def test_mixed_valid_and_invalid_hashes_flagged(parser):
    valid = "sha384-" + "A" * 64
    tag = _tag(
        f'<script src="https://cdn.example.org/app.js" '
        f'integrity="{valid} md5-deadbeef" crossorigin="anonymous"></script>'
    )
    result = parser._analyze_resource(tag, "script", "https://example.com/")
    assert "mixed-invalid-hashes" in result.reasons


def test_non_https_resource_flagged(parser):
    valid = "sha384-" + "A" * 64
    tag = _tag(
        f'<script src="http://cdn.example.org/app.js" '
        f'integrity="{valid}" crossorigin="anonymous"></script>'
    )
    result = parser._analyze_resource(tag, "script", "https://example.com/")
    assert "non-https-resource" in result.reasons


def test_cross_origin_without_crossorigin_flagged(parser):
    valid = "sha384-" + "A" * 64
    tag = _tag(
        f'<script src="https://cdn.example.org/app.js" integrity="{valid}"></script>'
    )
    result = parser._analyze_resource(tag, "script", "https://example.com/")
    assert "missing-crossorigin" in result.reasons


def test_external_stylesheet_missing_integrity(parser):
    tag = _tag('<link rel="stylesheet" href="https://cdn.example.org/style.css">')
    result = parser._analyze_resource(tag, "stylesheet", "https://example.com/")
    assert isinstance(result, UnsafeResource)
    assert "missing-integrity" in result.reasons
    assert result.tag_type == "stylesheet"


def test_restrictive_csp_is_compensating_control(parser):
    parser.csp_policies = [
        ("https://example.com/", "Content-Security-Policy", "script-src 'self' https://cdn.example.org")
    ]
    assert parser._has_compensating_csp() is True


def test_permissive_csp_is_not_compensating_control(parser):
    parser.csp_policies = [
        ("https://example.com/", "Content-Security-Policy", "script-src 'unsafe-inline' *")
    ]
    assert parser._has_compensating_csp() is False


def test_integrity_pattern_accepts_known_algorithms():
    assert sri_mod.INTEGRITY_PATTERN.match("sha256-" + "a" * 44)
    assert sri_mod.INTEGRITY_PATTERN.match("sha512-" + "b" * 88)
    assert not sri_mod.INTEGRITY_PATTERN.match("sha1-abc")
