"""Smoke tests for package structure and public API."""

import importlib


def test_package_exposes_public_api():
    pkg = importlib.import_module("domain_security_analyzer")
    assert hasattr(pkg, "DomainAnalyzer")
    assert hasattr(pkg, "analyze_domains_from_file")
    assert isinstance(pkg.__version__, str)
    assert pkg.__version__.count(".") >= 2


def test_version_matches_module():
    from domain_security_analyzer import __version__
    from domain_security_analyzer.__version__ import __version__ as mod_version
    assert __version__ == mod_version


def test_legacy_shim_reexports_analyzer():
    # Backward compatibility: `from domain_analyzer import DomainAnalyzer`
    shim = importlib.import_module("domain_analyzer")
    from domain_security_analyzer import DomainAnalyzer
    assert shim.DomainAnalyzer is DomainAnalyzer
