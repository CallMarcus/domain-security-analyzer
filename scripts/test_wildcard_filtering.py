"""
Small test script to demonstrate wildcard filtering logic without making real DNS/HTTP calls.

This script mocks DNS answers so you can see which subdomains are included vs. filtered
under default behavior and when using --include-wildcard-matches.

Usage:
  python scripts/test_wildcard_filtering.py

Expected output shows discovered and filtered subdomains for two simulated domains:
  - wild.example: has a wildcard A baseline (1.2.3.4)
  - nowild.example: no wildcard present
"""

from typing import List, Optional
import sys
import types
import os

# Ensure project root on sys.path for importing domain_analyzer
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _ensure_stubs():
    """Ensure minimal stubs for optional deps so import doesn't exit."""
    # dns stub
    if 'dns' not in sys.modules:
        dns = types.ModuleType('dns')
        resolver = types.ModuleType('dns.resolver')
        exception = types.ModuleType('dns.exception')

        class Resolver:
            def __init__(self, configure: bool = False):
                self.timeout = 5
                self.lifetime = 5

            def resolve(self, domain: str, record_type: str):  # pragma: no cover - not used in test
                class _Ans(list):
                    pass

                return _Ans()

        class NXDOMAIN(Exception):
            pass

        class NoAnswer(Exception):
            pass

        class Timeout(Exception):
            pass

        resolver.Resolver = Resolver
        resolver.NXDOMAIN = NXDOMAIN
        resolver.NoAnswer = NoAnswer
        exception.Timeout = Timeout

        sys.modules['dns'] = dns
        sys.modules['dns.resolver'] = resolver
        sys.modules['dns.exception'] = exception
        dns.resolver = resolver
        dns.exception = exception

    # requests stub
    if 'requests' not in sys.modules:
        requests = types.ModuleType('requests')

        class RequestException(Exception):
            pass

        def get(*args, **kwargs):  # pragma: no cover - not used in test
            raise RequestException('requests.get is not available in test stub')

        requests.RequestException = RequestException
        requests.exceptions = types.SimpleNamespace(RequestException=RequestException)
        requests.get = get
        sys.modules['requests'] = requests

    # bs4 stub
    if 'bs4' not in sys.modules:
        bs4 = types.ModuleType('bs4')

        class BeautifulSoup:  # pragma: no cover - not used in test
            def __init__(self, *args, **kwargs):
                pass

        bs4.BeautifulSoup = BeautifulSoup
        sys.modules['bs4'] = bs4


def _import_domain_analyzer():
    try:
        import domain_analyzer as da
        return da
    except SystemExit:
        # Likely exited due to missing deps; add stubs and retry
        _ensure_stubs()
        import importlib
        return importlib.import_module('domain_analyzer')
    except ImportError:
        _ensure_stubs()
        import importlib
        return importlib.import_module('domain_analyzer')


da = _import_domain_analyzer()
DomainAnalyzer = da.DomainAnalyzer


class MockDomainAnalyzer(DomainAnalyzer):
    def __init__(self, include_wildcard_matches: bool = False, collect_filtered: bool = False):
        super().__init__(include_wildcard_matches=include_wildcard_matches, collect_filtered=collect_filtered)
        # Keep the list short for demonstration
        self.common_subdomains = ["www", "api", "mail"]

    def get_dns_record(self, domain: str, record_type: str) -> Optional[List[str]]:
        domain = domain.lower()

        # Simulated domain: wild.example (has wildcard A=1.2.3.4)
        if domain.endswith(".wild.example"):
            # The analyzer queries a random wildcard-test-* label to establish baseline
            if domain.startswith("wildcard-test-") and record_type == "A":
                return ["1.2.3.4"]
            if domain.startswith("wildcard-test-") and record_type == "CNAME":
                return None

            # www.wild.example resolves due to wildcard A (should be filtered by default)
            if domain == "www.wild.example" and record_type == "A":
                return ["1.2.3.4"]
            # api.wild.example has an explicit CNAME (should be included)
            if domain == "api.wild.example" and record_type == "CNAME":
                return ["api-target.example.net."]
            # mail.wild.example has an explicit A different from wildcard (should be included)
            if domain == "mail.wild.example" and record_type == "A":
                return ["9.9.9.9"]
            return None

        # Simulated domain: nowild.example (no wildcard)
        if domain.endswith(".nowild.example"):
            if domain.startswith("wildcard-test-"):
                return None
            if domain == "www.nowild.example" and record_type == "A":
                return ["5.5.5.5"]
            if domain == "api.nowild.example" and record_type == "CNAME":
                return ["api-target.example.net."]
            # mail.nowild.example does not exist
            return None

        return None


def run_case(label: str, include_wildcard: bool, domain: str):
    analyzer = MockDomainAnalyzer(include_wildcard_matches=include_wildcard, collect_filtered=True)
    result = analyzer.discover_subdomains(domain)
    print(f"\n[{label}] include_wildcard={include_wildcard} domain={domain}")
    print("  discovered:", sorted(result.get("subdomains", [])))
    print("  filtered:  ", sorted(result.get("filtered_subdomains", [])))
    print("  has_wildcard:", result.get("has_wildcard_dns"))


def main():
    # Domain with wildcard
    run_case("wild-default", include_wildcard=False, domain="wild.example")
    run_case("wild-include", include_wildcard=True, domain="wild.example")

    # Domain without wildcard
    run_case("nowild-default", include_wildcard=False, domain="nowild.example")


if __name__ == "__main__":
    main()
