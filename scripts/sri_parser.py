"""SRI Parser - crawl a site for unsafe Subresource Integrity usage.

This script inspects pages on a given site, looks for external JavaScript
and stylesheet resources, and reports which ones violate SecurityScorecard's
"unsafe SRI" criteria. It also checks for a compensating control in the form
of a restrictive Content-Security-Policy header.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Regular expression to validate integrity hashes (sha256/sha384/sha512)
INTEGRITY_PATTERN = re.compile(r"^(sha(256|384|512))-[A-Za-z0-9+/=]+$")

# Tokens in script-src that indicate the policy is not restrictive enough to
# qualify as a compensating control.
PERMISSIVE_SCRIPT_TOKENS = {
    "*",
    "http:",
    "https:",
    "data:",
    "blob:",
    "filesystem:",
    "'unsafe-inline'",
    "'unsafe-eval'",
}


@dataclass
class UnsafeResource:
    page_url: str
    resource_url: str
    tag_type: str
    integrity: Optional[str]
    crossorigin: Optional[str]
    reasons: List[str] = field(default_factory=list)


class SRIParser:
    """Crawl a site and report unsafe Subresource Integrity usage."""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 1,
        max_pages: int = 25,
        timeout: int = 10,
        user_agent: str = "SRI-Parser/1.0 (+https://github.com/security-domain/domain-security-analyzer)",
    ) -> None:
        parsed = urlparse(base_url)
        if not parsed.scheme:
            base_url = f"https://{base_url}"
            parsed = urlparse(base_url)

        if not parsed.netloc:
            raise ValueError("A valid domain or URL is required")

        self.base_url = base_url.rstrip('/') or base_url
        self.base_netloc = parsed.netloc.lower()
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

        self.visited: Set[str] = set()
        self.to_visit: collections.deque[Tuple[str, int]] = collections.deque([(self.base_url, 0)])
        self.unsafe_resources: List[UnsafeResource] = []
        self.csp_policies: List[Tuple[str, str, str]] = []  # (page_url, header_name, policy_value)

    # ------------------------------------------------------------------
    # Crawling helpers
    # ------------------------------------------------------------------
    def _is_same_origin(self, url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        if not parsed.scheme:
            return True  # relative URL -> same origin
        return parsed.netloc.lower() == self.base_netloc

    def _is_external_resource(self, url: str) -> bool:
        if not url or not url.startswith(("http://", "https://")):
            return False
        parsed = urlparse(url)
        resource_domain = parsed.netloc.lower().replace("www.", "")
        base_domain = self.base_netloc.replace("www.", "")
        return resource_domain != base_domain

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if "text/html" not in response.headers.get("content-type", ""):
                return None
            return response
        except requests.RequestException:
            return None

    def _extract_links(self, html: str, page_url: str) -> Iterable[str]:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = urljoin(page_url, anchor.get("href"))
            if self._is_same_origin(href):
                yield href.split("#", 1)[0]

    # ------------------------------------------------------------------
    # SRI evaluation
    # ------------------------------------------------------------------
    def _parse_integrity_tokens(self, integrity: str) -> Tuple[List[str], List[str]]:
        valid_tokens: List[str] = []
        invalid_tokens: List[str] = []
        for token in integrity.split():
            if INTEGRITY_PATTERN.match(token.strip()):
                valid_tokens.append(token)
            else:
                invalid_tokens.append(token)
        return valid_tokens, invalid_tokens

    def _analyze_resource(self, tag, tag_type: str, page_url: str) -> Optional[UnsafeResource]:
        src_attr = "src" if tag_type == "script" else "href"
        resource_url = tag.get(src_attr)
        if not resource_url:
            return None

        resource_url = urljoin(page_url, resource_url)
        if not self._is_external_resource(resource_url):
            return None

        integrity = tag.get("integrity")
        crossorigin = tag.get("crossorigin")
        parsed = urlparse(resource_url)
        reasons: List[str] = []

        if not integrity:
            reasons.append("missing-integrity")
        else:
            valid_hashes, invalid_hashes = self._parse_integrity_tokens(integrity)
            if not valid_hashes:
                reasons.append("invalid-integrity-hash")
            elif invalid_hashes:
                reasons.append("mixed-invalid-hashes")

        if parsed.scheme != "https":
            reasons.append("non-https-resource")

        if self._is_cross_origin(parsed) and not crossorigin:
            reasons.append("missing-crossorigin")

        if reasons:
            return UnsafeResource(
                page_url=page_url,
                resource_url=resource_url,
                tag_type=tag_type,
                integrity=integrity,
                crossorigin=crossorigin,
                reasons=reasons,
            )
        return None

    def _is_cross_origin(self, parsed_url) -> bool:
        return parsed_url.netloc.lower() != self.base_netloc

    # ------------------------------------------------------------------
    # CSP evaluation
    # ------------------------------------------------------------------
    def _record_csp(self, page_url: str, response: requests.Response) -> None:
        for header_name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
            policy = response.headers.get(header_name)
            if policy:
                self.csp_policies.append((page_url, header_name, policy))

    def _has_compensating_csp(self) -> bool:
        for _, _, policy in self.csp_policies:
            directives = self._parse_csp(policy)
            script_sources = directives.get("script-src") or directives.get("default-src")
            if not script_sources:
                continue

            lower_tokens = [token.lower() for token in script_sources]
            if any(token in PERMISSIVE_SCRIPT_TOKENS for token in lower_tokens):
                continue

            has_specific_allowlist = any(
                token.startswith("'self'")
                or token.startswith("'nonce-")
                or token.startswith("'sha")
                or token.startswith("https://")
                or token.startswith("http://")
                or "." in token
                for token in lower_tokens
            )
            if has_specific_allowlist:
                return True
        return False

    def _parse_csp(self, policy: str) -> Dict[str, List[str]]:
        directives: Dict[str, List[str]] = {}
        for directive in policy.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if not parts:
                continue
            name = parts[0].lower()
            sources = parts[1:]
            directives[name] = sources
        return directives

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def crawl(self) -> Dict[str, object]:
        pages_crawled = 0
        while self.to_visit and pages_crawled < self.max_pages:
            url, depth = self.to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue

            response = self._fetch(url)
            self.visited.add(url)
            if not response:
                continue

            pages_crawled += 1
            html = response.text
            self._record_csp(url, response)

            soup = BeautifulSoup(html, "html.parser")
            for script in soup.find_all("script", src=True):
                unsafe = self._analyze_resource(script, "script", url)
                if unsafe:
                    self.unsafe_resources.append(unsafe)

            for link in soup.find_all("link", href=True):
                rel = link.get("rel") or []
                if "stylesheet" in [r.lower() for r in rel]:
                    unsafe = self._analyze_resource(link, "stylesheet", url)
                    if unsafe:
                        self.unsafe_resources.append(unsafe)

            if depth < self.max_depth:
                for href in self._extract_links(html, url):
                    if href not in self.visited:
                        self.to_visit.append((href, depth + 1))

        report = {
            "base_url": self.base_url,
            "pages_crawled": pages_crawled,
            "unsafe_resources": [unsafe.__dict__ for unsafe in self.unsafe_resources],
            "compensating_control_detected": self._has_compensating_csp(),
            "csp_policies": [
                {"page_url": page_url, "header": header, "value": policy}
                for page_url, header, policy in self.csp_policies
            ],
        }
        return report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl a site and report unsafe Subresource Integrity implementations.",
    )
    parser.add_argument("url", help="Base URL or domain to crawl")
    parser.add_argument("--max-depth", type=int, default=1, help="Maximum crawl depth (default: 1)")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=25,
        help="Maximum number of same-origin pages to visit (default: 25)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout for HTTP requests in seconds (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON instead of human-readable text",
    )
    return parser


def print_report(report: Dict[str, object], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"SRI Parser report for {report['base_url']}")
    print(f"Pages crawled: {report['pages_crawled']}")
    print()

    if report["compensating_control_detected"]:
        print("Compensating control: Restrictive Content-Security-Policy detected")
    else:
        print("Compensating control: Not detected")
    print()

    unsafe_resources = report["unsafe_resources"]
    if not unsafe_resources:
        print("No unsafe SRI resources found.")
    else:
        print("Unsafe SRI resources:")
        for entry in unsafe_resources:
            reasons = ", ".join(entry["reasons"])
            print(f"- {entry['resource_url']} ({entry['tag_type']})")
            print(f"  Page: {entry['page_url']}")
            print(f"  Integrity: {entry['integrity'] or 'None'}")
            print(f"  Crossorigin: {entry['crossorigin'] or 'None'}")
            print(f"  Reasons: {reasons}")
            print()

    if report["csp_policies"]:
        print("Content-Security-Policy headers encountered:")
        for entry in report["csp_policies"]:
            print(f"- {entry['page_url']} [{entry['header']}] -> {entry['value']}")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    sri_parser = SRIParser(
        base_url=args.url,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
    )
    report = sri_parser.crawl()
    print_report(report, as_json=args.json)


if __name__ == "__main__":
    main()
