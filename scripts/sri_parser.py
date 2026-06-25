"""SRI Parser CLI - crawl a site for unsafe Subresource Integrity usage.

The reusable analysis logic now lives in the installed package at
``domain_security_analyzer.sri`` (see issue #18 / PyPI packaging). This script
is a thin command-line wrapper kept for backward compatibility, so existing
``python scripts/sri_parser.py <url>`` invocations keep working. For
programmatic use prefer::

    from domain_security_analyzer.sri import scan_url
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict

try:
    from domain_security_analyzer.sri import (  # noqa: F401  (re-exported)
        INTEGRITY_PATTERN,
        SRIParser,
        UnsafeResource,
        scan_url,
    )
except ModuleNotFoundError:  # pragma: no cover - running from a source checkout
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from domain_security_analyzer.sri import (  # noqa: F401  (re-exported)
        INTEGRITY_PATTERN,
        SRIParser,
        UnsafeResource,
        scan_url,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl a site and report unsafe Subresource Integrity implementations.",
    )
    parser.add_argument("url", help="Base URL or domain to crawl")
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Follow same-origin links up to --max-depth/--max-pages",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=1,
        help="Maximum crawl depth when --crawl is set (default: 1)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=25,
        help="Maximum number of same-origin pages to visit when --crawl is set (default: 25)",
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
    parser.add_argument(
        "--list-sri",
        action="store_true",
        help="List all external resources that include an integrity attribute",
    )
    return parser


def print_report(report: Dict[str, object], as_json: bool = False, list_all: bool = False) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"SRI Parser report for {report['base_url']}")
    print(f"Pages crawled: {report['pages_crawled']}")
    print(
        "SRI resources with integrity attribute: "
        f"{report['resources_with_integrity_count']}"
    )
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

    if list_all:
        print()
        if report["resources_with_integrity"]:
            print("All resources with integrity attributes:")
            for entry in report["resources_with_integrity"]:
                valid = ", ".join(entry["valid_hashes"]) or "None"
                invalid = ", ".join(entry["invalid_hashes"]) or "None"
                print(f"- {entry['resource_url']} ({entry['tag_type']})")
                print(f"  Page: {entry['page_url']}")
                print(f"  Integrity: {entry['integrity']}")
                print(f"  Crossorigin: {entry['crossorigin'] or 'None'}")
                print(f"  Valid hashes: {valid}")
                print(f"  Invalid hashes: {invalid}")
                print()
        else:
            print("No resources with integrity attributes detected.")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    report = scan_url(
        args.url,
        crawl=args.crawl,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
    )
    print_report(report, as_json=args.json, list_all=args.list_sri)


if __name__ == "__main__":
    main()
