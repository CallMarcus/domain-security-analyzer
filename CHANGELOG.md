# Changelog

All notable changes to this project will be documented here.

## Unreleased

- Subdomain discovery: filter out hosts that resolve solely due to wildcard DNS by comparing against A and CNAME baselines.
- Add CLI flag `--include-wildcard-matches` to include wildcard-matched subdomains when desired.
- Add CLI flag `--filtered-subdomains-file <path>` to export filtered subdomains per domain to a separate CSV.
- Update README and docs with a Wildcard Filtering note and flag usage.
- Add `scripts/test_wildcard_filtering.py` mock-based test harness demonstrating the filtering behavior.

