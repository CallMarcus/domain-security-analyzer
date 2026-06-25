# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **SRI library API**: Subresource Integrity analysis is now importable from the
  installed package (`from domain_security_analyzer.sri import scan_url`),
  returning a structured report with per-resource integrity/crossorigin values,
  machine-readable reason codes, observed CSP headers, and compensating-control
  detection. `scripts/sri_parser.py` is now a thin CLI wrapper over it.
- **Local web UI** (optional `web` extra): `pip install domain-security-analyzer[web]`
  adds a `domain-analyzer-web` command that serves a localhost Flask app to
  upload domain lists, watch analysis progress, download the standard 29-column
  CSV, and diff the two most recent runs (highlighting security regressions vs.
  improvements). Runs are stored under `~/.domain-security-analyzer/runs/`
  (override via `DSA_DATA_DIR`).

### Changed

- `analyzer.py` exposes a reusable `write_results_csv()` helper, a shared
  `CSV_COLUMNS` constant, and an optional `progress_callback` on
  `analyze_domains_from_file` (used by the web UI). Backward compatible.

## [1.0.0] - 2026-06-21

First packaged release, distributable via PyPI.

### Added

- **Packaging**: project is now an installable Python package
  (`pip install domain-security-analyzer`) with a `pyproject.toml`, a
  `domain-analyzer` console entry point, `python -m domain_security_analyzer`
  module execution, and an importable API
  (`from domain_security_analyzer import DomainAnalyzer`).
- **Subresource Integrity (SRI) scanning**: detects external JS/CSS resources,
  computes SRI coverage, identifies SHA-256/384/512 usage, and reports gaps in
  the CSV output. Standalone `scripts/sri_parser.py` crawler mirrors
  SecurityScorecard's "Unsafe SRI" guidance.
- **Wildcard subdomain filtering**: suppresses subdomains that resolve solely due
  to wildcard DNS by comparing against A and CNAME baselines.
- CLI flag `--include-wildcard-matches` to include wildcard-matched subdomains.
- CLI flag `--filtered-subdomains-file <path>` to export filtered subdomains per
  domain to a separate CSV.
- `scripts/test_wildcard_filtering.py` mock-based test harness demonstrating the
  filtering behavior.
- Reference documentation for SRI, CSV output, SPF, DKIM, and DMARC under
  `docs/`.

### Changed

- Core logic moved from the top-level `domain_analyzer.py` script into the
  `domain_security_analyzer` package. `domain_analyzer.py` is retained as a thin
  backward-compatible shim, so `python domain_analyzer.py ...` and
  `from domain_analyzer import DomainAnalyzer` continue to work.
- README and docs updated with a Wildcard Filtering note and flag usage.

[Unreleased]: https://github.com/CallMarcus/domain-security-analyzer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/CallMarcus/domain-security-analyzer/releases/tag/v1.0.0
