#!/usr/bin/env python3
"""Backward-compatible entry point.

The implementation now lives in the :mod:`domain_security_analyzer` package.
This shim preserves the historical ``python domain_analyzer.py ...`` invocation
and the ``from domain_analyzer import DomainAnalyzer`` import path.

Prefer the installed console script ``domain-analyzer`` or
``python -m domain_security_analyzer`` going forward.
"""

from domain_security_analyzer.cli import main


def __getattr__(name):
    # Lazily re-export the public API (DomainAnalyzer, analyze_domains_from_file)
    # so importing this shim does not require the runtime dependencies unless the
    # analysis code is actually used.
    from domain_security_analyzer import analyzer
    return getattr(analyzer, name)


if __name__ == "__main__":
    main()
