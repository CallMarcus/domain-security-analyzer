"""Optional local web UI for Domain Security Analyzer.

Install with the ``web`` extra::

    pip install domain-security-analyzer[web]

then launch::

    domain-analyzer-web

This subpackage imports Flask, which is only present when the ``web`` extra is
installed; importing it without Flask raises a clear ImportError.
"""

from .app import create_app

__all__ = ["create_app"]
