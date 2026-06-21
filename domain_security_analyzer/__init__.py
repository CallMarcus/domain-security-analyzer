"""Domain Security Analyzer.

A tool for analyzing domain security configurations including DNS records,
email authentication (SPF/DKIM/DMARC), subdomain discovery, and Subresource
Integrity (SRI) scanning.
"""

from .__version__ import __version__
from .analyzer import DomainAnalyzer, analyze_domains_from_file

__all__ = ["DomainAnalyzer", "analyze_domains_from_file", "__version__"]
