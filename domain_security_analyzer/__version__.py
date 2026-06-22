"""Resolve the installed package version.

The version is owned by git tags via setuptools-scm — there is no hardcoded
version string to keep in sync. At runtime we read it from the installed
package metadata, falling back to the file setuptools-scm writes at build time
(``_version.py``) when running from an unbuilt source tree.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("domain-security-analyzer")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    try:
        from ._version import version as __version__
    except Exception:
        __version__ = "0.0.0+unknown"
