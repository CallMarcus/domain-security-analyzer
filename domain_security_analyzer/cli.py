"""Command-line interface for the domain security analyzer."""

import argparse
import os
import platform
import sys

from .__version__ import __version__

USAGE_EPILOG = """\
examples:
  domain-analyzer domains.txt report.csv
  domain-analyzer domains.txt report.csv 20
  domain-analyzer domains.txt report.csv --filtered-subdomains-file filtered.csv
"""


def check_required_modules():
    """Verify runtime dependencies and print install guidance if any are missing."""
    missing_modules = []

    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        missing_modules.append('dnspython')

    try:
        import requests  # noqa: F401
    except ImportError:
        missing_modules.append('requests')

    try:
        from bs4 import BeautifulSoup  # noqa: F401
    except ImportError:
        missing_modules.append('beautifulsoup4')

    if missing_modules:
        print("ERROR: Missing required Python packages!")
        print("\nPlease install the following packages:")
        for module in missing_modules:
            print(f"  - {module}")

        print("\nInstallation command:")
        print(f"  pip install {' '.join(missing_modules)}")
        print("\nOr if using pip3:")
        print(f"  pip3 install {' '.join(missing_modules)}")
        print("\nIf using a virtual environment, activate it first and then run the pip command.")

        if 'beautifulsoup4' in missing_modules:
            print("\nNote: beautifulsoup4 is required for SRI (Subresource Integrity) analysis")
        sys.exit(1)


def _configure_windows_console():
    """Best-effort console setup for color and UTF-8 output on Windows."""
    if platform.system() != 'Windows':
        return
    try:
        import colorama
        colorama.init()  # Initialize colorama for Windows color support
    except ImportError:
        pass  # colorama not installed, colors won't work

    # Try to set console to UTF-8 mode
    try:
        os.system('chcp 65001 > nul')
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='domain-analyzer',
        description='Analyze domain security configurations: DNS, email '
                    'authentication (SPF/DKIM/DMARC), subdomain discovery, and '
                    'Subresource Integrity (SRI) scanning.',
        epilog=USAGE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('input_file', help='Text file with one domain per line')
    parser.add_argument('output_file', help='Output CSV path')
    parser.add_argument(
        'max_workers', nargs='?', type=int, default=None,
        help='Number of parallel workers (default: OS-dependent)',
    )
    parser.add_argument(
        '--include-wildcard-matches', action='store_true',
        help='Include subdomains whose DNS answers match the wildcard baseline',
    )
    parser.add_argument(
        '--filtered-subdomains-file', metavar='PATH', default=None,
        help='Write subdomains excluded by wildcard filtering to a separate CSV',
    )
    parser.add_argument(
        '--version', action='version', version=f'%(prog)s {__version__}',
    )
    return parser


def main(argv=None):
    _configure_windows_console()

    parser = build_parser()
    args = parser.parse_args(argv)

    # Check dependencies only after argparse has handled --help/--version so
    # those work even in a minimal environment.
    check_required_modules()
    from .analyzer import analyze_domains_from_file

    default_workers = min(10, (os.cpu_count() or 4) * 2)
    max_workers = args.max_workers or default_workers

    input_file = os.path.normpath(args.input_file)
    output_file = os.path.normpath(args.output_file)
    filtered_subdomains_file = (
        os.path.normpath(args.filtered_subdomains_file)
        if args.filtered_subdomains_file else None
    )

    print("\nStarting domain analysis:")
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Workers: {max_workers}")
    if args.include_wildcard_matches:
        print("Include wildcard-matched subdomains: True")
    if filtered_subdomains_file:
        print(f"Filtered subdomains file: {filtered_subdomains_file}")
    print("")

    try:
        analyze_domains_from_file(
            input_file,
            output_file,
            max_workers,
            include_wildcard_matches=args.include_wildcard_matches,
            filtered_subdomains_file=filtered_subdomains_file,
        )
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user. Partial results may have been saved.")
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
