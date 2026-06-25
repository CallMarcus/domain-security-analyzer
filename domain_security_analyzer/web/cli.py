"""Command-line launcher for the local web UI (``domain-analyzer-web``)."""
from __future__ import annotations

import argparse
import sys
import threading
import webbrowser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-analyzer-web",
        description="Launch the local Domain Security Analyzer web UI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--open", action="store_true", help="Open the UI in a browser on start")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        from .app import create_app
    except ModuleNotFoundError as exc:  # Flask not installed
        if exc.name in {"flask", "werkzeug", "jinja2"}:
            print(
                "The web UI requires the optional 'web' extra. Install it with:\n"
                "    pip install domain-security-analyzer[web]",
                file=sys.stderr,
            )
            return 1
        raise

    app = create_app()
    url = f"http://{args.host}:{args.port}/"
    print(f"Domain Security Analyzer web UI running at {url}  (Ctrl+C to stop)")

    if args.open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    # use_reloader=False so the background browser-open and threads behave under launch.
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
