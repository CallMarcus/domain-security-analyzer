# Contributing

Thanks for your interest in improving Domain Security Analyzer! Contributions of
all kinds are welcome — bug reports, feature ideas, documentation, and code.

## Getting started

1. Fork the repository and clone your fork.
2. Create a development environment and install the package in editable mode:

   ```bash
   python -m venv .venv
   source .venv/bin/activate    # Windows: .venv\Scripts\activate
   pip install -e .
   ```

3. Create a branch for your change:

   ```bash
   git checkout -b my-feature
   ```

## Project layout

- `domain_security_analyzer/` — the installable package
  - `analyzer.py` — core analysis logic (`DomainAnalyzer`, `analyze_domains_from_file`)
  - `cli.py` — command-line interface (`domain-analyzer` entry point)
- `domain_analyzer.py` — thin backward-compatible shim for the legacy script path
- `scripts/` — standalone helpers (`sri_parser.py`, `parked_domain_csv.py`, test harnesses)
- `docs/` — reference guides (SRI, CSV output, SPF, DKIM, DMARC)

## Making changes

- Keep changes focused and match the style of the surrounding code.
- Update `README.md` and the relevant files in `docs/` when behavior changes.
- Add an entry under the `## [Unreleased]` section of `CHANGELOG.md`.
- Verify the package still builds and the CLI works:

  ```bash
  pip install -e .
  domain-analyzer --help
  python -m build && twine check dist/*
  ```

## Submitting

1. Push your branch and open a pull request against `main`.
2. Describe what the change does and why, and link any related issues.
3. Make sure the description notes any new dependencies or CLI flags.

## Reporting issues

Open an issue at
<https://github.com/CallMarcus/domain-security-analyzer/issues> with steps to
reproduce, the command you ran, and the observed vs. expected behavior.
