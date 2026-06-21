"""Tests for the command-line interface."""

import pytest

from domain_security_analyzer import __version__
from domain_security_analyzer import cli


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_help_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "domain-analyzer" in out
    assert "--filtered-subdomains-file" in out


def test_parser_parses_positional_and_flags():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["in.txt", "out.csv", "20", "--include-wildcard-matches",
         "--filtered-subdomains-file", "filtered.csv"]
    )
    assert args.input_file == "in.txt"
    assert args.output_file == "out.csv"
    assert args.max_workers == 20
    assert args.include_wildcard_matches is True
    assert args.filtered_subdomains_file == "filtered.csv"


def test_parser_optional_workers_defaults_none():
    parser = cli.build_parser()
    args = parser.parse_args(["in.txt", "out.csv"])
    assert args.max_workers is None
    assert args.include_wildcard_matches is False
