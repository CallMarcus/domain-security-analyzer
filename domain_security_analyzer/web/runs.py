"""Run storage and diff logic for the local web UI.

Each analysis run is persisted as a timestamped copy of the standard report
CSV under a local data directory. The "Changes" view compares the two most
recent runs and classifies per-domain field deltas into security regressions,
improvements, and informational changes (MVP: last two runs only, no database).
"""
from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Timestamp format used for run filenames (sortable, filesystem-safe).
RUN_TS_FORMAT = "%Y%m%d-%H%M%S"

# Fields whose change carries a security meaning, and which direction is "good".
# For booleans, True is the healthy state; for SRI Coverage %, higher is better.
BOOLEAN_GOOD_TRUE = [
    "SOA Exists",
    "SPF Exists",
    "DKIM Exists",
    "DMARC Exists",
    "Redirects to HTTPS",
    "SRI Enabled",
]
NUMERIC_HIGHER_BETTER = ["SRI Coverage %"]

# Columns that are pure metadata / noise for a posture diff.
IGNORED_COLUMNS = {"Timestamp"}


def data_dir() -> Path:
    """Directory where run CSVs are stored (override with DSA_DATA_DIR)."""
    override = os.environ.get("DSA_DATA_DIR")
    base = Path(override) if override else Path.home() / ".domain-security-analyzer"
    runs = base / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    return runs


def new_run_path(timestamp: Optional[datetime] = None) -> Path:
    """Path for a new run CSV stamped with the given (or current) time."""
    ts = (timestamp or datetime.now()).strftime(RUN_TS_FORMAT)
    return data_dir() / f"run-{ts}.csv"


def list_runs() -> List[Path]:
    """All saved run CSVs, newest first."""
    return sorted(data_dir().glob("run-*.csv"), reverse=True)


def run_label(path: Path) -> str:
    """Human-readable label for a run file derived from its timestamp."""
    stem = path.stem.replace("run-", "", 1)
    try:
        return datetime.strptime(stem, RUN_TS_FORMAT).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return stem


def load_run(path: Path) -> Dict[str, Dict[str, str]]:
    """Load a run CSV into a mapping of domain -> {column: value}."""
    rows: Dict[str, Dict[str, str]] = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            domain = (row.get("Domain") or "").strip()
            if domain:
                rows[domain] = row
    return rows


def _classify_change(column: str, old: str, new: str) -> str:
    """Return 'regression', 'improvement', or 'other' for a single field delta."""
    if column in BOOLEAN_GOOD_TRUE:
        # Healthy = "True"; losing it is a regression, gaining it an improvement.
        if old == "True" and new != "True":
            return "regression"
        if old != "True" and new == "True":
            return "improvement"
        return "other"
    if column in NUMERIC_HIGHER_BETTER:
        try:
            o, n = float(old or 0), float(new or 0)
        except ValueError:
            return "other"
        if n < o:
            return "regression"
        if n > o:
            return "improvement"
        return "other"
    return "other"


def diff_runs(old: Dict[str, Dict[str, str]], new: Dict[str, Dict[str, str]]) -> Dict[str, object]:
    """Diff two loaded runs (old -> new), classifying per-domain field changes."""
    old_domains, new_domains = set(old), set(new)

    added = sorted(new_domains - old_domains)
    removed = sorted(old_domains - new_domains)

    changed: List[Dict[str, object]] = []
    for domain in sorted(old_domains & new_domains):
        old_row, new_row = old[domain], new[domain]
        regressions: List[Dict[str, str]] = []
        improvements: List[Dict[str, str]] = []
        other: List[Dict[str, str]] = []

        for column in new_row:
            if column in IGNORED_COLUMNS or column == "Domain":
                continue
            old_val = (old_row.get(column) or "").strip()
            new_val = (new_row.get(column) or "").strip()
            if old_val == new_val:
                continue
            entry = {"field": column, "old": old_val, "new": new_val}
            kind = _classify_change(column, old_val, new_val)
            if kind == "regression":
                regressions.append(entry)
            elif kind == "improvement":
                improvements.append(entry)
            else:
                other.append(entry)

        if regressions or improvements or other:
            changed.append(
                {
                    "domain": domain,
                    "regressions": regressions,
                    "improvements": improvements,
                    "other": other,
                }
            )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "regression_count": sum(len(c["regressions"]) for c in changed),
        "improvement_count": sum(len(c["improvements"]) for c in changed),
    }
