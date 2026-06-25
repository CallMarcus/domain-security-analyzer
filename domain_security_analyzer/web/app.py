"""Flask app for the local Domain Security Analyzer web UI.

A thin presentation layer over the analysis engine: upload a list of domains,
watch progress, download the standard 29-column CSV, and diff the two most
recent runs. Single-user / localhost by design — analysis runs in a background
thread tracked in an in-memory registry.
"""
from __future__ import annotations

import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from ..analyzer import analyze_domains_from_file
from . import runs as runs_mod


@dataclass
class Job:
    id: str
    total: int
    completed: int = 0
    status: str = "running"  # running | done | error
    run_path: Optional[Path] = None
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.now)


class JobRegistry:
    """In-memory registry of analysis jobs (single-user local tool)."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, total: int) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], total=total)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                for key, value in fields.items():
                    setattr(job, key, value)


def parse_domains(text: str) -> list:
    """Extract domains from pasted/uploaded text: one per line, '#' comments skipped."""
    domains = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower() not in seen:
            seen.add(line.lower())
            domains.append(line)
    return domains


def create_app() -> Flask:
    app = Flask(__name__)
    registry = JobRegistry()

    def _run_job(job_id: str, domains: list, max_workers: int) -> None:
        """Background worker: write input, analyze, persist the run CSV."""
        try:
            run_path = runs_mod.new_run_path()
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tmp:
                tmp.write("\n".join(domains))
                input_path = tmp.name
            try:
                analyze_domains_from_file(
                    input_path,
                    str(run_path),
                    max_workers=max_workers,
                    progress_callback=lambda done, total: registry.update(job_id, completed=done),
                )
            finally:
                Path(input_path).unlink(missing_ok=True)
            registry.update(job_id, status="done", run_path=run_path, completed=len(domains))
        except Exception as exc:  # surface failure to the UI instead of dying silently
            registry.update(job_id, status="error", error=str(exc))

    @app.route("/")
    def index():
        return render_template("index.html", runs=runs_mod.list_runs(), label=runs_mod.run_label)

    @app.route("/run", methods=["POST"])
    def run():
        text = request.form.get("domains", "")
        upload = request.files.get("file")
        if upload and upload.filename:
            text += "\n" + upload.read().decode("utf-8", errors="replace")

        domains = parse_domains(text)
        if not domains:
            return render_template(
                "index.html",
                runs=runs_mod.list_runs(),
                label=runs_mod.run_label,
                error="No domains found. Paste one domain per line or upload a .txt file.",
            ), 400

        try:
            max_workers = max(1, min(50, int(request.form.get("max_workers", 10))))
        except (TypeError, ValueError):
            max_workers = 10

        job = registry.create(total=len(domains))
        thread = threading.Thread(
            target=_run_job, args=(job.id, domains, max_workers), daemon=True
        )
        thread.start()
        return redirect(url_for("run_progress", job_id=job.id))

    @app.route("/run/<job_id>")
    def run_progress(job_id: str):
        job = registry.get(job_id)
        if not job:
            abort(404)
        if job.status == "done" and job.run_path is not None:
            return redirect(url_for("results", run_name=job.run_path.name))
        return render_template("progress.html", job=job)

    @app.route("/run/<job_id>/status")
    def run_status(job_id: str):
        job = registry.get(job_id)
        if not job:
            abort(404)
        payload = {
            "status": job.status,
            "completed": job.completed,
            "total": job.total,
            "error": job.error,
        }
        if job.status == "done" and job.run_path is not None:
            payload["result_url"] = url_for("results", run_name=job.run_path.name)
        return jsonify(payload)

    @app.route("/results/<run_name>")
    def results(run_name: str):
        path = _safe_run_path(run_name)
        rows = runs_mod.load_run(path)
        columns = list(next(iter(rows.values())).keys()) if rows else []
        return render_template(
            "results.html",
            run_name=run_name,
            label=runs_mod.run_label(path),
            columns=columns,
            rows=list(rows.values()),
        )

    @app.route("/download/<run_name>")
    def download(run_name: str):
        path = _safe_run_path(run_name)
        return send_file(path, as_attachment=True, download_name=run_name, mimetype="text/csv")

    @app.route("/changes")
    def changes():
        run_files = runs_mod.list_runs()
        if len(run_files) < 2:
            return render_template("changes.html", insufficient=True, run_count=len(run_files))
        new_path, old_path = run_files[0], run_files[1]
        diff = runs_mod.diff_runs(runs_mod.load_run(old_path), runs_mod.load_run(new_path))
        return render_template(
            "changes.html",
            insufficient=False,
            diff=diff,
            old_label=runs_mod.run_label(old_path),
            new_label=runs_mod.run_label(new_path),
        )

    def _safe_run_path(run_name: str) -> Path:
        """Resolve a run filename to a path inside the data dir (no traversal)."""
        if "/" in run_name or "\\" in run_name or not run_name.startswith("run-"):
            abort(404)
        path = runs_mod.data_dir() / run_name
        if not path.is_file():
            abort(404)
        return path

    return app
