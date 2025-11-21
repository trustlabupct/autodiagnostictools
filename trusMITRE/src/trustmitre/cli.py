"""trustMITRE command line interface."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator, List, Optional

import requests
import typer
from rich.console import Console
from rich.table import Table

from .analytics.compiler import compile_all
from .analytics.loader import iter_analytics
from .config import TrustMITREConfig, dump_config, load_config
from .engine.runner import Runner, load_compiled
from .ingest.reader import stream_logs
from .ingest.sysmon import convert_evtx, export_live_sysmon, is_windows
from .report.aggregator import write_detection_artifacts
from .report.schema import DetectionRecord
from .util.io import JsonDict, write_json_lines
from .util.logging import setup_logging
from .util.paths import ensure_directory

app = typer.Typer(no_args_is_help=True)
console = Console()

CONFIG_OPTION = typer.Option(None, "--config", "-c", help="Optional configuration file path.")


def _load_settings(config_path: Optional[Path]) -> TrustMITREConfig:
    return load_config(config_path)


@app.command()
def validate_config(config: Optional[Path] = CONFIG_OPTION) -> None:
    """Print the resolved configuration."""
    settings = _load_settings(config)
    setup_logging()
    console.print_json(dump_config(settings))


def _download_impl(config: Optional[Path] = None, force: bool = False) -> None:
    """Internal implementation of download."""
    settings = _load_settings(config)
    setup_logging()

    destination = ensure_directory(settings.analytics_dir)
    download_url = settings.download_url
    if not download_url:
        console.print("[yellow]No download URL configured; keeping existing analytics.[/yellow]")
        return

    etag_path = destination / ".cache_etag"
    headers = {}
    if etag_path.exists() and not force:
        headers["If-None-Match"] = etag_path.read_text(encoding="utf-8").strip()

    console.print(f"Fetching analytics from {download_url}...")
    try:
        response = requests.get(download_url, headers=headers, timeout=60)
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        console.print(f"[red]Failed to download analytics: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    if response.status_code == 304:
        console.print("[green]Analytics already up to date.[/green]")
        return
    response.raise_for_status()

    try:
        data = response.json()
    except ValueError as exc:
        console.print("[red]Analytics source did not return JSON data.[/red]")
        raise typer.Exit(code=1) from exc
    if isinstance(data, dict):
        entries = data.get("analytics") or list(data.values())
    else:
        entries = data

    count = 0
    for entry in entries:
        analytic_id = entry.get("id") or entry.get("name")
        content = entry.get("content")
        if not analytic_id or not content:
            continue
        path = destination / f"{analytic_id}.txt"
        path.write_text(content, encoding="utf-8")
        count += 1
    etag = response.headers.get("ETag")
    if etag:
        etag_path.write_text(etag, encoding="utf-8")
    console.print(f"[green]Fetched {count} analytics into {destination}.[/green]")


@app.command()
def download(
    config: Optional[Path] = CONFIG_OPTION,
    force: bool = typer.Option(False, "--force", help="Re-download analytics even if present."),
) -> None:
    """Download or refresh CAR analytics."""
    return _download_impl(config, force)


def _compile_impl(config: Optional[Path] = None) -> None:
    """Internal implementation of compile."""
    settings = _load_settings(config)
    setup_logging()

    analytics = list(iter_analytics(settings.analytics_dir))
    outputs = compile_all(analytics, settings.compiled_dir)
    console.print(f"[green]Compiled {len(outputs)} analyzers into {settings.compiled_dir}.[/green]")


@app.command()
def compile(
    config: Optional[Path] = CONFIG_OPTION,
) -> None:
    """Compile CAR analytics into runnable analyzers."""
    return _compile_impl(config)


def _ingest_impl(
    inputs: Optional[List[Path]] = None,
    config: Optional[Path] = None,
    evtx: Optional[List[Path]] = None,
    live: bool = False,
    output: Optional[Path] = None,
) -> None:
    """Internal implementation of ingest."""
    settings = _load_settings(config)
    setup_logging()

    target = output or settings.logs_dir / "ingested.jsonl"
    ensure_directory(target.parent)

    count = 0

    def _records() -> Iterator[JsonDict]:
        nonlocal count
        if live:
            if not is_windows():
                raise typer.BadParameter("Live Sysmon ingestion requires Windows.")
            live_path = target.parent / "sysmon_live.jsonl"
            export_live_sysmon(live_path)
            for record in stream_logs([live_path]):
                count += 1
                yield record
        for path in evtx or []:
            converted = target.parent / f"{path.stem}.jsonl"
            convert_evtx(path, converted)
            for record in stream_logs([converted]):
                count += 1
                yield record
        if inputs:
            for record in stream_logs(inputs):
                count += 1
                yield record

    write_json_lines(target, _records())
    console.print(f"[green]Wrote {count} normalized events to {target}.[/green]")


@app.command()
def ingest(
    inputs: List[Path] = typer.Argument(None, help="Input log files (JSON/JSONL/CSV)."),
    config: Optional[Path] = CONFIG_OPTION,
    evtx: List[Path] = typer.Option(
        None,
        "--evtx",
        help="EVTX files to convert using python-evtx.",
    ),
    live: bool = typer.Option(False, "--live", help="Collect live Sysmon events (Windows only)."),
    output: Optional[Path] = typer.Option(None, "--output", help="Output JSONL destination."),
) -> None:
    """Ingest logs into normalized JSONL."""
    return _ingest_impl(inputs, config, evtx, live, output)


def _run_impl(
    inputs: Optional[List[Path]] = None,
    config: Optional[Path] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    workers: Optional[int] = None,
    batch_size: Optional[int] = None,
) -> None:
    """Internal implementation of run."""
    settings = _load_settings(config)
    setup_logging()

    events_path = inputs or [settings.logs_dir / "ingested.jsonl"]
    events = stream_logs(events_path)

    analytics = load_compiled(settings.compiled_dir, include=include, exclude=exclude)
    if not analytics:
        if include or exclude:
            console.print(
                "[yellow]No analyzers matched the provided filters. Adjust filters or recompile analytics.[/yellow]"
            )
            raise typer.Exit(code=0)
        console.print(
            "[yellow]No compiled analyzers found. Run `trustmitre compile` first.[/yellow]"
        )
        raise typer.Exit(code=1)

    runner = Runner(
        analytics,
        workers=workers or settings.workers,
        batch_size=batch_size or settings.batch_size,
    )

    output_dir = ensure_directory(settings.output_dir)
    detection_path, report_path, summary_path = runner.execute_to_artifacts(events, output_dir)
    console.print(
        f"[green]Run complete.[/green]\nDetections: {detection_path}\nReport: {report_path}\nSummary: {summary_path}"
    )


@app.command()
def run(
    inputs: List[Path] = typer.Argument(
        None, help="Input normalized logs (defaults to config output)."
    ),
    config: Optional[Path] = CONFIG_OPTION,
    include: List[str] = typer.Option(None, "--include", help="Analytic IDs to include."),
    exclude: List[str] = typer.Option(None, "--exclude", help="Analytic IDs to exclude."),
    workers: Optional[int] = typer.Option(None, "--workers", help="Number of worker processes."),
    batch_size: Optional[int] = typer.Option(
        None, "--batch-size", help="Batch size for streaming."
    ),
) -> None:
    """Execute compiled analyzers on normalized logs."""
    return _run_impl(inputs, config, include, exclude, workers, batch_size)


def _report_impl(config: Optional[Path] = None) -> None:
    """Internal implementation of report."""
    settings = _load_settings(config)
    setup_logging()

    detection_path = settings.output_dir / "detections.jsonl"
    if not detection_path.exists():
        raise typer.BadParameter("No detections.jsonl found. Run `trustmitre run` first.")
    with open(detection_path, "r", encoding="utf-8") as handle:
        detections = [json.loads(line) for line in handle if line.strip()]
    records = [
        DetectionRecord(
            analytic_id=item["analytic_id"],
            title=item["title"],
            log_type=item["log_type"],
            time_generated=item["time_generated"],
            host=item["host"],
            details=item["details"],
            evidence=item["evidence"],
            severity=item["severity"],
        )
        for item in detections
    ]
    write_detection_artifacts(settings.output_dir, records)
    console.print("[green]Reports regenerated.[/green]")


@app.command()
def report(
    config: Optional[Path] = CONFIG_OPTION,
) -> None:
    """Re-build report artifacts from detections."""
    return _report_impl(config)


@app.command()
def schema() -> None:
    """Show detection schema example."""
    table = Table(title="Detection schema v1.0")
    table.add_column("Field")
    table.add_column("Description")
    table.add_row("analytic_id", "CAR analytic identifier")
    table.add_row("title", "Human readable title")
    table.add_row("log_type", "Event category")
    table.add_row("time_generated", "ISO8601 timestamp")
    table.add_row("host", "Originating host")
    table.add_row("details", "Original event subset")
    table.add_row("evidence", "Key fields used")
    table.add_row("severity", "info|low|medium|high")
    table.add_row("version", "Schema version (1.0)")
    console.print(table)


@app.command()
def clean(
    config: Optional[Path] = CONFIG_OPTION,
) -> None:
    """Remove generated artifacts and caches."""
    settings = _load_settings(config)
    setup_logging()

    targets = [
        settings.compiled_dir,
        settings.output_dir,
        settings.logs_dir,
        Path(".pytest_cache"),
        Path("__pycache__"),
    ]
    for target in targets:
        if target.exists():
            if target.is_file():
                target.unlink()
            else:
                shutil.rmtree(target, ignore_errors=True)
    console.print("[green]Cleanup complete.[/green]")


@app.command()
def quickstart(
    config: Optional[Path] = CONFIG_OPTION,
    inputs: List[Path] = typer.Argument(None, help="Optional log inputs for quickstart run."),
) -> None:
    """Run the full pipeline: download, compile, ingest, run, report."""
    _load_settings(config)
    setup_logging()

    _download_impl(config)
    _compile_impl(config)
    _ingest_impl(inputs=inputs, config=config)
    _run_impl(inputs=inputs, config=config)
    _report_impl(config=config)


if __name__ == "__main__":
    app()
