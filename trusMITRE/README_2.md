# trustMITRE

Version 2025.10.15 · Author: Volodymyr Dubetskyy · Contact: volodymyr.dubetskyy@upct.es

trustMITRE ingests CAR analytics, compiles them into deterministic analyzers, and executes
streaming detections over Sysmon and other telemetry sources to produce actionable reports.

```
analytics → compiler → ingest → engine → detections → reports
```

## Supported Platforms
- Windows 10/11 (Sysmon live collection)
- Windows Server 2019+
- Linux distributions with Python 3.11+

## Python Support
- CPython 3.11 and 3.12 officially tested

## Installation

### Linux / macOS (bash)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

Optional extras:
- `pip install trustmitre[windows]` for live Sysmon ingestion (requires admin privileges).
- `pip install trustmitre[offline_evtx]` for EVTX conversion.
- `pip install trustmitre[huge_json]` for streaming extremely large JSON dumps.

## Configuration
trustMITRE reads configuration from (in precedence order): command line flags, environment
variables prefixed with `TRUSTMITRE_`, an optional JSON file provided via `--config`, and the
platform default path:
- Linux/macOS: `~/.config/trustmitre/config.json`
- Windows: `%PROGRAMDATA%\trustmitre\config.json`

Available keys (defaults assume the current working directory):

| Key            | Default          | Description |
|----------------|------------------|-------------|
| `analytics_dir`| `./analytics`    | Source CAR text files |
| `compiled_dir` | `./.compiled`    | Generated Python analyzers |
| `logs_dir`     | `./logs`         | Normalized log snapshots |
| `output_dir`   | `./output`       | Reports and detections |
| `download_url` | `null`           | Remote feed for analytics (JSON response) |
| `workers`      | `max(1, cpu-1)`  | ProcessPool worker count |
| `batch_size`   | `500`            | Events per execution batch |
| `timezone`     | `null`           | Event normalization timezone |

Validate the active configuration:
```bash
trustmitre validate-config
```

## Sysmon Setup
Sysmon binaries are not redistributed. Download officially from Microsoft and ensure EULA
acceptance before deployment. Example steps:
1. Download Sysmon and configuration of choice.
2. Install with administrative PowerShell: `Sysmon64.exe -accepteula -i sysmonconfig-export.xml`.
3. Confirm events are written to `Microsoft-Windows-Sysmon/Operational`.

For live ingestion (Windows only):
```powershell
trustmitre ingest --live --output logs/sysmon.jsonl
```

To convert offline EVTX captures:
```bash
trustmitre ingest --evtx path/to/sysmon.evtx --output logs/sysmon.jsonl
```

## Quickstart Pipeline
```bash
trustmitre quickstart --config local-config.json --input samples/golden_events.jsonl
```
The pipeline performs:
1. `trustmitre download` – refresh analytics from `download_url` when supplied.
2. `trustmitre compile` – render analyzers into `compiled_dir` using Jinja2 templates.
3. `trustmitre ingest` – normalize logs (live Sysmon, EVTX, JSON, JSONL, CSV).
4. `trustmitre run` – execute analyzers with streaming batches and ProcessPool workers.
5. `trustmitre report` – build `detections.jsonl`, `report.csv`, and `summary.json`.

## Subcommands Overview
- `trustmitre download` – idempotent analytics refresh with ETag support.
- `trustmitre compile` – transforms `analytics/*.txt` into Python analyzers.
- `trustmitre ingest` – normalize raw logs; supports live Sysmon, EVTX, JSON, JSONL, CSV.
- `trustmitre run` – apply analyzers with `--include/--exclude`, `--workers`, and
  `--batch-size` controls.
- `trustmitre report` – regenerate CSV and JSON summaries from existing detections.
- `trustmitre validate-config` – display resolved configuration.
- `trustmitre schema` – print detection schema reference.
- `trustmitre clean` – purge caches, compiled analyzers, and temporary artifacts.

## Outputs
Primary detection log: `output/detections.jsonl` (schema v1.0).
Secondary artifacts:
- `output/report.csv` – tabular detections per analytic and host.
- `output/summary.json` – totals and severity breakdown.

Detection schema example:
```json
{
  "analytic_id": "CAR-2013-02-003",
  "title": "cmd.exe spawn",
  "log_type": "process",
  "time_generated": "2025-10-15T10:00:00Z",
  "host": "lab-host",
  "details": {"original_subset": {"host": "lab-host", "event_type": "Process:Create"}},
  "evidence": {"fields_used": ["exe", "command_line"]},
  "severity": "medium",
  "version": "1.0"
}
```

## Extending trustMITRE
1. Drop new CAR text analytics into `analytics/`.
2. `trustmitre compile` to regenerate analyzers.
3. Provide normalized events and re-run `trustmitre run`.
4. Review reports and iterate on tuning.

## Performance Tips
- Increase `workers` to leverage additional CPU capacity when running heavy analytics.
- Adjust `batch_size` to balance memory pressure and throughput for large JSONL feeds.
- Install the `huge_json` extra to stream gigabyte-scale JSON files without loading them fully.

## Troubleshooting
- **Empty detections**: confirm analytics compiled successfully and logs contain matching fields.
- **Permission errors**: live Sysmon collection requires elevated PowerShell.
- **Missing dependencies**: install extras (`windows`, `offline_evtx`, `huge_json`) as needed.
- **Network failures**: ensure `download_url` is reachable or skip the download phase when offline.

## Versioning
This release follows calendar version `2025.10.15`.
