# Samples

The `samples/golden_events.jsonl` file contains four synthetic events that exercise three
representative CAR analytics:

- `CAR-2013-02-003` (process creation of `cmd.exe`).
- `CAR-2013-08-001` (process creation of `schtasks.exe`).
- `CAR-2013-05-003` (network flow with SMB Write on port 445).

Each record is normalized JSONL that can be fed directly to
`trustmitre ingest` or `trustmitre run` for end-to-end smoke testing.

Additional helper datasets:

- `samples/sample.csv` – minimal CSV variant for ingestion format checks.
- `samples/bad_lines.jsonl` – contains one malformed JSON line to validate graceful skipping.
- `samples/event spaced.jsonl` – JSONL file with spaces in the filename to exercise path handling.
