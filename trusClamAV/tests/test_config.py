from pathlib import Path

from trusClamAV.config_schema import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_OUTPUT_PREFIX,
    resolve_output_prefix,
)


def test_resolve_output_prefix_default():
    prefix = resolve_output_prefix("")
    expected = DEFAULT_OUTPUT_DIR / DEFAULT_OUTPUT_PREFIX
    assert prefix == expected


def test_resolve_output_prefix_relative_custom():
    prefix = resolve_output_prefix("daily/scan1")
    assert prefix == DEFAULT_OUTPUT_DIR / "daily" / "scan1"


def test_resolve_output_prefix_explicit_out_subdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prefix = resolve_output_prefix("out/custom/scan1")
    assert prefix == Path("out/custom/scan1")
