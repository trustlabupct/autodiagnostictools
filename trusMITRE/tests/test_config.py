from __future__ import annotations

import json

from trustmitre.config import TrustMITREConfig, load_config


def test_trustmitre_config_creates_directories(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.json"
    payload = {
        "analytics_dir": "./analytics",
        "compiled_dir": "./.compiled",
        "logs_dir": "./logs",
        "output_dir": "./output",
        "workers": 2,
        "batch_size": 10,
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    settings = load_config(config_path)
    assert isinstance(settings, TrustMITREConfig)
    assert settings.analytics_dir.exists()
    assert settings.compiled_dir.exists()
    assert settings.logs_dir.exists()
    assert settings.output_dir.exists()
