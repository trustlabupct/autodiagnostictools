"""Configuration handling for trustMITRE."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from pydantic import Field, PositiveInt, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .util.paths import (
    default_config_path,
    ensure_directory,
    ensure_directories,
    resolve_path,
    runtime_base,
)


def _default_workers() -> int:
    cpu = os.cpu_count() or 1
    return max(1, cpu - 1)


class TrustMITREConfig(BaseSettings):
    """Application configuration values sourced from env vars, files, or defaults."""

    analytics_dir: Path = Field(default=Path("./analytics"))
    compiled_dir: Path = Field(default=Path("./.compiled"))
    logs_dir: Path = Field(default=Path("./logs"))
    output_dir: Path = Field(default=Path("./output"))
    download_url: str | None = Field(default=None)
    workers: PositiveInt = Field(default_factory=_default_workers)
    batch_size: PositiveInt = Field(default=500)
    timezone: str | None = Field(default=None)

    model_config = SettingsConfigDict(env_prefix="TRUSTMITRE_", extra="ignore")

    @model_validator(mode="after")
    def _normalize_paths(self) -> "TrustMITREConfig":
        base = Path.cwd()
        bundled_base = runtime_base()

        analytics_candidates = [
            resolve_path(self.analytics_dir, base),
            resolve_path(self.analytics_dir, bundled_base),
            resolve_path(Path("analytics"), bundled_base.parent.parent),
            resolve_path(Path("trusMITRE") / "analytics", bundled_base.parent),
        ]
        for candidate in analytics_candidates:
            if candidate.exists():
                self.analytics_dir = candidate
                break
        else:
            self.analytics_dir = analytics_candidates[0]

        self.compiled_dir = resolve_path(self.compiled_dir, base)
        self.logs_dir = resolve_path(self.logs_dir, base)
        self.output_dir = resolve_path(self.output_dir, base)
        ensure_directories(
            [
                self.compiled_dir,
                self.logs_dir,
                self.output_dir,
            ]
        )
        if not self.analytics_dir.exists():
            ensure_directory(self.analytics_dir)
        return self

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        for key in ("analytics_dir", "compiled_dir", "logs_dir", "output_dir"):
            data[key] = str(data[key])
        return data

    def save(self, path: Path | None = None) -> Path:
        target = path or default_config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
            handle.write("\n")
        return target


def load_config(config_path: Path | None = None) -> TrustMITREConfig:
    """Load configuration by merging defaults, file values, and environment variables."""
    file_path = config_path or default_config_path()
    payload: Dict[str, Any] = {}
    if file_path and file_path.exists():
        with open(file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    return TrustMITREConfig(**payload)


def dump_config(config: TrustMITREConfig) -> str:
    return json.dumps(config.to_dict(), indent=2)


__all__ = ["TrustMITREConfig", "load_config", "dump_config"]
