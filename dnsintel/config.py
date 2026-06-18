from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class NetworkConfig(BaseModel):
    timeout_seconds: float = 15
    max_retries: int = 2
    rate_limit_per_second: float = 0.5


class SourceConfig(BaseModel):
    enabled: bool = False
    mode: str = "fixture"
    url: str | None = None
    requires_token: bool = False
    requires_authorization: bool = False
    enrichment_only: bool = False
    allow_empty: bool = False


class SourcesConfig(BaseModel):
    sources: dict[str, SourceConfig] = Field(default_factory=dict)
    network: NetworkConfig = Field(default_factory=NetworkConfig)


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def load_sources_config(path: Path = Path("configs/sources.yml")) -> SourcesConfig:
    return SourcesConfig.model_validate(load_yaml(path))


def validate_config_dir(config_dir: Path = Path("configs")) -> list[Path]:
    required = ["sources.yml", "scoring.yml", "allowlist.yml", "brands.yml"]
    paths = [config_dir / name for name in required]
    missing = [path for path in paths if not path.exists()]
    if missing:
        joined = ", ".join(str(path) for path in missing)
        raise FileNotFoundError(f"missing config files: {joined}")
    for path in paths:
        load_yaml(path)
    load_sources_config(config_dir / "sources.yml")
    return paths
