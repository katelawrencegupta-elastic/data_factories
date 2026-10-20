"""Resolve GEV demo paths when running under the gev_wkst1 CLI."""

from __future__ import annotations

import os
from pathlib import Path


def world_config_path() -> Path:
    env = os.environ.get("GEV_WORLD_CONFIG")
    if env:
        return Path(env)
    try:
        from src.config import WORLD_CONFIG  # type: ignore

        return WORLD_CONFIG
    except ImportError as exc:
        raise SystemExit(
            "Set GEV_WORLD_CONFIG to config/world.yaml or run under "
            "demos/gev_wkst1 (provides src.config)"
        ) from exc
