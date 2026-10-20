"""Resolve FinOps demo paths when running under the cloud&llm CLI."""

from __future__ import annotations

import os
from pathlib import Path


def world_config_path() -> Path:
    env = os.environ.get("FINOPS_WORLD_CONFIG")
    if env:
        return Path(env)
    try:
        from src.config import WORLD_CONFIG  # type: ignore

        return WORLD_CONFIG
    except ImportError as exc:
        raise SystemExit(
            "Set FINOPS_WORLD_CONFIG to config/world.yaml or run under "
            "demos/cloud&llm_cost_modeling (provides src.config)"
        ) from exc


def demo_root() -> Path:
    env = os.environ.get("FINOPS_ROOT")
    if env:
        return Path(env)
    try:
        from src.config import ROOT  # type: ignore

        return ROOT
    except ImportError as exc:
        raise SystemExit(
            "Set FINOPS_ROOT to the FinOps demo root or run under "
            "demos/cloud&llm_cost_modeling"
        ) from exc


def ce_account(acct: dict | None) -> dict | None:
    """Rewrite account ids when FinOps live profile is active; else identity."""
    try:
        from src.profile import ce_account as _ce  # type: ignore

        return _ce(acct)
    except ImportError:
        return acct
