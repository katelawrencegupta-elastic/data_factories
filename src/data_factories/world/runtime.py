"""Resolve world config / demo paths from env vars or the calling demo's ``src`` package."""

from __future__ import annotations

import os
from pathlib import Path


def _world_config_from(env_var: str, demo_hint: str) -> Path:
    env = os.environ.get(env_var)
    if env:
        return Path(env)
    try:
        from src.config import WORLD_CONFIG  # type: ignore

        return WORLD_CONFIG
    except ImportError as exc:
        raise SystemExit(
            f"Set {env_var} to config/world.yaml or run under {demo_hint} "
            "(provides src.config)"
        ) from exc


def cloud_org_config_path() -> Path:
    """world.yaml for the multi-cloud org (FINOPS_WORLD_CONFIG)."""
    return _world_config_from("FINOPS_WORLD_CONFIG", "demos/cloud&llm_cost_modeling")


def microservices_config_path() -> Path:
    """world.yaml for the microservice shop (GEV_WORLD_CONFIG)."""
    return _world_config_from("GEV_WORLD_CONFIG", "demos/gev_wkst1")


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
