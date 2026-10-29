"""Resolve world config / demo paths from env vars or an optional calling demo ``src`` package."""

from __future__ import annotations

import os
from pathlib import Path


def _world_config_from(env_var: str, hint: str) -> Path:
    env = os.environ.get(env_var)
    if env:
        return Path(env)
    try:
        from src.config import WORLD_CONFIG  # type: ignore

        return WORLD_CONFIG
    except ImportError as exc:
        raise SystemExit(
            f"Set {env_var} to a world.yaml path (or provide src.config.WORLD_CONFIG). "
            f"Hint: {hint}"
        ) from exc


def cloud_org_config_path() -> Path:
    """world.yaml for the multi-cloud org (``FINOPS_WORLD_CONFIG``)."""
    return _world_config_from(
        "FINOPS_WORLD_CONFIG",
        "export FINOPS_WORLD_CONFIG=/path/to/config/world.yaml",
    )


def microservices_config_path() -> Path:
    """world.yaml for the microservice shop (``GEV_WORLD_CONFIG``)."""
    return _world_config_from(
        "GEV_WORLD_CONFIG",
        "export GEV_WORLD_CONFIG=/path/to/config/world.yaml",
    )


def demo_root() -> Path:
    env = os.environ.get("FINOPS_ROOT") or os.environ.get("DEMO_ROOT")
    if env:
        return Path(env)
    try:
        from src.config import ROOT  # type: ignore

        return ROOT
    except ImportError as exc:
        raise SystemExit(
            "Set FINOPS_ROOT or DEMO_ROOT to the demo project root "
            "(or provide src.config.ROOT)."
        ) from exc


def ce_account(acct: dict | None) -> dict | None:
    """Rewrite account ids when a live profile shim is present; else identity."""
    try:
        from src.profile import ce_account as _ce  # type: ignore

        return _ce(acct)
    except ImportError:
        return acct
