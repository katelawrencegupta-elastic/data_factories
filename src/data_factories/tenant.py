"""Neutral naming for streams, tags, lookups, and custom fields.

Override with env ``DATA_FACTORIES_TENANT`` (default ``demo``). Use a short
lowercase slug: letters, digits, ``_``, ``-`` (e.g. ``demo``, ``acme``).
"""

from __future__ import annotations

import os
import re

_DEFAULT = "demo"


def _sanitize(value: str) -> str:
    v = (value or "").strip().lower().replace(" ", "-")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", v):
        raise SystemExit(
            f"Invalid DATA_FACTORIES_TENANT={value!r}; "
            "expected a short lowercase slug (e.g. demo, acme)"
        )
    return v


TENANT = _sanitize(os.environ.get("DATA_FACTORIES_TENANT", _DEFAULT))


def poc_tag() -> str:
    return f"{TENANT}-poc"


def dataset(name: str) -> str:
    """Data-stream dataset id, e.g. ``demo.hdsi_auth``."""
    return f"{TENANT}.{name}"


def data_stream(type_: str, name: str, namespace: str = "default") -> dict:
    return {"type": type_, "dataset": dataset(name), "namespace": namespace}


def stream_name(type_: str, name: str, namespace: str = "default") -> str:
    """Full data-stream name, e.g. ``logs-demo.badge-default``."""
    return f"{type_}-{TENANT}.{name}-{namespace}"


def ndjson_logs(name: str) -> str:
    return f"logs-{TENANT}.{name}.ndjson"


def ndjson_metrics(name: str) -> str:
    return f"metrics-{TENANT}.{name}.ndjson"


def lookup_file(name: str) -> str:
    """Lookup NDJSON basename, e.g. ``demo-identities.ndjson``."""
    return f"{TENANT}-{name}.ndjson"


def index_name(name: str) -> str:
    return f"{TENANT}-{name}"


def enrich_policy(name: str) -> str:
    return f"{TENANT}-{name}-policy"


def alias(*parts: str) -> str:
    """Index-alias style id, e.g. ``demo_sec_okta_prod``."""
    return "_".join((TENANT, *parts))


def email(local: str) -> str:
    return f"{local}@{TENANT}.example"


def demo_host(kind: str = "dc") -> str:
    return f"{TENANT}-{kind}"


def public_ips_field() -> str:
    return f"{TENANT}_public_ips"
