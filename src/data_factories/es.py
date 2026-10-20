"""Shared Elasticsearch REST helpers for data factories."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def load_env(path: Path | None = None) -> dict[str, str]:
    """Load key=value pairs from a .env file, then overlay process env."""
    env: dict[str, str] = {}
    if path is not None and path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    for key in ("ELASTICSEARCH_URL", "ELASTICSEARCH_API_KEY", "KIBANA_URL"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def require_es(env: dict[str, str]) -> tuple[str, str]:
    url = env.get("ELASTICSEARCH_URL", "").rstrip("/")
    key = env.get("ELASTICSEARCH_API_KEY", "")
    if not url or not key:
        raise SystemExit(
            "Missing ELASTICSEARCH_URL / ELASTICSEARCH_API_KEY "
            "(set env vars or pass --env-file)"
        )
    return url, key


def es_url_to_kb(es_url: str) -> str:
    return es_url.rstrip("/").replace(".es.", ".kb.")


class Api:
    def __init__(self, base: str, api_key: str, kibana: bool = False):
        self.base = base.rstrip("/")
        self.api_key = api_key
        self.kibana = kibana

    def request(self, method: str, path: str, body=None, content_type: str | None = None):
        url = f"{self.base}{path}"
        data = None
        headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Accept": "application/json",
        }
        if self.kibana:
            headers["kbn-xsrf"] = "true"
            headers["x-elastic-internal-origin"] = "kibana"
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode()
                headers["Content-Type"] = content_type or "application/json"
            elif isinstance(body, (bytes, bytearray)):
                data = body
                headers["Content-Type"] = content_type or "application/x-ndjson"
            else:
                data = str(body).encode()
                headers["Content-Type"] = content_type or "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
                if not raw:
                    return resp.status, None
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = raw
            return e.code, payload


def bulk_ndjson(
    api: Api,
    docs: list[dict],
    *,
    index: str | None = None,
    op: str = "create",
    refresh: bool = True,
) -> tuple[int, object]:
    """POST /_bulk (or /{index}/_bulk) with create/index actions."""
    lines: list[str] = []
    for d in docs:
        meta: dict = {op: {}}
        if index:
            meta[op]["_index"] = index
        if "_id" in d and op == "index":
            meta[op]["_id"] = d["_id"]
            body = {k: v for k, v in d.items() if k != "_id"}
        else:
            body = d
        lines.append(json.dumps(meta))
        lines.append(json.dumps(body))
    payload = ("\n".join(lines) + "\n").encode()
    path = f"/{index}/_bulk" if index else "/_bulk"
    if refresh:
        path += "?refresh=true"
    return api.request("POST", path, payload, content_type="application/x-ndjson")


def write_ndjson(path: Path, docs: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for d in docs:
            f.write(json.dumps(d) + "\n")
    print(f"wrote {path} ({len(docs)})")


def load_ndjson(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
