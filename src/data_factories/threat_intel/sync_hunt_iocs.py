#!/usr/bin/env python3
"""Automate hunt_task IOC sync into Elastic lookup + enrich.

Sources (first available wins, or --source):
  1. --hunt-ips JSON cache
  2. --splunk-samples lookup_samples.json → hunt_task.content[].ip
  3. --file path (newline or JSON list of IPs)

Usage:
  df-sync-hunt-iocs --hunt-ips ... --env-file ...
  df-sync-hunt-iocs --source splunk --splunk-samples ... --hunt-ips ... --env-file ...
  df-sync-hunt-iocs --loop 300 --hunt-ips ... --env-file ...
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from data_factories.es import Api, load_env, require_es

MAPPINGS = {
    "properties": {
        "ip": {"type": "ip"},
        "hunt_name": {"type": "keyword"},
        "source": {"type": "keyword"},
        "@timestamp": {"type": "date"},
        "updated_by": {"type": "keyword"},
    }
}


def load_ips(
    source: str,
    file: str | None,
    hunt_json: Path,
    splunk_samples: Path | None,
) -> tuple[list[str], str]:
    if file:
        path = Path(file)
        text = path.read_text().strip()
        if text.startswith("["):
            ips = json.loads(text)
        else:
            ips = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        return sorted(set(ips)), f"file:{path}"

    if (
        source in ("splunk", "auto")
        and splunk_samples
        and splunk_samples.exists()
        and source != "json"
    ):
        if source == "splunk" or not hunt_json.exists():
            ht = json.loads(splunk_samples.read_text())["results"]["hunt_task"]["content"]
            ips = [r["ip"] for r in ht if r.get("ip")]
            hunt_json.parent.mkdir(parents=True, exist_ok=True)
            hunt_json.write_text(json.dumps(ips, indent=2) + "\n")
            return sorted(set(ips)), "splunk_lookup_samples:hunt_task"

    if source in ("json", "auto") and hunt_json.exists():
        ips = json.loads(hunt_json.read_text())
        return sorted(set(ips)), f"cache:{hunt_json}"

    if splunk_samples and splunk_samples.exists():
        ht = json.loads(splunk_samples.read_text())["results"]["hunt_task"]["content"]
        ips = [r["ip"] for r in ht if r.get("ip")]
        return sorted(set(ips)), "splunk_lookup_samples:hunt_task"

    raise SystemExit("No IOC source found")


def ensure_indexes(es: Api) -> None:
    for index, settings in [
        ("bx-hunt-task", {}),
        ("bx-hunt-task-lookup", {"settings": {"index": {"mode": "lookup"}}}),
    ]:
        body = {"mappings": MAPPINGS, **settings}
        status, resp = es.request("PUT", f"/{index}", body)
        already = (
            isinstance(resp, dict)
            and resp.get("error", {}).get("type") == "resource_already_exists_exception"
        )
        if status not in (200, 201) and not already:
            raise SystemExit(f"create {index} failed: {status} {resp}")


def bulk_ips(es: Api, ips: list[str], provenance: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for index in ("bx-hunt-task", "bx-hunt-task-lookup"):
        es.request(
            "POST",
            f"/{index}/_delete_by_query?refresh=true&conflicts=proceed",
            {"query": {"match_all": {}}},
        )
        lines = []
        for i, ip in enumerate(ips):
            lines.append(json.dumps({"index": {"_id": f"hunt-{i}"}}))
            lines.append(
                json.dumps(
                    {
                        "ip": ip,
                        "hunt_name": "steve_dashboard_hunt_task",
                        "source": provenance,
                        "updated_by": "sync_hunt_iocs",
                        "@timestamp": now,
                    }
                )
            )
        status, body = es.request(
            "POST",
            f"/{index}/_bulk?refresh=true",
            ("\n".join(lines) + "\n").encode(),
            content_type="application/x-ndjson",
        )
        if status >= 300 or (isinstance(body, dict) and body.get("errors")):
            raise SystemExit(f"bulk {index} failed: {status} {body}")
        print(f"Synced {len(ips)} IPs → {index}")


def refresh_enrich(es: Api) -> None:
    status, body = es.request(
        "PUT",
        "/_enrich/policy/bx-hunt-task-policy",
        {
            "match": {
                "indices": "bx-hunt-task",
                "match_field": "ip",
                "enrich_fields": ["ip", "hunt_name", "source"],
            }
        },
    )
    if status not in (200, 201) and not (
        isinstance(body, dict)
        and body.get("error", {}).get("type") == "resource_already_exists_exception"
    ):
        print(f"enrich policy create: {status} {body}")
    status, body = es.request("PUT", "/_enrich/policy/bx-hunt-task-policy/_execute")
    print(f"Enrich execute → {status} {body}")


def sync_once(es: Api, args: argparse.Namespace) -> None:
    ips, provenance = load_ips(args.source, args.file, args.hunt_ips, args.splunk_samples)
    if args.add:
        ips = sorted(set(ips) | set(args.add))
        provenance += "+cli_add"
    if args.remove:
        ips = sorted(set(ips) - set(args.remove))
        provenance += "+cli_remove"
    args.hunt_ips.parent.mkdir(parents=True, exist_ok=True)
    args.hunt_ips.write_text(json.dumps(ips, indent=2) + "\n")
    ensure_indexes(es)
    bulk_ips(es, ips, provenance)
    refresh_enrich(es)
    print(f"IOC sync complete ({len(ips)} IPs from {provenance})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", choices=["auto", "json", "splunk"], default="auto")
    ap.add_argument("--file", help="External IP list (JSON array or newline-delimited)")
    ap.add_argument("--add", nargs="*", default=[], help="IPs to add this run")
    ap.add_argument("--remove", nargs="*", default=[], help="IPs to remove this run")
    ap.add_argument("--loop", type=int, default=0, help="Resync every N seconds")
    ap.add_argument(
        "--hunt-ips",
        type=Path,
        required=True,
        help="JSON cache path for hunt IOC IPs",
    )
    ap.add_argument(
        "--splunk-samples",
        type=Path,
        help="Optional splunk lookup_samples.json for --source splunk/auto",
    )
    ap.add_argument("--env-file", type=Path, help=".env with ELASTICSEARCH_URL / API_KEY")
    args = ap.parse_args(argv)
    env = load_env(args.env_file) if args.env_file else load_env()
    url, key = require_es(env)
    es = Api(url, key)

    def sync_safe() -> None:
        try:
            sync_once(es, args)
        except Exception as exc:  # noqa: BLE001 — keep sync loop alive
            print(f"hunt sync error (will retry): {type(exc).__name__}: {exc}", flush=True)

    sync_safe()
    while args.loop > 0:
        time.sleep(args.loop)
        sync_safe()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
