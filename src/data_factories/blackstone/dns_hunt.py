#!/usr/bin/env python3
"""P0 data factories for the BX DNS Hunt use case.

Usage:
  df-bx-dns-hunt --hunt-ips /path/to/hunt_task_ips.json --env-file /path/to/.env
  df-bx-dns-hunt --loop 30 --hunt-ips ... --env-file ...
  df-bx-dns-hunt --storyline single_host_c2 --hunt-ips ... --env-file ...
  df-bx-dns-hunt --refresh-hunt --hunt-ips ... --env-file ...
"""

from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from data_factories.es import Api, load_env, require_es

DNS_DS = "logs-bx.dns-default"
NETWORK_DS = "logs-bx.network-default"
SEED_BLOCKED = {"src": "10.226.65.68", "dest": "110.191.200.13"}
SEED_FLOW = {"dest": "10.191.200.135", "dest_port": 10000}

BENIGN = [
    "update.microsoft.com",
    "login.microsoftonline.com",
    "ocsp.digicert.com",
    "cdn.blackstone.com",
    "ntp.ubuntu.com",
    "watson.telemetry.microsoft.com",
]
SUSPICIOUS = [
    "suspicious-c2.example",
    "malicious-beacon.badactor.tld",
    "dga-like-xk7qp2.example",
]
DESTS = ["10.1.1.10", "10.1.1.11", "8.8.8.8", "1.1.1.1"]


def noise_ip() -> str:
    return f"10.{random.randint(50, 200)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def choose_query(profile: str | None = None) -> str:
    if profile == "suspicious":
        return random.choice(SUSPICIOUS)
    if profile == "benign":
        return random.choice(BENIGN)
    return random.choice(SUSPICIOUS if random.random() < 0.25 else BENIGN)


def dns_doc(src_ip: str, query: str) -> dict:
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "data_stream": {"type": "logs", "dataset": "bx.dns", "namespace": "default"},
        "event": {
            "category": ["network"],
            "dataset": "bx.dns",
            "kind": "event",
            "type": ["protocol"],
        },
        "dns": {"question": {"name": query, "type": "A"}},
        "source": {"ip": src_ip},
        "destination": {"ip": random.choice(DESTS)},
        "host": {"name": f"bx-dc-{random.randint(1, 3)}"},
        "observer": {"vendor": "Microsoft", "product": "Windows DNS"},
        "tags": ["bx-poc", "dns-factory"],
    }


def bulk_dns(es: Api, docs: list[dict]) -> int:
    lines: list[str] = []
    for d in docs:
        lines.append(json.dumps({"create": {}}))
        lines.append(json.dumps(d))
    status, body = es.request(
        "POST",
        f"/{DNS_DS}/_bulk?refresh=true",
        ("\n".join(lines) + "\n").encode(),
        content_type="application/x-ndjson",
    )
    if status >= 300 or (isinstance(body, dict) and body.get("errors")):
        raise RuntimeError(f"bulk failed: {status} {body}")
    return len(docs)


def factory_windows_dns(es: Api, hunt_ips: list[str], n: int = 120) -> None:
    """Mix of hunt-IP DNS (majority) + noise so JOIN panels stay informative."""
    docs = []
    for _ in range(n):
        if random.random() < 0.85:
            src = random.choice(hunt_ips[:20] if len(hunt_ips) >= 20 else hunt_ips)
            q = choose_query()
        else:
            src = noise_ip()
            q = choose_query("benign")
        docs.append(dns_doc(src, q))
    count = bulk_dns(es, docs)
    print(f"windows_dns_factory: wrote {count} events → {DNS_DS}")


def factory_pan_traffic(es: Api, n: int = 40) -> None:
    """P1: Palo Alto-like ECS network events (steve_dashboard traffic seeds)."""
    es.request("PUT", f"/_data_stream/{NETWORK_DS}")
    now = datetime.now(timezone.utc)
    docs = []

    def pan(**kw):
        return {
            "@timestamp": kw.get("ts", now.isoformat()),
            "data_stream": {"type": "logs", "dataset": "bx.network", "namespace": "default"},
            "event": {
                "category": ["network"],
                "dataset": "bx.network",
                "kind": "event",
                "type": ["connection"],
                "action": kw.get("action", "allow"),
                "outcome": kw.get("outcome", "success"),
            },
            "source": {"ip": kw["src_ip"], "port": kw.get("src_port", 40000)},
            "destination": {"ip": kw["dest_ip"], "port": kw.get("dest_port", 443)},
            "network": {
                "bytes": kw.get("bytes", 1024),
                "transport": "tcp",
                "protocol": "ip",
            },
            "observer": {
                "vendor": "Palo Alto Networks",
                "product": "PAN-OS",
                "ingress": {"interface": {"name": kw.get("iface", "ethernet1/1")}},
            },
            "cloud": {"account": {"id": "bx-aws-prod-001"}},
            "tags": ["bx-poc", "pan-traffic-factory"],
        }

    docs.append(
        pan(
            src_ip=SEED_BLOCKED["src"],
            dest_ip=SEED_BLOCKED["dest"],
            action="deny",
            outcome="failure",
            dest_port=443,
        )
    )
    docs.append(
        pan(
            src_ip="10.226.65.71",
            dest_ip=SEED_FLOW["dest"],
            dest_port=SEED_FLOW["dest_port"],
            action="allow",
        )
    )
    for _ in range(n):
        if random.random() < 0.2:
            docs.append(
                pan(
                    src_ip=SEED_BLOCKED["src"],
                    dest_ip=SEED_BLOCKED["dest"],
                    action=random.choice(["deny", "drop"]),
                    outcome="failure",
                    src_port=random.randint(20000, 60000),
                )
            )
        elif random.random() < 0.35:
            docs.append(
                pan(
                    src_ip=f"10.226.65.{random.randint(70, 90)}",
                    dest_ip=SEED_FLOW["dest"],
                    dest_port=SEED_FLOW["dest_port"],
                    action=random.choice(["allow", "allow", "deny"]),
                    src_port=random.randint(20000, 60000),
                    bytes=random.randint(200, 20000),
                )
            )
        else:
            action = random.choice(["allow", "allow", "deny", "drop"])
            docs.append(
                pan(
                    src_ip=f"10.{random.randint(1,50)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    dest_ip=f"110.{random.randint(1,200)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    dest_port=random.choice([80, 443, 22, 10000]),
                    action=action,
                    outcome="failure" if action != "allow" else "success",
                    src_port=random.randint(1024, 65535),
                    bytes=random.randint(64, 50000),
                )
            )

    lines = []
    for d in docs:
        lines.append(json.dumps({"create": {}}))
        lines.append(json.dumps(d))
    status, body = es.request(
        "POST",
        f"/{NETWORK_DS}/_bulk?refresh=true",
        ("\n".join(lines) + "\n").encode(),
        content_type="application/x-ndjson",
    )
    if status >= 300 or (isinstance(body, dict) and body.get("errors")):
        raise RuntimeError(f"pan traffic bulk failed: {status} {body}")
    print(f"pan_traffic_factory: wrote {len(docs)} events → {NETWORK_DS}")


def factory_storyline(es: Api, hunt_ips: list[str], scenario: str) -> None:
    if not hunt_ips:
        raise RuntimeError("no hunt IPs")
    docs = []
    if scenario == "single_host_c2":
        src = hunt_ips[0]
        for _ in range(30):
            docs.append(dns_doc(src, "malicious-beacon.badactor.tld"))
        print(f"storyline single_host_c2: {src} → malicious-beacon.badactor.tld x30")
    elif scenario == "shared_ioc_domain":
        for src in hunt_ips[:8]:
            for _ in range(5):
                docs.append(dns_doc(src, "suspicious-c2.example"))
        print("storyline shared_ioc_domain: 8 hunt IPs → suspicious-c2.example")
    else:
        raise RuntimeError(f"unknown storyline: {scenario}")
    bulk_dns(es, docs)


def refresh_hunt(es: Api, hunt_ips: list[str]) -> None:
    """Re-bulk lookup index + re-execute enrich (IOC factory)."""
    mappings = {
        "properties": {
            "ip": {"type": "ip"},
            "hunt_name": {"type": "keyword"},
            "source": {"type": "keyword"},
            "@timestamp": {"type": "date"},
        }
    }
    now = datetime.now(timezone.utc).isoformat()
    for index, settings in [
        ("bx-hunt-task", {}),
        ("bx-hunt-task-lookup", {"settings": {"index": {"mode": "lookup"}}}),
    ]:
        body = {"mappings": mappings, **settings}
        es.request("PUT", f"/{index}", body)
        lines = []
        for i, ip in enumerate(hunt_ips):
            lines.append(json.dumps({"index": {"_id": f"hunt-{i}"}}))
            lines.append(
                json.dumps(
                    {
                        "ip": ip,
                        "hunt_name": "steve_dashboard_hunt_task",
                        "source": "splunk_kvstore:hunt_task",
                        "@timestamp": now,
                    }
                )
            )
        status, resp = es.request(
            "POST",
            f"/{index}/_bulk?refresh=true",
            ("\n".join(lines) + "\n").encode(),
            content_type="application/x-ndjson",
        )
        if status >= 300:
            raise RuntimeError(f"refresh {index} failed: {status} {resp}")
        print(f"hunt_ioc_factory: refreshed {len(hunt_ips)} docs in {index}")

    es.request(
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
    status, resp = es.request("PUT", "/_enrich/policy/bx-hunt-task-policy/_execute")
    print(f"hunt_ioc_factory: enrich execute → {status} {resp}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--loop", type=int, default=0, help="Repeat every N seconds (0=once)")
    ap.add_argument("--batch", type=int, default=120, help="DNS events per burst")
    ap.add_argument(
        "--storyline",
        choices=["single_host_c2", "shared_ioc_domain"],
        help="Run a scripted demo scenario",
    )
    ap.add_argument("--refresh-hunt", action="store_true", help="Refresh IOC indexes")
    ap.add_argument("--pan", action="store_true", help="Also emit pan_traffic_factory events")
    ap.add_argument("--dns-only", action="store_true", help="Only DNS (default if no --pan/--storyline)")
    ap.add_argument(
        "--hunt-ips",
        type=Path,
        required=True,
        help="JSON list of hunt IOC IPs (e.g. elastic/dns_hunt/hunt_task_ips.json)",
    )
    ap.add_argument("--env-file", type=Path, help=".env with ELASTICSEARCH_URL / API_KEY")
    args = ap.parse_args(argv)

    env = load_env(args.env_file) if args.env_file else load_env()
    url, key = require_es(env)
    es = Api(url, key)
    hunt_ips = json.loads(args.hunt_ips.read_text())

    def once() -> None:
        if args.refresh_hunt:
            refresh_hunt(es, hunt_ips)
        if args.storyline:
            factory_storyline(es, hunt_ips, args.storyline)
            return
        factory_windows_dns(es, hunt_ips, n=args.batch)
        if args.pan or not args.dns_only:
            factory_pan_traffic(es, n=max(20, args.batch // 3))

    def once_safe() -> None:
        try:
            once()
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # noqa: BLE001 — keep demo loop alive
            print(f"factory cycle error (will retry): {type(exc).__name__}: {exc}", flush=True)

    once_safe()
    while args.loop > 0:
        time.sleep(args.loop)
        once_safe()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
