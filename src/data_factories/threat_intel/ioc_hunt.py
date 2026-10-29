#!/usr/bin/env python3
"""Synthetic events for IOC Threat Hunt dashboard panels."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from data_factories.tenant import (
    TENANT,
    alias,
    dataset,
    lookup_file,
    ndjson_logs,
    poc_tag,
)

IOC_IP = "203.0.113.77"
IOC_DOMAIN = "evil-c2.example"
NOISE_IP = "198.51.100.10"


def _ts(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def network_doc(minutes_ago: int, *, hit: bool) -> dict:
    dest = IOC_IP if hit else NOISE_IP
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('ioc_hunt'), "namespace": "default"},
        "event": {
            "category": ["network"],
            "dataset": dataset('ioc_hunt') + '.network',
            "action": "allow",
            "outcome": "success",
            "kind": "event",
        },
        "source": {"ip": "10.20.4.18"},
        "destination": {"ip": dest, "domain": IOC_DOMAIN if hit else "cdn.example"},
        "network": {"transport": "tcp", "protocol": "https"},
        "observer": {"vendor": "Palo Alto", "product": "PAN-OS", "hostname": "pa-edge-01"},
        "rule": {"name": "threat-outbound" if hit else "allow-web"},
        "user": {"name": "jdoe"},
        "related": {
            "ip": ["10.20.4.18", dest],
            "hosts": [IOC_DOMAIN if hit else "cdn.example"],
        },
        "tags": [poc_tag(), "ioc-hunt", "network"] + (["ioc-hit"] if hit else []),
        TENANT: {'hunt': {'channel': 'network_traffic', 'index_alias': alias('sec', 'paloalto', 'prod')}},
    }


def web_doc(minutes_ago: int, *, hit: bool) -> dict:
    url = f"https://{IOC_DOMAIN}/beacon" if hit else "https://cdn.example/static.js"
    host = IOC_DOMAIN if hit else "cdn.example"
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('ioc_hunt'), "namespace": "default"},
        "event": {
            "category": ["web"],
            "dataset": dataset('ioc_hunt') + '.web',
            "action": "url-access",
            "kind": "event",
        },
        "source": {"ip": "10.20.4.18"},
        "url": {"full": url, "domain": host},
        "observer": {"vendor": "Zscaler", "product": "ZIA", "hostname": "zpa-gw"},
        "rule": {"name": "url-block" if hit else "allow"},
        "user": {"name": "jdoe"},
        "related": {"ip": ["10.20.4.18"], "hosts": [host]},
        "tags": [poc_tag(), "ioc-hunt", "web"] + (["ioc-hit"] if hit else []),
        TENANT: {'hunt': {'channel': 'web', 'index_alias': alias('sec', 'zscaler', 'prod')}},
    }


def auth_doc(minutes_ago: int, *, hit: bool) -> dict:
    src = IOC_IP if hit else "10.30.1.5"
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('ioc_hunt'), "namespace": "default"},
        "event": {
            "category": ["authentication"],
            "dataset": dataset('ioc_hunt') + '.auth',
            "action": "logon-failed" if hit else "logon-success",
            "outcome": "failure" if hit else "success",
            "kind": "event",
            "code": "4625" if hit else "4624",
        },
        "source": {"ip": src},
        "destination": {"ip": "10.1.8.12", "domain": "dc01.corp.local"},
        "host": {"hostname": "dc01"},
        "user": {"name": "admin"},
        "related": {"ip": [src, "10.1.8.12"], "hosts": ["dc01.corp.local"]},
        "tags": [poc_tag(), "ioc-hunt", "authentication"] + (["ioc-hit"] if hit else []),
        TENANT: {'hunt': {'channel': 'authentication', 'index_alias': alias('sec', 'msad', 'prod')}},
    }


def vpc_doc(minutes_ago: int, *, hit: bool) -> dict:
    dest = IOC_IP if hit else NOISE_IP
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('ioc_hunt'), "namespace": "default"},
        "event": {
            "category": ["network"],
            "dataset": dataset('ioc_hunt') + '.vpcflow',
            "action": "accept",
            "kind": "event",
        },
        "source": {"ip": "10.20.4.18"},
        "destination": {"ip": dest},
        "observer": {"vendor": "AWS", "product": "VPC Flow", "hostname": "vpc-fw-a"},
        "related": {"ip": ["10.20.4.18", dest]},
        "tags": [poc_tag(), "ioc-hunt", "vpcflow"] + (["ioc-hit"] if hit else []),
        TENANT: {'hunt': {'channel': 'network_traffic', 'index_alias': alias('app', 'aws', 'vpcflowlogs')}},
    }


def notables() -> list[dict]:
    return [
        {
            "@timestamp": _ts(120),
            "ioc.value": IOC_IP,
            "ioc.type": "ip",
            "ioc.field": "destination.ip",
            "notable.id": "ALERT-10482",
            "notable.name": "Outbound C2 Communication",
            "notable.severity": "high",
            "notable.link": "/app/security/alerts?kuery=ALERT-10482",
            "tags": [poc_tag(), "ioc-hunt", "notable"],
        },
        {
            "@timestamp": _ts(90),
            "ioc.value": IOC_DOMAIN,
            "ioc.type": "domain",
            "ioc.field": "url.domain",
            "notable.id": "ALERT-10471",
            "notable.name": "Suspicious Domain Access",
            "notable.severity": "medium",
            "notable.link": "/app/security/alerts?kuery=ALERT-10471",
            "tags": [poc_tag(), "ioc-hunt", "notable"],
        },
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("out"), help="NDJSON output directory")
    args = ap.parse_args(argv)
    OUT = args.out
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)
    docs: list[dict] = []
    # Hits for demo IOC
    for m in (5, 12, 25, 40, 55, 80, 100, 140, 200, 300):
        docs.append(network_doc(m, hit=True))
        docs.append(web_doc(m + 3, hit=True))
    for m in (60, 90, 150):
        docs.append(auth_doc(m, hit=True))
        docs.append(vpc_doc(m + 2, hit=True))
    # Noise
    for _ in range(40):
        m = rng.randint(1, 24 * 60)
        pick = rng.choice([network_doc, web_doc, auth_doc, vpc_doc])
        docs.append(pick(m, hit=False))

    hunt_path = OUT / ndjson_logs('ioc_hunt')
    hunt_path.write_text("\n".join(json.dumps(d) for d in docs) + "\n")
    not_path = OUT / lookup_file('ioc-notables')
    not_path.write_text("\n".join(json.dumps(d) for d in notables()) + "\n")
    print(f"Wrote {hunt_path} ({len(docs)} docs)")
    print(f"Wrote {not_path} ({len(notables())} docs)")
    print(f"Demo IOC IP={IOC_IP} domain={IOC_DOMAIN}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
