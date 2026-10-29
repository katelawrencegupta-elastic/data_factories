#!/usr/bin/env python3
"""Synthetic egress traffic + Splunk-style lookups for exfil spike dashboard."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from data_factories.tenant import (
    TENANT,
    alias,
    dataset as tenant_dataset,
    lookup_file,
    ndjson_logs,
    poc_tag,
    public_ips_field,
)

# Hosts that should surface as spikes (today >> 3× weekly avg)
SPIKE_HOSTS = [
    ("10.32.8.44", 12.0, 95.0),   # weekly_avg_mb, mb_out_today
    ("10.32.11.7", 8.5, 40.0),
    ("10.40.2.19", 5.0, 22.0),
]
# Baseline hosts (no spike)
BASE_HOSTS = [
    ("10.32.5.10", 15.0, 12.0),
    ("10.32.5.22", 9.0, 8.0),
]

PUBLIC_IPS = [
    "203.0.113.10",
    "198.51.100.50",
    "93.184.216.34",
]

NOISE_URLS = [
    "http://ocsp.digicert.com/",
    "http://crl.paloaltonetworks.com/update",
]
REAL_URLS = [
    "https://transfer.example.net/pkg.zip",
    "https://files.dropbox-shadow.test/bulk",
    "https://cdn.legit.example/static.js",
]


def _ts(hours_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def traffic_doc(
    hours_ago: float,
    *,
    src: str,
    dest: str,
    bytes_out: int,
    url: str,
    noise: bool,
    dataset: str = "pan:traffic",
    rule: str = "allow-egress",
) -> dict:
    return {
        "@timestamp": _ts(hours_ago),
        "data_stream": {"type": "logs", "dataset": tenant_dataset("network_egress"), "namespace": "default"},
        "event": {
            "category": ["network"],
            "dataset": dataset,
            "action": "allowed",
            "kind": "event",
        },
        "source": {"ip": src},
        "destination": {"ip": dest},
        "url": {"full": url, "domain": url.split("/")[2] if "://" in url else url},
        "network": {
            "bytes": bytes_out,
            "direction": "outbound",
        },
        "rule": {"name": rule},
        "observer": {"vendor": "Palo Alto", "product": "PAN-OS"},
        TENANT: {
            "egress": {
                "src_zone": "trust",
                "dest_zone": "untrust",
                "palo_url_noise": noise,
                "index_alias": alias("sec", "paloalto", "nonprod"),
            }
        },
        "tags": [poc_tag(), "network-egress-exfil"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("out"), help="NDJSON output directory")
    args = ap.parse_args(argv)
    OUT = args.out
    OUT.mkdir(parents=True, exist_ok=True)
    docs: list[dict] = []

    # ~7d of traffic so Weekly_Avg_MB can be derived; heavy today for spike hosts
    for src, weekly_avg, today_mb in SPIKE_HOSTS + BASE_HOSTS:
        # distribute weekly volume across past 6 days (MB → bytes)
        daily_bytes = int(weekly_avg * 1_000_000)
        for day in range(1, 7):
            dest = f"52.{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,200)}"
            docs.append(
                traffic_doc(
                    day * 24 + random.random() * 6,
                    src=src,
                    dest=dest,
                    bytes_out=daily_bytes + random.randint(-100_000, 100_000),
                    url=random.choice(REAL_URLS),
                    noise=False,
                )
            )
        # today volume
        today_bytes = int(today_mb * 1_000_000)
        chunks = 8
        for i in range(chunks):
            dest = f"52.{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,200)}"
            docs.append(
                traffic_doc(
                    random.uniform(0.1, 12),
                    src=src,
                    dest=dest,
                    bytes_out=today_bytes // chunks,
                    url=random.choice(REAL_URLS),
                    noise=False,
                    dataset="pan:threat" if i % 3 == 0 else "pan:traffic",
                    rule="allow-web" if i % 3 == 0 else "allow-egress",
                )
            )
        # noise URL rows (macro should drop these from spike path)
        docs.append(
            traffic_doc(
                2.0,
                src=src,
                dest="165.225.10.20",
                bytes_out=5_000_000,
                url=random.choice(NOISE_URLS),
                noise=True,
            )
        )
        # public IP dest (lookup exclude)
        docs.append(
            traffic_doc(
                3.0,
                src=src,
                dest=random.choice(PUBLIC_IPS),
                bytes_out=8_000_000,
                url="https://corp-public.example/",
                noise=False,
            )
        )

    # Lookups
    public_rows = [{'ip': ip, public_ips_field(): ip, 'source': 'public_ips.csv'} for ip in PUBLIC_IPS]
    outbound_rows = [
        {"host_ip": src, "MB_out_today": today_mb, "source": "24h_outbound_data.csv"}
        for src, _w, today_mb in SPIKE_HOSTS + BASE_HOSTS
    ]

    (OUT / ndjson_logs('network_egress')).write_text(
        "\n".join(json.dumps(d) for d in docs) + "\n"
    )
    (OUT / lookup_file('lookup-public-ips')).write_text(
        "\n".join(json.dumps(d) for d in public_rows) + "\n"
    )
    (OUT / lookup_file('lookup-24h-outbound')).write_text(
        "\n".join(json.dumps(d) for d in outbound_rows) + "\n"
    )
    print(f"Wrote {len(docs)} egress events")
    print(f"Wrote {len(public_rows)} public_ips lookup rows")
    print(f"Wrote {len(outbound_rows)} 24h_outbound lookup rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
