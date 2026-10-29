#!/usr/bin/env python3
"""Synthetic VPC flow + CloudTrail events for AWS Blast Radius panels."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from data_factories.tenant import TENANT, alias, dataset, ndjson_logs, poc_tag

TARGET_IP = "10.40.12.88"
ACCOUNTS = [
    ("111122223333", "Customer-Prod-Security", "vpc-0a1b2c3d"),
    ("444455556666", "Customer-Shared-Services", "vpc-0a1b2c3d"),
]
DESTS = [
    ("10.40.20.11", "C1", 40),
    ("10.50.1.4", "C1", 25),
    ("10.40.30.7", "C1", 18),
    ("52.84.12.9", "C2", 12),
    ("10.60.2.15", "C2", 8),
    ("3.22.45.10", "C3", 6),
]
ARNS = [
    ("arn:aws:sts::111122223333:assumed-role/SecOpsInvest/jdoe", 18.2, ["LookupEvents", "GetCallerIdentity", "DescribeInstances"]),
    ("arn:aws:iam::111122223333:user/breakglass-admin", 14.1, ["ConsoleLogin", "AssumeRole", "PutObject"]),
    ("arn:aws:sts::111122223333:assumed-role/CIDeploy/build", 9.4, ["CreateStack", "UpdateFunctionCode"]),
    ("arn:aws:iam::444455556666:role/lambda-edge-reader", 6.2, ["GetObject", "ListBuckets"]),
    ("arn:aws:iam::111122223333:user/svc-inventory", 3.8, ["DescribeRegions", "ListAccounts"]),
]


def _ts(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def vpcflow_doc(
    minutes_ago: int,
    *,
    src: str,
    dest: str,
    account_id: str,
    account_name: str,
    vpc_id: str,
    community: str,
    packets: int = 1,
) -> dict:
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('aws_vpcflow'), "namespace": "default"},
        "event": {
            "category": ["network"],
            "dataset": dataset('aws_vpcflow'),
            "action": "accept",
            "kind": "event",
            "type": ["connection"],
        },
        "source": {"ip": src},
        "destination": {"ip": dest, "port": random.choice([443, 445, 22, 53, 80])},
        "network": {
            "transport": "tcp",
            "packets": packets,
            "direction": "egress",
        },
        "cloud": {
            "account": {"id": account_id, "name": account_name},
            "provider": "aws",
            "region": "us-east-1",
        },
        "related": {"ip": [src, dest]},
        TENANT: {
            "aws": {
                "vpc_id": vpc_id,
                "community": community,
                "flow_index_alias": alias("app", "aws", "vpcflowlogs"),
            }
        },
        "tags": [poc_tag(), "aws-blast-radius", "vpcflow"],
    }


def cloudtrail_doc(minutes_ago: int, *, arn: str, command: str, weight: float, account_id: str) -> dict:
    return {
        "@timestamp": _ts(minutes_ago),
        "data_stream": {"type": "logs", "dataset": dataset('aws_cloudtrail'), "namespace": "default"},
        "event": {
            "category": ["iam"],
            "dataset": dataset('aws_cloudtrail'),
            "action": command,
            "kind": "event",
            "provider": "cloudtrail.amazonaws.com",
        },
        "user": {"id": arn},
        "cloud": {
            "account": {"id": account_id},
            "provider": "aws",
            "region": "us-east-1",
        },
        TENANT: {
            "aws": {
                "arn": arn,
                "api_command": command,
                "centrality": {"weight": weight},
                "trail_index_alias": alias("app", "aws", "prod"),
            }
        },
        "tags": [poc_tag(), "aws-blast-radius", "cloudtrail"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("out"), help="NDJSON output directory")
    args = ap.parse_args(argv)
    OUT = args.out
    OUT.mkdir(parents=True, exist_ok=True)
    flows: list[dict] = []
    # Target IP as source → each dest (weighted)
    for dest, community, weight in DESTS:
        acct_id, acct_name, vpc = random.choice(ACCOUNTS) if dest.startswith("52.") or dest.startswith("3.") else ACCOUNTS[0]
        if dest.startswith("52.") or dest.startswith("3."):
            acct_id, acct_name, vpc = ACCOUNTS[1]
        for i in range(weight):
            flows.append(
                vpcflow_doc(
                    random.randint(1, 14),
                    src=TARGET_IP,
                    dest=dest,
                    account_id=acct_id,
                    account_name=acct_name,
                    vpc_id=vpc,
                    community=community,
                    packets=random.randint(1, 40),
                )
            )
    # Lateral edges inside C1 for label-propagation panel
    for _ in range(15):
        flows.append(
            vpcflow_doc(
                random.randint(1, 14),
                src="10.40.20.11",
                dest="10.40.30.7",
                account_id=ACCOUNTS[0][0],
                account_name=ACCOUNTS[0][1],
                vpc_id=ACCOUNTS[0][2],
                community="C1",
            )
        )
    for _ in range(8):
        flows.append(
            vpcflow_doc(
                random.randint(1, 14),
                src="10.50.1.4",
                dest="52.84.12.9",
                account_id=ACCOUNTS[1][0],
                account_name=ACCOUNTS[1][1],
                vpc_id=ACCOUNTS[1][2],
                community="C2",
            )
        )

    trails: list[dict] = []
    for arn, weight, commands in ARNS:
        acct = "111122223333" if "111122223333" in arn or "SecOps" in arn or "breakglass" in arn or "CIDeploy" in arn or "svc-inventory" in arn else "444455556666"
        if "444455556666" in arn:
            acct = "444455556666"
        for cmd in commands:
            for i in range(max(2, int(weight // 3))):
                trails.append(
                    cloudtrail_doc(
                        random.randint(1, 14),
                        arn=arn,
                        command=cmd,
                        weight=weight,
                        account_id=acct,
                    )
                )

    flow_path = OUT / ndjson_logs('aws_vpcflow')
    trail_path = OUT / ndjson_logs('aws_cloudtrail')
    flow_path.write_text("\n".join(json.dumps(d) for d in flows) + "\n")
    trail_path.write_text("\n".join(json.dumps(d) for d in trails) + "\n")
    print(f"Wrote {len(flows)} vpcflow → {flow_path}")
    print(f"Wrote {len(trails)} cloudtrail → {trail_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
