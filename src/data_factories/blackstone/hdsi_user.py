#!/usr/bin/env python3
"""Synthetic HDSI user-investigation data: identity lookup + CIM-style streams."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEMO_USER = "alex.analyst"
DEMO_EMAIL = "alex.analyst@blackstone.com"


def _ts(hours_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("out"), help="NDJSON output directory")
    args = ap.parse_args(argv)
    OUT = args.out
    OUT.mkdir(parents=True, exist_ok=True)

    identities = [
        {
            "identity": DEMO_USER,
            "normalized_identity": DEMO_EMAIL,
            "email": DEMO_EMAIL,
            "first": "Alex",
            "last": "Analyst",
            "bunit": "BXTI Security Operations",
            "category": "employee",
            "managedBy": "manager.demo@blackstone.com",
            "work_city": "New York",
            "phone": "+1-212-555-0142",
            "startDate": "2021-03-15",
            "endDate": "",
            "identity_tag": "privileged",
        },
        {
            "identity": "jdoe",
            "normalized_identity": "jdoe@blackstone.com",
            "email": "jdoe@blackstone.com",
            "first": "Jamie",
            "last": "Doe",
            "bunit": "Corporate IT",
            "category": "employee",
            "managedBy": "manager.demo@blackstone.com",
            "work_city": "London",
            "phone": "",
            "startDate": "2019-08-01",
            "endDate": "",
            "identity_tag": "standard",
        },
    ]

    tickets = [
        {
            "@timestamp": _ts(5),
            "ticket": {"id": "INC0012345", "subject": "Suspicious login review", "status": "open"},
            "user": {"name": DEMO_USER},
            "tags": ["bx-poc", "hdsi-user"],
        },
        {
            "@timestamp": _ts(30),
            "ticket": {"id": "INC0011988", "subject": "Laptop reimage", "status": "closed"},
            "user": {"name": DEMO_USER},
            "tags": ["bx-poc", "hdsi-user"],
        },
    ]

    notables = [
        {
            "@timestamp": _ts(2),
            "notable": {
                "id": "N-8821",
                "name": "Multiple Failed Authentications",
                "severity": "medium",
                "urgency": "medium",
            },
            "user": {"name": DEMO_USER},
            "tags": ["bx-poc", "hdsi-user"],
        },
        {
            "@timestamp": _ts(8),
            "notable": {
                "id": "N-8790",
                "name": "Endpoint Process - Encoded PowerShell",
                "severity": "high",
                "urgency": "high",
            },
            "user": {"name": DEMO_USER},
            "tags": ["bx-poc", "hdsi-user"],
        },
    ]

    auth = []
    for country, ip, n in [
        ("United States", "203.0.113.40", 6),
        ("United Kingdom", "198.51.100.22", 3),
        ("Germany", "203.0.113.90", 2),
        ("Private noise", "10.40.1.5", 4),  # filtered by ext-ip stand-in
    ]:
        for i in range(n):
            auth.append(
                {
                    "@timestamp": _ts(random.uniform(1, 20)),
                    "data_stream": {"type": "logs", "dataset": "bx.hdsi_auth", "namespace": "default"},
                    "event": {
                        "category": ["authentication"],
                        "action": "success",
                        "dataset": "bx.hdsi_auth",
                        "kind": "event",
                    },
                    "user": {"name": DEMO_USER},
                    "source": {"ip": ip, "geo": {"country_name": country}},
                    "bx": {"hdsi": {"datamodel": "Authentication"}},
                    "tags": ["bx-poc", "hdsi-user", "authentication"],
                }
            )

    malware = [
        {
            "@timestamp": _ts(12),
            "data_stream": {"type": "logs", "dataset": "bx.hdsi_malware", "namespace": "default"},
            "event": {"category": ["malware"], "action": "blocked", "dataset": "bx.hdsi_malware"},
            "user": {"name": DEMO_USER},
            "host": {"name": "WS-ALEX-01"},
            "file": {"name": "invoice.iso"},
            "threat": {
                "software": {"name": "Trojan.Generic"},
                "indicator": {"name": "Trojan.Generic"},
            },
            "bx": {
                "hdsi": {
                    "datamodel": "Malware",
                    "category": "Trojan",
                    "severity": "high",
                    "signature": "Trojan.GenericKD",
                }
            },
            "tags": ["bx-poc", "hdsi-user", "malware"],
        }
    ]

    procs = []
    for parent, proc in [
        ("explorer.exe", "powershell.exe -enc JABzAD0A"),
        ("cmd.exe", "cmd.exe /c whoami"),
        ("svchost.exe", "powershell.exe Get-Process"),
    ]:
        for _ in range(3):
            procs.append(
                {
                    "@timestamp": _ts(random.uniform(0.5, 18)),
                    "data_stream": {"type": "logs", "dataset": "bx.hdsi_endpoint", "namespace": "default"},
                    "event": {"category": ["process"], "action": "start", "dataset": "bx.hdsi_endpoint"},
                    "user": {"name": DEMO_USER},
                    "host": {"name": "WS-ALEX-01"},
                    "process": {
                        "name": proc.split()[0],
                        "command_line": proc,
                        "parent": {"name": parent, "command_line": parent},
                    },
                    "bx": {"hdsi": {"datamodel": "Endpoint.Processes"}},
                    "tags": ["bx-poc", "hdsi-user", "endpoint"],
                }
            )

    windows = []
    for logon_type, src in [(2, "10.32.8.10"), (10, "203.0.113.40"), (3, "10.32.8.44")]:
        windows.append(
            {
                "@timestamp": _ts(random.uniform(1, 15)),
                "data_stream": {"type": "logs", "dataset": "bx.hdsi_windows", "namespace": "default"},
                "event": {
                    "category": ["authentication"],
                    "action": "logged-in",
                    "code": "4624",
                    "dataset": "bx.hdsi_windows",
                },
                "user": {"name": DEMO_USER},
                "source": {"ip": src},
                "destination": {"ip": "10.32.8.50"},
                "host": {"name": "WS-ALEX-01"},
                "winlog": {
                    "event_id": 4624,
                    "logon": {"type": str(logon_type), "process_name": "User32.dll"},
                },
                "bx": {"hdsi": {"macro": "hdsi_windows_security", "logon_type": logon_type}},
                "tags": ["bx-poc", "hdsi-user", "windows"],
            }
        )

    change = []
    for action, as_src in [("modified", False), ("created", False), ("modified", True)]:
        change.append(
            {
                "@timestamp": _ts(random.uniform(2, 22)),
                "data_stream": {"type": "logs", "dataset": "bx.hdsi_change", "namespace": "default"},
                "event": {"category": ["change"], "action": action, "dataset": "bx.hdsi_change"},
                "user": {"name": DEMO_USER if not as_src else "svc-automation"},
                "source": {"user": {"name": DEMO_USER if as_src else "admin"}},
                "host": {"name": "DC01"},
                "bx": {
                    "hdsi": {
                        "macro": "cim_Change_indexes",
                        "role": "src_user" if as_src else "user",
                    }
                },
                "message": f"Account {action} for {DEMO_USER}",
                "tags": ["bx-poc", "hdsi-user", "change"],
            }
        )

    # footprint rows derived from streams (also write compact index)
    footprint = [
        {"@timestamp": _ts(1), "user": {"name": DEMO_USER}, "data_stream": {"dataset": ds}, "bx": {"index_alias": idx}, "tags": ["bx-poc", "hdsi-user", "footprint"]}
        for ds, idx in [
            ("bx.hdsi_auth", "bx_sec_okta_prod"),
            ("bx.hdsi_windows", "bx_sec_windows_prod"),
            ("bx.hdsi_endpoint", "bx_sec_crowdstrike_prod"),
            ("bx.hdsi_malware", "bx_sec_crowdstrike_prod"),
            ("bx.hdsi_change", "bx_app_azure_prod"),
        ]
    ]

    def write(name: str, rows: list) -> None:
        path = OUT / name
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        print(f"Wrote {len(rows)} → {path.name}")

    write("bx-lookup-identity-expanded.ndjson", identities)
    write("bx-hdsi-tickets.ndjson", tickets)
    write("bx-hdsi-notables.ndjson", notables)
    write("logs-bx.hdsi_auth.ndjson", auth)
    write("logs-bx.hdsi_malware.ndjson", malware)
    write("logs-bx.hdsi_endpoint.ndjson", procs)
    write("logs-bx.hdsi_windows.ndjson", windows)
    write("logs-bx.hdsi_change.ndjson", change)
    write("logs-bx.hdsi_footprint.ndjson", footprint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
