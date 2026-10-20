#!/usr/bin/env python3
"""Generate demo badge / Meraki / Teams / presence docs for Employee Safety.

Does not require a live cluster — writes NDJSON under ./out/ by default.
Pass --push to bulk into the cluster from project .env.

Examples:
  python3 generate_employee_safety.py --days 90 --push
  python3 generate_employee_safety.py --days 7 --push
"""

from __future__ import annotations

import argparse
import json
import random
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from data_factories.es import load_env, load_ndjson, require_es, write_ndjson

random.seed(7)

HOUR_WEIGHTS = [3, 5, 8, 10, 9, 6, 4, 3, 3, 3, 3, 3, 2, 2, 2, 1]  # 06:00–21:00


def _office_readers(readers: list[dict]) -> dict[str, list]:
    by_office: dict[str, list] = {}
    for r in readers:
        by_office.setdefault(r.get("office") or "", []).append(r)
    return by_office


def _office_aps(meraki_aps: list[dict]) -> dict[str, list]:
    by_office: dict[str, list] = {}
    for a in meraki_aps:
        by_office.setdefault(a.get("office") or "", []).append(a)
    return by_office


def _badge_doc(ident: dict, reader: dict, ts: datetime, admitted: bool = True) -> dict:
    return {
        "@timestamp": ts.isoformat(),
        "data_stream": {"type": "logs", "dataset": "bx.badge", "namespace": "default"},
        "event": {
            "category": ["physical"],
            "dataset": "bx.badge",
            "kind": "event",
            "type": ["access"],
            "action": "badge_in",
            "outcome": "success" if admitted else "failure",
        },
        "user": {
            "email": ident["email"],
            "first_name": ident["first"],
            "last_name": ident["last"],
            "full_name": f"{ident['last']}, {ident['first']}",
        },
        "observer": {
            "vendor": "Software House",
            "product": "CCure",
            "name": reader.get("inbound_reader"),
        },
        "bx": {
            "badge": {
                "entrance": reader.get("reader_name"),
                "location": reader.get("description"),
                "entry_type": "CardAdmitted" if admitted else "CardRejected",
                "office": reader.get("office"),
                "office_short": reader.get("office_short"),
                "timestamp_raw": ts.strftime("%Y-%m-%d %H:%M:%S"),
            }
        },
        "tags": ["bx-poc", "employee-safety", "badge", "backfill"],
    }


def _meraki_doc(ident: dict, ap: dict, ts: datetime, action: str, status: str) -> dict:
    return {
        "@timestamp": ts.isoformat(),
        "data_stream": {"type": "logs", "dataset": "bx.meraki", "namespace": "default"},
        "event": {
            "category": ["network", "session"],
            "dataset": "bx.meraki",
            "kind": "event",
            "type": ["connection"],
            "action": action,
        },
        "source": {"mac": ident.get("mac_address")},
        "user": {"email": ident["email"]},
        "observer": {"name": ap.get("ap_name")},
        "bx": {
            "meraki": {
                "access_point": ap.get("ap_name"),
                "floor": ap.get("floor"),
                "office": ap.get("office"),
                "office_short": ap.get("office_short"),
                "building_status": status,
            }
        },
        "tags": ["bx-poc", "employee-safety", "meraki", "backfill"],
    }


def _teams_doc(ident: dict, ts: datetime) -> dict:
    return {
        "@timestamp": ts.isoformat(),
        "data_stream": {"type": "logs", "dataset": "bx.o365", "namespace": "default"},
        "event": {
            "category": ["collaboration"],
            "dataset": "bx.o365.teams",
            "kind": "event",
            "type": ["info"],
            "action": random.choice(
                ["MessageSent", "CallAccepted", "ChannelCreated", "TeamsSessionStarted"]
            ),
        },
        "user": {"email": ident["email"], "name": ident["email"]},
        "tags": ["bx-poc", "employee-safety", "teams", "backfill"],
    }


def gen_backfill(
    identities: list[dict],
    readers: list[dict],
    meraki_aps: list[dict],
    days: int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Generate ~3 months of weekday-biased badge / Meraki / Teams activity."""
    now = datetime.now(timezone.utc)
    by_readers = _office_readers(readers)
    by_aps = _office_aps(meraki_aps)

    # Stable attendance propensity per employee
    profiles = []
    for ident in identities:
        profiles.append(
            {
                "ident": ident,
                "office_rate": random.uniform(0.25, 0.85),  # fraction of weekdays in office
                "remote_teams": random.random() < 0.7,
                "after_hours_rate": random.uniform(0.02, 0.12),
            }
        )

    badge: list[dict] = []
    meraki_docs: list[dict] = []
    teams: list[dict] = []

    for day_offset in range(days, -1, -1):
        day = (now - timedelta(days=day_offset)).date()
        weekday = day.weekday()  # 0=Mon
        is_weekend = weekday >= 5

        for prof in profiles:
            ident = prof["ident"]
            office = ident.get("home_office") or ""
            rdrs = by_readers.get(office) or readers[:20]
            aps = by_aps.get(office) or meraki_aps[:20]
            if not rdrs or not aps:
                continue

            # Weekends: rare badge / meraki
            attend_p = prof["office_rate"] * (0.08 if is_weekend else 1.0)
            in_office = random.random() < attend_p

            if in_office:
                # Arrival
                hour = random.choices(range(6, 22), weights=HOUR_WEIGHTS)[0]
                if random.random() < prof["after_hours_rate"]:
                    hour = random.choice([0, 1, 2, 3, 21, 22, 23])
                arrive = datetime(
                    day.year,
                    day.month,
                    day.day,
                    hour,
                    random.randint(0, 59),
                    random.randint(0, 59),
                    tzinfo=timezone.utc,
                )
                reader = random.choice(rdrs)
                admitted = random.random() > 0.04
                badge.append(_badge_doc(ident, reader, arrive, admitted))

                # Optional mid-day / exit swipe
                if admitted and random.random() < 0.45:
                    exit_ts = arrive + timedelta(hours=random.randint(3, 10), minutes=random.randint(0, 59))
                    if exit_ts.date() == day:
                        badge.append(_badge_doc(ident, random.choice(rdrs), exit_ts, True))

                # Meraki associate near arrival
                if admitted and random.random() < 0.75:
                    ap = random.choice(aps)
                    connect_ts = arrive + timedelta(minutes=random.randint(1, 25))
                    meraki_docs.append(_meraki_doc(ident, ap, connect_ts, "connect", "In Building"))
                    if random.random() < 0.55:
                        disc = connect_ts + timedelta(hours=random.uniform(0.5, 9))
                        if disc <= now:
                            age_min = (now - disc).total_seconds() / 60
                            status = "Recently Left" if age_min <= 30 else "Left Building"
                            meraki_docs.append(
                                _meraki_doc(ident, ap, disc, "disconnect", status)
                            )

            # Teams activity (office or remote)
            if prof["remote_teams"] and random.random() < (0.55 if not is_weekend else 0.15):
                ts = datetime(
                    day.year,
                    day.month,
                    day.day,
                    random.randint(8, 20),
                    random.randint(0, 59),
                    random.randint(0, 59),
                    tzinfo=timezone.utc,
                )
                if ts <= now:
                    teams.append(_teams_doc(ident, ts))
                    # burst a few more same day
                    if random.random() < 0.3:
                        for _ in range(random.randint(1, 3)):
                            burst = ts + timedelta(minutes=random.randint(5, 240))
                            if burst <= now and burst.date() == day:
                                teams.append(_teams_doc(ident, burst))

    return badge, meraki_docs, teams


def build_presence(
    identities, badge, meraki, teams, lookback_hours: int = 12
) -> list[dict]:
    now = datetime.now(timezone.utc)
    lookback = now - timedelta(hours=lookback_hours)

    # Index latest events by email for speed on large backfills
    def latest_map(docs: list[dict]) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for d in docs:
            email = (d.get("user") or {}).get("email")
            if not email:
                continue
            prev = latest.get(email)
            if prev is None or d["@timestamp"] > prev["@timestamp"]:
                latest[email] = d
        return latest

    badge_latest = latest_map(badge)
    meraki_latest = latest_map(meraki)
    teams_latest = latest_map(teams)

    def parse(ts: str | None):
        return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None

    out = []
    for ident in identities:
        email = ident["email"]
        b = badge_latest.get(email)
        m = meraki_latest.get(email)
        t = teams_latest.get(email)

        b_ts = parse(b["@timestamp"]) if b else None
        m_ts = parse(m["@timestamp"]) if m else None
        t_ts = parse(t["@timestamp"]) if t else None

        present = (b_ts is not None and b_ts >= lookback) or (
            m_ts is not None and m_ts >= lookback
        )
        active = present or (t_ts is not None and t_ts >= lookback)

        swiped = (b or {}).get("bx", {}).get("badge", {}).get("office")
        meraki_office = (m or {}).get("bx", {}).get("meraki", {}).get("office")
        if b_ts and m_ts:
            last_office = swiped if b_ts >= m_ts else meraki_office
        else:
            last_office = swiped or meraki_office

        short = None
        if b and b_ts and (not m_ts or b_ts >= m_ts):
            short = b["bx"]["badge"].get("office_short")
        elif m:
            short = m["bx"]["meraki"].get("office_short")

        out.append(
            {
                "@timestamp": now.isoformat(),
                "data_stream": {
                    "type": "metrics",
                    "dataset": "bx.employee_presence",
                    "namespace": "default",
                },
                "event": {"dataset": "bx.employee_presence", "kind": "metric"},
                "user": {
                    "email": email,
                    "first_name": ident["first"],
                    "last_name": ident["last"],
                    "full_name": f"{ident['last']}, {ident['first']}",
                },
                "bx": {
                    "presence": {
                        "present": present,
                        "active": active,
                        "lookback_hours": lookback_hours,
                        "last_office": last_office,
                        "last_office_short": short,
                        "swiped_office": swiped,
                        "meraki_office": meraki_office,
                        "badge_last": b_ts.isoformat() if b_ts else None,
                        "meraki_last": m_ts.isoformat() if m_ts else None,
                        "teams_last": t_ts.isoformat() if t_ts else None,
                        "badge_entrance": (b or {})
                        .get("bx", {})
                        .get("badge", {})
                        .get("entrance"),
                        "meraki_ap": (m or {})
                        .get("bx", {})
                        .get("meraki", {})
                        .get("access_point"),
                        "meraki_floor": (m or {})
                        .get("bx", {})
                        .get("meraki", {})
                        .get("floor"),
                        "building_status": (m or {})
                        .get("bx", {})
                        .get("meraki", {})
                        .get("building_status"),
                        "teams_last_action": (t or {}).get("event", {}).get("action"),
                        "bunit": ident.get("bunit"),
                        "employee_category": ident.get("category"),
                    }
                },
                "tags": ["bx-poc", "employee-safety", "presence"],
            }
        )
    return out


def push_bulk_chunked(
    es_url: str, api_key: str, index: str, docs: list[dict], chunk_size: int = 2000
) -> None:
    total = 0
    for i in range(0, len(docs), chunk_size):
        chunk = docs[i : i + chunk_size]
        lines: list[str] = []
        for d in chunk:
            lines.append(json.dumps({"create": {}}))
            lines.append(json.dumps(d))
        body = ("\n".join(lines) + "\n").encode()
        req = urllib.request.Request(
            f"{es_url.rstrip('/')}/{index}/_bulk?refresh=false",
            data=body,
            headers={
                "Authorization": f"ApiKey {api_key}",
                "Content-Type": "application/x-ndjson",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                result = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise SystemExit(f"bulk HTTP {e.code} on {index}: {e.read()[:400]}") from e
        if result.get("errors"):
            bad = [
                it
                for it in result.get("items", [])
                if it.get("create", {}).get("error") or it.get("index", {}).get("error")
            ]
            raise SystemExit(f"bulk errors on {index}: {bad[:2]}")
        total += len(chunk)
        print(f"  pushed {total}/{len(docs)} → {index}")

    # final refresh
    req = urllib.request.Request(
        f"{es_url.rstrip('/')}/{index}/_refresh",
        headers={"Authorization": f"ApiKey {api_key}", "Accept": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=120).read()
    print(f"pushed {len(docs)} → {index} (refreshed)")


def ensure_data_stream(es_url: str, api_key: str, name: str) -> None:
    req = urllib.request.Request(
        f"{es_url.rstrip('/')}/_data_stream/{name}",
        data=b"{}",
        headers={
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    try:
        urllib.request.urlopen(req, timeout=60).read()
    except urllib.error.HTTPError:
        pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--push", action="store_true", help="Bulk into cluster from .env")
    ap.add_argument("--lookback", type=int, default=12)
    ap.add_argument(
        "--days",
        type=int,
        default=90,
        help="Days of historical activity to generate (default 90 ≈ 3 months)",
    )
    ap.add_argument("--chunk-size", type=int, default=2000)
    ap.add_argument(
        "--lookups",
        type=Path,
        help="Directory with bx-identities / readers / meraki NDJSON lookups",
    )
    ap.add_argument(
        "--package-root",
        type=Path,
        help="Employee Safety package root (lookups/ sibling); alternative to --lookups",
    )
    ap.add_argument("--out", type=Path, default=Path("out"), help="NDJSON output directory")
    ap.add_argument("--env-file", type=Path, help=".env with ELASTICSEARCH_URL / API_KEY")
    args = ap.parse_args(argv)

    if args.lookups:
        look = args.lookups
    elif args.package_root:
        look = args.package_root / "lookups"
    else:
        raise SystemExit("Pass --lookups DIR or --package-root DIR (employee_safety package)")

    identities = load_ndjson(look / "bx-identities.ndjson")
    readers = load_ndjson(look / "bx-physical-access-readers.ndjson")
    meraki = load_ndjson(look / "bx-meraki-inventory.ndjson")

    print(f"Generating {args.days} days of activity for {len(identities)} identities…")
    badge, meraki_docs, teams = gen_backfill(identities, readers, meraki, days=args.days)
    presence = build_presence(
        identities, badge, meraki_docs, teams, lookback_hours=args.lookback
    )

    print(
        f"counts: badge={len(badge)} meraki={len(meraki_docs)} "
        f"teams={len(teams)} presence={len(presence)}"
    )

    out = args.out
    write_ndjson(out / "logs-bx.badge.ndjson", badge)
    write_ndjson(out / "logs-bx.meraki.ndjson", meraki_docs)
    write_ndjson(out / "logs-bx.o365.ndjson", teams)
    write_ndjson(out / "metrics-bx.employee_presence.ndjson", presence)

    if args.push:
        env = load_env(args.env_file) if args.env_file else load_env()
        url, key = require_es(env)
        for idx, docs in [
            ("logs-bx.badge-default", badge),
            ("logs-bx.meraki-default", meraki_docs),
            ("logs-bx.o365-default", teams),
            ("metrics-bx.employee_presence-default", presence),
        ]:
            ensure_data_stream(url, key, idx)
            push_bulk_chunked(url, key, idx, docs, chunk_size=args.chunk_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
