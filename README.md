# data_factories

Shared Elastic synthetic data factories, grouped by the data they produce.
Customer-neutral by default — no hard-coded tenant brands.

## Install

Public repo: [katelawrencegupta-elastic/data_factories](https://github.com/katelawrencegupta-elastic/data_factories).

```bash
# from GitHub (other machines / CI)
pip install "git+https://github.com/katelawrencegupta-elastic/data_factories.git"

# local editable checkout
git clone https://github.com/katelawrencegupta-elastic/data_factories.git
cd data_factories
pip install -e .
```

In a consumer `requirements.txt`:

```text
data-factories @ git+https://github.com/katelawrencegupta-elastic/data_factories.git
```

Requires Python ≥ 3.11. Core deps: `PyYAML`, `requests`.

## Tenant naming (portability)

All stream names, tags, lookup filenames, and custom document fields use a
**tenant slug** (default `customer`):

| Kind | Example (default) |
|------|-------------------|
| POC tag | `customer-poc` |
| Dataset | `customer.hdsi_auth` |
| Data stream | `logs-customer.badge-default` |
| NDJSON out | `logs-customer.ioc_hunt.ndjson` |
| Lookup file | `customer-identities.ndjson` |
| Nested custom field | `customer: { … }` |

Override with env:

```bash
export DATA_FACTORIES_TENANT=acme   # → logs-acme.*, acme-poc, …
df-ioc-hunt --out ./out
```

## Layout

```text
src/data_factories/
  tenant.py          TENANT slug + naming helpers
  es.py              ES REST + NDJSON helpers
  common.py          Beats-style doc builders, time/count helpers
  service_common.py  microservice telemetry helpers
  service_streams.py microservice data stream names

  cloud_billing/  cloud_metrics/  cloud_audit/  llm/  apm/
  kubernetes/   app_logs/  network/  threat_intel/  identity/
  world/             scenario models (need WORLD_CONFIG env when used)
  presets/           generator selections for demos
```

## CLIs (local NDJSON)

These write under `--out` and do **not** need a live cluster:

```bash
df-hdsi-user --out ./out
df-ioc-hunt --out ./out
df-egress-exfil --out ./out
df-aws-blast-radius --out ./out
```

These need extra inputs and/or ES credentials:

```bash
df-employee-safety --lookups /path/to/lookups --out ./out
# lookups must include: customer-identities.ndjson,
#   customer-physical-access-readers.ndjson, customer-meraki-inventory.ndjson
# (names follow DATA_FACTORIES_TENANT)

df-dns-hunt --hunt-ips ./hunt_task_ips.json --env-file ./.env
df-sync-hunt-iocs --hunt-ips ./hunt_task_ips.json --env-file ./.env
```

Or: `python -m data_factories.identity.hdsi_user`.

Generated NDJSON under `out/` is gitignored — regenerate before bulk ingest.

## World config

FinOps / observability world models read config from env (or an optional calling
demo’s `src.config`):

- `FINOPS_WORLD_CONFIG` / `FINOPS_ROOT` (or `DEMO_ROOT`) — `world.cloud_org` and friends
- `GEV_WORLD_CONFIG` — `world.microservices`

## License

Apache-2.0
