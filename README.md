# data_factories

Shared Elastic synthetic data factories:

- **Blackstone** — NDJSON generators for Splunk→Kibana dashboard POCs (DNS hunt, employee safety, HDSI, IOC hunt, egress exfil, AWS blast radius)
- **FinOps** — ELK Co cloud & LLM cost-modeling generators + world model
- **GEV** — Elastic Co. observability workshop generators + world model

## Install

```bash
pip install -e /Users/klg/Documents/GItHub/data_factories
# optional: requests for demo ensure-* helpers that still live in demos
pip install -e "/Users/klg/Documents/GItHub/data_factories[demos]"
```

Consumers (Blackstone wrappers, FinOps/GEV demos) expect this editable install on `PYTHONPATH`.

## Blackstone CLI

```bash
df-bx-hdsi-user --out ./out
df-bx-employee-safety --lookups /path/to/employee_safety/lookups --out ./out
df-bx-dns-hunt --hunt-ips /path/to/hunt_task_ips.json --env-file /path/to/.env
```

Or: `python -m data_factories.blackstone.hdsi_user`.

Generated NDJSON under `out/` is gitignored — regenerate before `setup_*.py` bulk.

## FinOps / GEV

Demos keep CLI, setup, sink, and `config/world.yaml`. They import generators via thin `src.generators` / `src.world` shims that re-export from this package.

## Layout

```text
src/data_factories/
  es.py              # REST + NDJSON helpers
  blackstone/        # NDJSON factories + catalog.yaml
  finops/            # generators/ + world/
  gev/               # generators/ + world/
```
