# data_factories

Shared Elastic synthetic data factories, grouped by the data they produce.

## Install

Public repo: [katelawrencegupta-elastic/data_factories](https://github.com/katelawrencegupta-elastic/data_factories).

```bash
# from GitHub (other machines / CI)
pip install "git+https://github.com/katelawrencegupta-elastic/data_factories.git"

# optional: requests for demo ensure-* helpers that still live in demos
pip install "data-factories[demos] @ git+https://github.com/katelawrencegupta-elastic/data_factories.git"

# local editable checkout
git clone https://github.com/katelawrencegupta-elastic/data_factories.git
cd data_factories
pip install -e .
# or: pip install -e ".[demos]"
```

In a consumer `requirements.txt`:

```text
data-factories @ git+https://github.com/katelawrencegupta-elastic/data_factories.git
```

## Layout

```text
src/data_factories/
  es.py              ES REST + NDJSON helpers
  common.py          Beats-style doc builders, time/count helpers
  service_common.py  microservice telemetry helpers (labels, data_stream meta)
  service_streams.py microservice data stream names

  cloud_billing/     aws_billing, aws_billing_cur, azure_billing, gcp_billing,
                     ess_billing, ess_billing_credits
  cloud_metrics/     aws_ec2_metrics, aws_usage (RDS, Lambda, S3 storage, MQ,
                     CloudWatch usage, kubeletstats)
  cloud_audit/       aws_cloudtrail, aws_guardduty, aws_s3access, azure_activity,
                     gcp_audit, aws_blast_radius (CloudTrail + VPC flow)
  llm/               openai, anthropic, bedrock, azure_openai, vertexai, elastic_ai
  apm/               service_traces, service_deps, llm_traces
  kubernetes/        pods_events (pod metrics, k8s events), hosts_nodes
  app_logs/          service_logs, orchestrator
  network/           dns_hunt, egress_exfil
  threat_intel/      ioc_hunt, sync_hunt_iocs
  identity/          hdsi_user, employee_safety (badge, Meraki, Teams presence)

  world/             scenario models that drive the generators
                     cloud_org, cloud_scenarios, cloud_costs, llm_catalog,
                     llm_traffic, microservices, runtime
  presets/           generator selections demos use
                     cost_modeling (NAMED, select(scope)), o11y_workshop (GENERATORS, select)
```

## Consumers

| Consumer | How it uses this package |
|----------|--------------------------|
| [`demos/cloud&llm_cost_modeling`](../demos/cloud&llm_cost_modeling) (+ `variants/*`) | `src/generators` + `src/world` shims → `presets.cost_modeling` and the domain modules |
| [`skills/…/splunk-xml-to-kibana`](../skills/skills/splunk-xml-to-kibana) | Skill docs point new factories here |

## CLIs

```bash
df-hdsi-user --out ./out
df-employee-safety --lookups /path/to/employee_safety/lookups --out ./out
df-dns-hunt --hunt-ips /path/to/hunt_task_ips.json --env-file /path/to/.env
df-sync-hunt-iocs --hunt-ips ... --env-file ...
df-ioc-hunt --out ./out
df-egress-exfil --out ./out
df-aws-blast-radius --out ./out
```

Or: `python -m data_factories.identity.hdsi_user`.

Generated NDJSON under `out/` is gitignored — regenerate before `setup_*.py` bulk.

## World config

World models read their config from the calling demo (`src.config.WORLD_CONFIG`) or from env:

- `FINOPS_WORLD_CONFIG`, `FINOPS_ROOT` — `world.cloud_org` and friends
- `GEV_WORLD_CONFIG` — `world.microservices`
