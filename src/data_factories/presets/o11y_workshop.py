"""Microservice observability workshop preset: GENERATORS registry and select(scope)."""
from data_factories.apm import service_deps as apm_deps
from data_factories.apm import service_traces as apm
from data_factories.app_logs import orchestrator
from data_factories.app_logs import service_logs as app_logs
from data_factories.kubernetes import hosts_nodes as infra
from data_factories.kubernetes import pods_events as k8s

GENERATORS = {
    "orchestrator": orchestrator,
    "apm": apm,
    "apm_deps": apm_deps,
    "k8s": k8s,
    "infra": infra,
    "app_logs": app_logs,
}


def select(scope: str = "all"):
    if scope == "all":
        return list(GENERATORS.values())
    if scope == "traces":
        return [apm, apm_deps]
    if scope == "k8s":
        # Pods + hosts + nodes + APM runtime metrics
        return [k8s, infra]
    if scope not in GENERATORS:
        raise SystemExit(
            f"unknown scope {scope}; choose all|traces|{'|'.join(GENERATORS)}"
        )
    return [GENERATORS[scope]]
