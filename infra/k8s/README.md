# Kubernetes manifests

Production deployment target (PRD §55–56): EKS with namespaces

- `agentguard-api`
- `agentguard-security`
- `agentguard-workers`
- `agentguard-data`
- `monitoring`

with HPA, PodDisruptionBudgets, NetworkPolicies, resource limits, and
readiness / liveness probes.

Populated in a later step. Local development uses
[`../docker-compose.yml`](../docker-compose.yml).
