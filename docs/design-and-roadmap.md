# Design notes and feature gap closure

## Source review

The supplied Wazuh repository describes an endpoint agent/manager model with log analysis, file-integrity monitoring, vulnerability detection, configuration assessment, incident response, compliance and cloud/container integrations.

The supplied Sigma repository describes generic YAML detection rules, threat-hunting/emerging-threat/compliance rule categories, metadata/ATT&CK tags, rule review and regression testing.

SentinelOps narrows the scope to an educational local endpoint-monitoring lab. It does not attempt to reproduce Wazuh's distributed agent, indexer, production scale or full vulnerability/configuration modules.

## Additional features added for this project

1. **Common normalized event schema** — data from Linux SSH logs and Windows Event Log exports share one storage and detection path.
2. **Runnable local-first architecture** — standard-library Python, SQLite, localhost dashboard, no external service dependency.
3. **Practical collection paths** — native Linux auth-log parsing, Windows read-only event exporter, and generic JSONL import.
4. **Alert lifecycle** — new, investigating, resolved and false-positive statuses with analyst notes.
5. **Evidence retention** — raw event attached to the normalized event and alert evidence.
6. **File-integrity checks** — SHA-256 baseline, additions/modifications/deletions; read-only monitoring.
7. **Rule interoperability** — import a constrained SigmaForge JSON export with explicit validation instead of pretending to support every Sigma feature.
8. **Tests and CI** — parser, detector and ingestion tests run without a production SIEM.

## Intentionally not implemented

- Distributed authenticated agents, mutual TLS and remote fleet management.
- Full endpoint software inventory across all operating systems or an internal vulnerability feed; the optional dependency audit focuses on the active Python environment.
- Automated containment, process termination, account lockout or firewall changes.
- Formal compliance certification, full CIS benchmark coverage, multi-tenant RBAC, high availability, horizontal scaling and production-grade retention.
- Complete Sigma specification or arbitrary backend query translation.

These are not hidden or simulated as if they exist. A production implementation would require a threat model, secure agent enrollment, access control, auditability, deployment hardening and much broader integration testing.
