# Hosted SentinelOps deployment notes

## Trust boundaries

```text
Authorized endpoint log file
       |
       v
local push_events.py (HTTPS + bearer token)
       |
       v
Render web service (/api/ingest)
       |  validate + normalize + detect
       v
SQLite on attached persistent disk
       |
       v
Public dashboard: aggregate-only endpoints
```

The public web view must never receive raw event records. Only the agent holds the ingest token. The token is a service secret and must not be placed in JavaScript, GitHub, the portfolio repository, or a screenshot. Rotate it immediately if it is disclosed.

## Current boundaries

- One configured bearer token is shared by the collector for this portfolio deployment; it is not per-device identity or multi-tenant auth.
- Use only one Render service instance with the attached disk. Do not scale it horizontally.
- Public API returns only aggregate counts and day buckets.
- Detailed event and alert APIs plus triage are disabled in public mode.
- A compromised collector token could inject false telemetry; rotate the secret if the collector is lost or the token is exposed.
- Event evidence is stored in SQLite; use a dedicated lab endpoint and do not upload private workplace data.
- This implementation does not provide production retention, multi-tenant access, per-device revocation or a managed incident-response workflow.
