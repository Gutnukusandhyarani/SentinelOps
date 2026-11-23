# SentinelOps — Vercel + Supabase hosted dashboard

This hosted deployment uses Vercel for the static dashboard and Python API, with Supabase Postgres for persistent telemetry. The local SQLite workflow remains independent.

## Current hosted architecture

- Vercel static site: `web/`
- Serverless API: `api/`
- Supabase tables: `public.events`, `public.alerts`, `public.fim_baseline`
- Public dashboard routes: `/api/public_summary` and `/api/public_activity`
- Authenticated collector route: `POST /api/ingest`

The public dashboard can display aggregate counts only. It does not expose raw events, usernames, IP addresses, hostnames, process names, messages, or alert evidence.

## Supabase access model

The telemetry tables remain private with RLS enabled and no anonymous table grants. The dashboard reads only through two fixed aggregate functions:

- `public.sentinelops_public_summary()`
- `public.sentinelops_public_activity(days)`

Collector writes and detection lookups use token-verifying server-side RPC functions:

- `public.sentinelops_ingest_event(token, event)`
- `public.sentinelops_ingest_alert(token, alert)`
- `public.sentinelops_count_failed_logins(token, source_ip, since)`

The collector token is stored only as a SHA-256 hash in the non-exposed `private.sentinelops_secrets` schema. Do not grant browser users direct table access. The migration is tracked in `supabase/migrations/`.

## Vercel environment variables

The Vercel project `sentinelops` needs these values in Preview and Production:

| Variable | Purpose |
|---|---|
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side Supabase Data API key configured for this deployment |
| `SENTINELOPS_INGEST_TOKEN` | Random private bearer token, at least 32 characters |

These values must remain server-side. Never add them to `web/`, a `NEXT_PUBLIC_` variable, source control, screenshots, or public messages. The public API key alone cannot read or write the private telemetry tables; the RPCs enforce the dashboard and collector boundaries.

After changing environment variables, redeploy the Vercel project so the functions receive the updated values.

## API smoke tests

- `GET /api/health` returns health status.
- `GET /api/config` returns hosted public mode.
- `GET /api/public_summary` returns aggregate counters only.
- `GET /api/public_activity` returns daily totals only.
- `POST /api/ingest` requires the bearer token and accepts bounded JSON batches.

A zero count is not a dashboard error. It means the database has no endpoint telemetry yet. Synthetic fixtures in `samples/` are never uploaded automatically or represented as real endpoint evidence.

## Authorized endpoint collection

On a machine you own or are authorized to monitor:

1. Set `SENTINELOPS_INGEST_TOKEN` as a private environment variable to the same value configured in Vercel.
2. Prepare a JSONL or SSH authentication log using the existing read-only collector/export scripts.
3. Run `scripts/push_events.py` with the HTTPS Vercel deployment URL.

Example for a JSONL export:

```powershell
$env:SENTINELOPS_INGEST_TOKEN = "<the private token configured in Vercel>"
python .\scripts\push_events.py --file .\data\windows-security.jsonl --type windows --url https://sentinelops-git-vercel-supabase-sandhya-6e9f.vercel.app --from-start
```

The collector sends bounded batches over HTTPS. Do not send credentials, private keys, customer records, or logs from systems you are not authorized to monitor. The collector runs on the endpoint; Vercel cannot read local machine logs by itself.

## Operational limits

This is a defensive learning and portfolio project, not a production SOC platform. Rate limiting is per serverless instance, and public dashboard endpoints intentionally omit sensitive event details. Keep real endpoint logs private and follow your organization's monitoring rules.
