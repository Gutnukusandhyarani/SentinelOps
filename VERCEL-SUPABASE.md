# Deploy SentinelOps on Vercel + Supabase

This hosted adapter is separate from the local SQLite workflow. Local commands continue to use SQLite; Vercel uses Supabase Postgres through the Supabase REST API. Vercel's function filesystem is not used for persistence.

## 1. Supabase project

The configured database project is `sentinelops` (Mumbai region). It already contains private `events`, `alerts`, and `fim_baseline` tables. Row Level Security is enabled and no browser-facing policies are configured.

## 2. Vercel environment variables

In Vercel → project `sentinelops` → Settings → Environment Variables, add these for **Production and Preview**:

| Name | Value |
|---|---|
| `SUPABASE_URL` | Project URL from Supabase → Project Settings / API |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side secret key from Supabase API keys |
| `SENTINELOPS_INGEST_TOKEN` | A random secret with at least 32 characters |

Do not put any of these values in `web/`, a `NEXT_PUBLIC_` variable, GitHub, screenshots, or chat. The service-role key bypasses RLS, so it must remain server-side only. If Supabase offers a modern secret key for server-side use, it can be used instead of the legacy service-role key if it is compatible with the project's Data API.

After adding variables, redeploy so the functions receive them.

## 3. Vercel project

Connect `Gutnukusandhyarani/SentinelOps` to the Vercel project named `sentinelops`. Set the Git production branch to `main`; the implementation is currently isolated on `vercel-supabase` for review. The preview branch should deploy automatically when pushed. Do not merge into `main` until the preview has been tested.

The repository's `vercel.json` publishes `web/` as the static site and maps Python functions under `api/`.

## 4. Smoke tests

After the preview deployment is ready, verify:

- `/api/health` returns `status: ok` and `public_mode: true`.
- `/api/config` returns public mode.
- `/api/public/summary` returns aggregate counts only.
- `/api/public/activity` returns daily event/alert totals only.
- `/api/ingest` rejects requests without the bearer token.

Do not treat zero counts as a failure: it means no authorized endpoint events have been ingested yet. The bundled sample data remains synthetic and is not automatically uploaded to the hosted database.

## 5. Authorized endpoint collection

Set `SENTINELOPS_INGEST_TOKEN` as a private environment variable on a machine you own or are authorized to monitor. Use the existing `scripts/push_events.py` with the Vercel deployment URL. The collector reads a local log and sends bounded batches over HTTPS. Never send credentials, private keys, customer records, or logs from systems you are not authorized to monitor.

## API security boundary

The hosted dashboard exposes aggregate-only summary/activity routes. Detailed events, alert evidence, and analyst triage are intentionally not exposed publicly. Ingestion requires the bearer token. Rate limiting is per serverless instance and should not be treated as a global abuse-control system. This project is a learning/portfolio lab, not a production SOC platform.
