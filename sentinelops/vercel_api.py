"""Shared HTTP helpers for Vercel Python functions."""
from __future__ import annotations

from http import HTTPStatus
import hashlib
import json
import os
import secrets
import time

from .hosted import HostedStore, RESTError, ingest_remote_records

_rate = {}
_RATE_LIMIT = 60
_RATE_WINDOW = 60


def send_json(handler, payload, status=200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def handle_public_summary(handler):
    try:
        send_json(handler, HostedStore().public_summary())
    except RESTError as exc:
        send_json(handler, {"error": "database unavailable"}, 503)
    except Exception:
        send_json(handler, {"error": "service unavailable"}, 503)


def handle_public_activity(handler):
    try:
        send_json(handler, HostedStore().public_activity(14))
    except RESTError:
        send_json(handler, {"error": "database unavailable"}, 503)
    except Exception:
        send_json(handler, {"error": "service unavailable"}, 503)


def handle_health(handler):
    send_json(handler, {"status": "ok", "product": "SentinelOps", "public_mode": True})


def handle_config(handler):
    send_json(handler, {"public_mode": True, "refresh_seconds": 15})


def _rate_allowed(handler):
    # Vercel instances may scale independently; this is a per-instance safety limit.
    now = time.monotonic()
    forwarded = handler.headers.get("x-forwarded-for", "")
    client = forwarded.split(",", 1)[0].strip() or "unknown"
    recent = [stamp for stamp in _rate.get(client, []) if now - stamp < _RATE_WINDOW]
    if len(recent) >= _RATE_LIMIT:
        _rate[client] = recent
        return False
    recent.append(now)
    _rate[client] = recent
    if len(_rate) > 1000:
        for key in list(_rate):
            if not any(now - stamp < _RATE_WINDOW for stamp in _rate[key]):
                _rate.pop(key, None)
    return True


def handle_ingest(handler):
    # Vercel stores only the SHA-256 digest. The raw collector token stays on
    # the authorized endpoint and is passed directly to the token-verifying DB RPC.
    expected_hash = os.environ.get("SENTINELOPS_INGEST_TOKEN", "").strip().lower()
    supplied = handler.headers.get("Authorization", "")
    if not supplied.startswith("Bearer "):
        return send_json(handler, {"error": "unauthorized"}, 401)
    collector_token = supplied[7:].strip()
    actual_hash = hashlib.sha256(collector_token.encode("utf-8")).hexdigest()
    if (len(collector_token) < 32 or len(expected_hash) != 64 or
            not secrets.compare_digest(actual_hash, expected_hash)):
        return send_json(handler, {"error": "unauthorized"}, 401)
    if not _rate_allowed(handler):
        return send_json(handler, {"error": "rate limit exceeded"}, 429)
    if handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        return send_json(handler, {"error": "application/json required"}, 415)
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return send_json(handler, {"error": "invalid content length"}, 400)
    if length < 1 or length > 128000:
        return send_json(handler, {"error": "request must be between 1 and 128000 bytes"}, 413)
    try:
        payload = json.loads(handler.rfile.read(length))
        if not isinstance(payload, dict):
            return send_json(handler, {"error": "JSON object required"}, 400)
        result = ingest_remote_records(
            payload.get("records"), str(payload.get("source_type", "json")),
            collector_token=collector_token,
        )
        send_json(handler, {
            "accepted": result["ingested"], "skipped": result["skipped"],
            "alerts_created": result["alerts"], "errors": result["errors"],
        }, 202)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        send_json(handler, {"error": str(exc)}, 400)
    except RESTError:
        send_json(handler, {"error": "database unavailable"}, 503)
    except Exception:
        send_json(handler, {"error": "ingestion failed"}, 500)
