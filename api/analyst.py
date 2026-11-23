"""Private SentinelOps analyst API. Public endpoints remain aggregate-only."""
from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit
import hashlib
import hmac
import json
import os
import secrets
import time

from http.server import BaseHTTPRequestHandler
from sentinelops.hosted import HostedStore, RESTError

SESSION_COOKIE = "sentinelops_analyst"
SESSION_TTL = 8 * 60 * 60
_LOGIN_ATTEMPTS = {}
_LOGIN_WINDOW = 60
_LOGIN_LIMIT = 8


def _json(handler, payload, status=200, cookie=None):
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store, private")
    handler.send_header("Pragma", "no-cache")
    handler.send_header("Vary", "Cookie")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "same-origin")
    handler.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if cookie:
        handler.send_header("Set-Cookie", cookie)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _action(handler):
    values = parse_qs(urlsplit(handler.path).query)
    return values.get("action", [""])[0].strip().lower()


def _cookie_token(handler):
    jar = SimpleCookie()
    try:
        jar.load(handler.headers.get("Cookie", ""))
        return jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else ""
    except Exception:
        return ""


def _session_valid(handler):
    secret = os.environ.get("SENTINELOPS_ANALYST_SESSION_SECRET", "")
    if len(secret) < 32:
        return False
    value = _cookie_token(handler)
    try:
        expires_text, signature = value.split(".", 1)
        expires = int(expires_text)
    except (ValueError, TypeError):
        return False
    if expires < int(time.time()) or expires > int(time.time()) + SESSION_TTL + 60:
        return False
    message = "sentinelops-analyst-v1:" + expires_text
    expected = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return secrets.compare_digest(signature, expected)


def _session_cookie(handler):
    secret = os.environ.get("SENTINELOPS_ANALYST_SESSION_SECRET", "")
    expires = str(int(time.time()) + SESSION_TTL)
    message = "sentinelops-analyst-v1:" + expires
    signature = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    value = expires + "." + signature
    return (SESSION_COOKIE + "=" + value + "; Path=/api/analyst; Max-Age=" +
            str(SESSION_TTL) + "; HttpOnly; Secure; SameSite=Strict")


def _clear_cookie():
    return SESSION_COOKIE + "=; Path=/api/analyst; Max-Age=0; HttpOnly; Secure; SameSite=Strict"


def _origin_ok(handler):
    origin = handler.headers.get("Origin", "")
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
        host = handler.headers.get("Host", "").lower()
        return parsed.scheme == "https" and parsed.netloc.lower() == host
    except Exception:
        return False


def _login_allowed(handler):
    now = time.monotonic()
    client = (handler.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
              or "unknown")
    attempts = [stamp for stamp in _LOGIN_ATTEMPTS.get(client, [])
                if now - stamp < _LOGIN_WINDOW]
    if len(attempts) >= _LOGIN_LIMIT:
        _LOGIN_ATTEMPTS[client] = attempts
        return False
    attempts.append(now)
    _LOGIN_ATTEMPTS[client] = attempts
    if len(_LOGIN_ATTEMPTS) > 1000:
        for key in list(_LOGIN_ATTEMPTS):
            if not any(now - stamp < _LOGIN_WINDOW for stamp in _LOGIN_ATTEMPTS[key]):
                _LOGIN_ATTEMPTS.pop(key, None)
    return True


def _read_body(handler):
    if handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ValueError("application/json required")
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        raise ValueError("invalid content length")
    if length < 1 or length > 8192:
        raise ValueError("request body must be between 1 and 8192 bytes")
    payload = json.loads(handler.rfile.read(length).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON object required")
    return payload


def _number(value, fallback, maximum):
    try:
        return max(1, min(int(value), maximum))
    except (TypeError, ValueError):
        return fallback


def _store():
    return HostedStore()


def _overview(store):
    summary = store.public_summary()
    records, _ = store.db.request(
        "events",
        params={"select": "timestamp", "order": "timestamp.desc", "limit": "1"},
    )
    last_event = records[0] if records else None
    return {"summary": summary, "last_event": last_event}


def _alerts(store, query):
    params = {
        "select": "id,rule_id,title,severity,timestamp,host,entity,description,evidence,status,notes,fingerprint",
        "order": "timestamp.desc",
        "limit": str(_number(query.get("limit", ["100"])[0], 100, 150)),
    }
    severity = query.get("severity", [""])[0].lower()
    status = query.get("status", [""])[0].lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        params["severity"] = "eq." + severity
    if status in {"new", "investigating", "resolved", "false_positive"}:
        params["status"] = "eq." + status
    rows, _ = store.db.request("alerts", params=params)
    return rows or []


def _events(store, query):
    params = {
        "select": "id,timestamp,host,source,product,category,action,outcome,severity,message,source_ip,user,process,event_id,raw_json",
        "order": "timestamp.desc",
        "limit": str(_number(query.get("limit", ["100"])[0], 100, 150)),
    }
    severity = query.get("severity", [""])[0].lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        params["severity"] = "eq." + severity
    rows, _ = store.db.request("events", params=params)
    return rows or []


def _handle_get(handler):
    action = _action(handler)
    if action == "session":
        return _json(handler, {"authenticated": _session_valid(handler)})
    if not _session_valid(handler):
        return _json(handler, {"error": "analyst sign-in required"}, 401)
    try:
        store = _store()
        query = parse_qs(urlsplit(handler.path).query)
        if action == "overview":
            return _json(handler, _overview(store))
        if action == "alerts":
            return _json(handler, _alerts(store, query))
        if action == "events":
            return _json(handler, _events(store, query))
        return _json(handler, {"error": "unknown action"}, 404)
    except RESTError:
        return _json(handler, {"error": "database unavailable"}, 503)
    except Exception:
        return _json(handler, {"error": "service unavailable"}, 503)


def _handle_post(handler):
    if not _origin_ok(handler):
        return _json(handler, {"error": "origin not allowed"}, 403)
    action = _action(handler)
    if action == "logout":
        return _json(handler, {"ok": True}, 200, _clear_cookie())
    try:
        payload = _read_body(handler)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _json(handler, {"error": str(exc)}, 400)

    if action == "login":
        if not _login_allowed(handler):
            return _json(handler, {"error": "too many sign-in attempts; try again in a minute"}, 429)
        configured_hash = os.environ.get("SENTINELOPS_ANALYST_PASSWORD_HASH", "").strip().lower()
        session_secret = os.environ.get("SENTINELOPS_ANALYST_SESSION_SECRET", "")
        if len(configured_hash) != 64 or len(session_secret) < 32:
            return _json(handler, {"error": "analyst access is not configured"}, 503)
        password = payload.get("password", "")
        if not isinstance(password, str) or not 20 <= len(password) <= 256:
            return _json(handler, {"error": "invalid credentials"}, 401)
        supplied_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if not secrets.compare_digest(supplied_hash, configured_hash):
            return _json(handler, {"error": "invalid credentials"}, 401)
        return _json(handler, {"ok": True}, 200, _session_cookie(handler))

    if not _session_valid(handler):
        return _json(handler, {"error": "analyst sign-in required"}, 401)

    if action == "triage":
        try:
            alert_id = int(payload.get("id"))
        except (TypeError, ValueError):
            return _json(handler, {"error": "valid alert id required"}, 400)
        if alert_id <= 0:
            return _json(handler, {"error": "valid alert id required"}, 400)
        status = str(payload.get("status", "")).strip().lower()
        if status not in {"new", "investigating", "resolved", "false_positive"}:
            return _json(handler, {"error": "invalid alert status"}, 400)
        notes = payload.get("notes", "")
        if not isinstance(notes, str) or len(notes) > 4000:
            return _json(handler, {"error": "notes must be 4000 characters or fewer"}, 400)
        try:
            store = _store()
            updated, _ = store.db.request(
                "alerts", method="PATCH",
                params={"id": "eq." + str(alert_id)},
                payload={"status": status, "notes": notes},
                prefer="return=representation",
            )
            if not updated:
                return _json(handler, {"error": "alert not found"}, 404)
            return _json(handler, {"ok": True, "alert": updated[0]})
        except RESTError:
            return _json(handler, {"error": "database unavailable"}, 503)
        except Exception:
            return _json(handler, {"error": "unable to update alert"}, 500)

    return _json(handler, {"error": "unknown action"}, 404)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        _handle_get(self)

    def do_POST(self):
        _handle_post(self)
