"""Built-in and imported-rule detection. Rules are intentionally read-only."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

BUILTIN_RULES = [
    {"id":"AUTH-001","title":"Repeated SSH authentication failures","severity":"high",
     "description":"Five or more SSH failures from the same source IP within ten minutes.",
     "tags":["attack.credential-access","attack.t1110"],"kind":"ssh_burst"},
    {"id":"WIN-001","title":"Local or domain account created","severity":"medium",
     "description":"A Windows account creation event was observed.","kind":"action",
     "action":"account_created","tags":["attack.persistence","attack.t1136"]},
    {"id":"WIN-002","title":"Privileged group membership changed","severity":"high",
     "description":"A Windows security group membership change was observed.","kind":"action",
     "action":"group_member_added","tags":["attack.persistence","attack.t1098"]},
    {"id":"WIN-003","title":"Windows audit log cleared","severity":"critical",
     "description":"A Windows event indicates that the Security audit log was cleared.","kind":"action",
     "action":"audit_log_cleared","tags":["attack.defense-evasion","attack.t1070.001"]},
    {"id":"WIN-004","title":"Service installation observed","severity":"high",
     "description":"A Windows service installation event was observed; verify the change is authorized.","kind":"action",
     "action":"service_installed","tags":["attack.persistence","attack.t1543.003"]},
    {"id":"FIM-001","title":"File integrity baseline changed","severity":"medium",
     "description":"A watched file was added, modified or removed since the last baseline.","kind":"action",
     "action":"file_integrity_changed","tags":["attack.impact"]},
]

def _parse_time(value: str) -> datetime:
    try:
        parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
        if parsed.tzinfo is None:
            parsed=parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def _make_alert(rule, event, entity, evidence, fingerprint):
    return {
        "rule_id":rule["id"], "title":rule["title"], "severity":rule["severity"],
        "timestamp":event.timestamp, "host":event.host, "entity":entity,
        "description":rule["description"], "evidence":evidence,
        "fingerprint":fingerprint,
    }

def detect_builtin(event, store):
    alerts=[]
    for rule in BUILTIN_RULES:
        if rule["kind"]=="action" and event.action==rule["action"]:
            entity=event.user or event.host
            fp=f"{rule['id']}|{entity}|{event.event_id or event.timestamp}"
            alerts.append(_make_alert(rule,event,entity,{"message":event.message,"event_id":event.event_id,
                              "tags":rule.get("tags",[])},fp))
        elif rule["kind"]=="ssh_burst" and event.action=="login_failed" and event.source_ip:
            now=_parse_time(event.timestamp)
            since=(now-timedelta(minutes=10)).isoformat()
            count=store.count_recent_failed_logins(event.source_ip, since)
            if count>=5:
                bucket=int(now.timestamp()//900)
                fp=f"{rule['id']}|{event.source_ip}|{bucket}"
                alerts.append(_make_alert(rule,event,event.source_ip,{"failed_attempts_10m":count,
                    "source_ip":event.source_ip,"tags":rule.get("tags",[])},fp))
    return alerts

def _get_path(record, dotted):
    current=record
    for part in dotted.split("."):
        if isinstance(current,dict):
            current=current.get(part)
        else:
            return None
    return current

def _match_condition(actual, operator, expected):
    if operator=="equals":
        values=expected if isinstance(expected,list) else [expected]
        return any(str(actual).casefold()==str(v).casefold() for v in values)
    if operator=="contains":
        values=expected if isinstance(expected,list) else [expected]
        return any(str(v).casefold() in str(actual).casefold() for v in values)
    if operator=="in":
        values=expected if isinstance(expected,list) else [expected]
        return str(actual).casefold() in {str(v).casefold() for v in values}
    if operator=="exists":
        return actual is not None and actual!=""
    return False

def load_imported_rules(path: str | Path) -> list[dict]:
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data,list):
        raise ValueError("SentinelOps rule pack must be a JSON array")
    checked=[]
    for rule in data:
        if not isinstance(rule,dict) or not rule.get("id") or not rule.get("conditions"):
            raise ValueError("each imported rule needs id and conditions")
        if not all(c.get("field") and c.get("operator") in {"equals","contains","in","exists"} for c in rule["conditions"]):
            raise ValueError(f"unsupported condition in rule {rule.get('id')}")
        checked.append(rule)
    return checked

def detect_imported(event, rules):
    record=event.to_dict()
    alerts=[]
    for rule in rules:
        if all(_match_condition(_get_path(record,c["field"]),c["operator"],c.get("value"))
               for c in rule["conditions"]):
            entity=event.user or event.source_ip or event.host
            fp=f"IMPORTED|{rule['id']}|{entity}|{event.event_id or event.timestamp}"
            alerts.append({
                "rule_id":rule["id"],"title":rule.get("title",rule["id"]),
                "severity":rule.get("level","medium"),"timestamp":event.timestamp,
                "host":event.host,"entity":entity,"description":rule.get("description","Imported Sigma rule match"),
                "evidence":{"event":record,"tags":rule.get("tags",[])},
                "fingerprint":fp,
            })
    return alerts
