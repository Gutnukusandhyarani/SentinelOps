# Normalized event schema

SentinelOps stores one normalized event per successfully parsed input record.

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | ISO-8601 event timestamp; UTC `Z` is preferred |
| `host` | string | Endpoint or system name |
| `source` | string | Log channel, file, or product |
| `product` | string | `linux`, `windows`, or source product |
| `category` | string | Broad event category such as `authentication`, `identity`, `audit` |
| `action` | string | Normalized action such as `login_failed`, `account_created` |
| `outcome` | string | `success`, `failure`, `changed`, or `unknown` |
| `severity` | string | `informational`, `low`, `medium`, `high`, or `critical` |
| `message` | string | Human-readable event message |
| `source_ip` | string | Source address, when present |
| `user` | string | User or account, when present |
| `process` | string | Process or service, when present |
| `event_id` | string | Original event code/ID |
| `raw` | object | Original record or source line for evidence |

Unknown fields are not discarded from the raw record. Timestamps are taken from the event whenever available. A missing timestamp receives the ingestion time; avoid relying on that fallback for forensic timelines.
