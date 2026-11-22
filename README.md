# SentinelOps — Local Endpoint Monitoring & SIEM Lab

**A defensive-security portfolio project inspired by the capabilities of Wazuh.** SentinelOps collects local security telemetry, normalizes events, detects suspicious patterns, tracks file-integrity changes, and provides a small analyst dashboard. It is an original implementation; it does not contain Wazuh source code or claim to be affiliated with Wazuh.

> **Designed to run locally.** No cloud account, external SIEM, API key, or paid service is required. The core application uses Python's standard library. Real endpoint logs can be ingested from a machine you own or are authorized to monitor. Bundled sample events are clearly labeled as test data.

## What it does

| Capability | Implementation |
|---|---|
| Log collection | Linux `auth.log` / `secure`, JSONL exports, and Windows Event Log export |
| Event normalization | Common event schema with host, source, category, action, outcome, user, source IP, event ID and raw evidence |
| Detection | Built-in rules for repeated SSH failures, account creation, privileged-group changes, audit-log clearing and service installation |
| Alert workflow | Severity, evidence, timestamps, analyst status and notes |
| File integrity monitoring | SHA-256 baseline and drift checks; does not modify watched files |
| Configuration posture | Read-only Linux SSH/firewall baseline checks plus a Windows Defender/Firewall export script |
| Software inventory | CycloneDX 1.5 inventory of installed Python packages |
| Vulnerability assessment | Optional `pip-audit` integration; findings are added to SQLite and the alert queue |
| Dashboard | Local web dashboard with KPIs, alert/event tables and triage controls |
| Storage | SQLite database, with no external database server |
| Interoperability | Imports SentinelOps rule-pack JSON exported by the companion SigmaForge project |
| Reliability | Unit tests, JSONL fixtures, input validation and structured logging |

## Quick start

Requires Python 3.10 or newer.

### 1. Create a virtual environment (recommended)

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate
```

No third-party Python package is required.

### 2. Initialize the database

```bash
python -m sentinelops init
```

### 3. Run a labelled sample

```bash
python -m sentinelops ingest --file samples/sample_events.jsonl --type json
```

The sample data is deliberately synthetic and is only a smoke-test fixture. It is not represented as live telemetry.

### 4. Start the dashboard

```bash
python -m sentinelops serve
```

Open `http://127.0.0.1:8787` in your browser. The server binds to localhost by default.

## Ingest real endpoint logs

### Linux

On a Linux machine you own or administer, use one of the available authentication log files:

```bash
python -m sentinelops ingest --file /var/log/auth.log --type ssh
# Some distributions use:
python -m sentinelops ingest --file /var/log/secure --type ssh
```

Reading these files may require appropriate permissions. Start with read-only access; do not change system logging or security settings just to run this lab.

For journald-based systems, export a bounded time window to a text file and ingest it:

```bash
journalctl -u ssh --since "today" --no-pager > ssh-auth.log
python -m sentinelops ingest --file ssh-auth.log --type ssh
```

### Windows

Run PowerShell as an account that is permitted to read the relevant event log. The collector is read-only:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_windows_events.ps1 `
  -OutputPath .\data\windows-security.jsonl -MaxEvents 500
```

Then import the export:

```powershell
python -m sentinelops ingest --file .\data\windows-security.jsonl --type windows
```

The script reads selected Security/System event IDs. Windows may require elevated permissions to read the Security log. Use it only on your own or authorized machine.

### Follow a live log file

For continuous local collection from a log file, use `monitor`. It starts at the end of the file by default and processes new lines as they arrive:

```bash
python -m sentinelops monitor --file /var/log/auth.log --type ssh
```

To process existing lines first, add `--from-start`. Stop the collector with `Ctrl+C`. The watcher handles basic file replacement/rotation; it is a lightweight local collector, not a remotely managed production agent.

### Generic JSONL

You can ingest JSON Lines exported by an EDR, SIEM, application, or lab system:

```bash
python -m sentinelops ingest --file path/to/events.jsonl --type json
```

Each line should be a JSON object. SentinelOps preserves the original record under `raw` and normalizes common fields. See `docs/event-schema.md`.

## Configuration posture assessment

Run read-only checks on Linux:

```bash
python -m sentinelops posture
# Override the SSH configuration file path when necessary:
python -m sentinelops posture --ssh-config /path/to/sshd_config
```

On Windows, run the read-only PowerShell audit:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\audit_windows_posture.ps1
```

The Windows script writes `windows-posture.json` in the current directory. These checks are review prompts, not a security certification or guarantee of compliance.

## Software inventory and vulnerability assessment

Export installed Python packages as a CycloneDX 1.5 SBOM:

```bash
python -m sentinelops inventory --output data/python-sbom.json
```

For an optional known-vulnerability audit of the active Python environment, install `pip-audit` and run:

```bash
python -m pip install pip-audit
python -m sentinelops vuln-audit
```

This optional audit can contact package/advisory services to retrieve current vulnerability information. It does not install, upgrade or remove packages. Findings are written to `reports/pip-audit.json` and added to the SentinelOps alert queue. The main monitoring application remains dependency-free.

## File integrity monitoring

Create a baseline:

```bash
python -m sentinelops integrity baseline --path ./example-watch
```

Check for additions, modifications, or deletions:

```bash
python -m sentinelops integrity check --path ./example-watch
```

A baseline is a point-in-time reference. A change is not automatically malicious; review the path, change window and expected administrative activity.

## Import SigmaForge detections

In the companion repository, export supported Sigma rules:

```bash
python -m sigmaforge export --rules rules --format sentinelops --output ../sentinelops-project/rules/imported_sigma.json
```

Then run SentinelOps with that ruleset:

```bash
python -m sentinelops ingest --file samples/sample_events.jsonl --type json \
  --rules rules/imported_sigma.json
```

SentinelOps loads simple, explicitly supported field-match rules from the export. Complex Sigma conditions are not silently approximated; SigmaForge reports unsupported constructs during export.

## CLI reference

```text
python -m sentinelops init
python -m sentinelops ingest --file FILE --type auto|ssh|windows|json [--rules FILE]
python -m sentinelops monitor --file FILE --type auto|ssh|windows|json [--from-start]
python -m sentinelops serve [--host 127.0.0.1] [--port 8787]
python -m sentinelops summary
python -m sentinelops posture [--ssh-config PATH]
python -m sentinelops inventory [--output FILE]
python -m sentinelops vuln-audit [--output FILE]
python -m sentinelops integrity baseline --path DIR
python -m sentinelops integrity check --path DIR
```

`--type auto` detects JSONL where possible and otherwise parses common SSH authentication messages.

## Architecture

```text
Linux auth logs ──────┐
Windows JSON export ──┼──> Collectors / parsers ──> Normalized event schema
Generic JSONL ────────┘                                  │
                                                        ▼
                                               Detection engine
                                          built-in + imported rule pack
                                                        │
                                  ┌─────────────────────┴──────────┐
                                  ▼                                ▼
                              SQLite DB                      Alert records
                                  │                                │
                                  └──────────────> Local dashboard ◄┘

Watched paths ──> SHA-256 baseline/check ──> File-integrity events
```

## Security and operational boundaries

- Localhost binding is the default. Do not expose the development server to an untrusted network.
- The Windows collector only reads event records; it does not clear logs, change policy or execute response actions.
- File-integrity monitoring reads files and stores hashes; it does not alter watched content.
- Alert triage is manual. The project intentionally does not block accounts, kill processes or modify firewall rules.
- Keep imported logs private. Real logs may contain usernames, IP addresses, hostnames and other personal or organizational data.
- This is a learning/portfolio SIEM, not a replacement for a production EDR, SIEM, or incident-response process.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Repository layout

```text
sentinelops-project/
├── sentinelops/          # Normalization, storage, detection, API and CLI
├── web/                  # Local analyst dashboard
├── rules/                # Built-in and imported rule packs
├── samples/              # Clearly labelled synthetic test data
├── scripts/              # Read-only Windows event and posture exporters
├── tests/                # Unit and integration tests
└── docs/                 # Event schema, design, limitations and demo guide
```

## Credits and relationship to upstream projects

SentinelOps was independently written as a learning project after reviewing the high-level feature areas documented in [Wazuh](https://github.com/wazuh/wazuh) and the generic detection-rule approach used by [Sigma](https://github.com/SigmaHQ/sigma). No Wazuh source code, SigmaHQ rule files, logos, or other upstream assets are bundled here. Wazuh and Sigma are separate projects maintained by their respective communities; this repository is not endorsed by either.
