# Known limitations

- Linux parsing targets common OpenSSH authentication messages. Distribution-specific variations may be skipped.
- Windows Event Log export depends on `Get-WinEvent`, event-log permissions and the localized message rendering provided by Windows.
- JSONL ingestion expects one JSON object per line and supports common aliases, not every vendor schema.
- The repeated SSH failure rule is a simple 5-in-10-minute threshold, not a statistical baseline or correlation engine.
- The imported rule-pack adapter supports conjunctions of basic field tests; see SigmaForge export limitations.
- SQLite is suitable for a local lab, not a high-volume centralized SIEM.
- The dashboard has no authentication and must stay on localhost.
- File integrity checks compare against a saved baseline; an analyst must decide whether a change is authorized.
