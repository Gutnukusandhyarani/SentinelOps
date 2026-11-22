# Demo walkthrough

1. Initialize: `python -m sentinelops init`.
2. Ingest the included test data: `python -m sentinelops ingest --file samples/sample_events.jsonl --type json`.
3. Start the UI: `python -m sentinelops serve`.
4. Show the repeated-authentication alert and Windows account-creation alert.
5. Open an alert's **Review** action, change it to `investigating`, add notes, and refresh.
6. Export real local records from Windows or ingest a Linux SSH auth log.
7. Create a small watched folder, baseline it, change a text file, and run the FIM check.
8. Export supported detection rules from SigmaForge and ingest them with `--rules`.

Important: the bundled events are synthetic test fixtures. To demonstrate real endpoint telemetry, use the OS-specific collection steps in the main README and identify the source and time window in your presentation.
