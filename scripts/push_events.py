#!/usr/bin/env python3
"""Push newly appended authorized endpoint log records to a SentinelOps HTTPS service.

The bearer token is read only from SENTINELOPS_INGEST_TOKEN; it is never a CLI argument.
Use only with systems and log files you own or are explicitly authorized to monitor.
"""
from __future__ import annotations
import argparse
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse


def parse_record(line: str, source_type: str):
    if source_type == "ssh":
        return line.rstrip("\r\n")
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return None
    return item if isinstance(item, dict) else None


def send_batch(base_url: str, token: str, source_type: str, records: list) -> dict:
    url = base_url.rstrip("/") + "/api/ingest"
    body = json.dumps({"source_type": source_type, "records": records}, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SentinelOps-Authorized-Collector/1.0",
    })
    with urlopen(request, timeout=20) as response:
        if response.status not in (200, 202):
            raise RuntimeError(f"Unexpected collector response: HTTP {response.status}")
        return json.loads(response.read(16000).decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Send appended log records to a SentinelOps hosted dashboard")
    parser.add_argument("--file", required=True, help="Local log or JSONL export to follow")
    parser.add_argument("--type", choices=("ssh", "json", "windows"), default="ssh", dest="source_type")
    parser.add_argument("--url", required=True, help="Your SentinelOps HTTPS service base URL")
    parser.add_argument("--poll", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--batch-size", type=int, default=10, help="Records per upload (1-10)")
    parser.add_argument("--from-start", action="store_true", help="Upload existing file contents before following")
    args = parser.parse_args()

    token = os.environ.get("SENTINELOPS_INGEST_TOKEN", "")
    if len(token) < 32:
        parser.error("Set SENTINELOPS_INGEST_TOKEN to the secret configured on the hosted service (at least 32 characters).")
    if not 1 <= args.batch_size <= 10:
        parser.error("--batch-size must be between 1 and 10")
    if args.poll < 0.2 or args.poll > 60:
        parser.error("--poll must be between 0.2 and 60 seconds")
    parsed = urlparse(args.url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        parser.error("Use the HTTPS URL of your own hosted SentinelOps service")
    path = Path(args.file).expanduser().resolve()
    if not path.is_file():
        parser.error(f"Log file not found: {path}")

    def flush_batch(batch: list) -> int:
        while batch:
            try:
                result = send_batch(args.url, token, args.source_type, batch)
                print(f"Uploaded: accepted={result.get('accepted', 0)}, alerts={result.get('alerts_created', 0)}, skipped={result.get('skipped', 0)}, errors={result.get('errors', 0)}")
                batch.clear()
                return 0
            except HTTPError as exc:
                if exc.code in (401, 403):
                    print("Authentication failed. Stop and verify the service token; the token is not printed.")
                    return 2
                if exc.code == 429 or exc.code >= 500:
                    print(f"Upload deferred: HTTP {exc.code}; retrying the buffered batch.")
                    time.sleep(max(2.0, args.poll))
                    continue
                print(f"The service rejected this batch with HTTP {exc.code}. Stop and review the collector input and service logs.")
                return 3
            except (URLError, TimeoutError, OSError) as exc:
                print(f"Upload deferred: {type(exc).__name__}; retrying the buffered batch.")
                time.sleep(max(2.0, args.poll))
        return 0

    with path.open("r", encoding="utf-8", errors="replace") as stream:
        if not args.from_start:
            stream.seek(0, os.SEEK_END)
        identity = (path.stat().st_dev, path.stat().st_ino)
        batch: list = []
        print(f"Following {path.name}; sending to the configured HTTPS SentinelOps service.")
        print("Only aggregate counts are shown on the public dashboard. Press Ctrl+C to stop.")
        try:
            while True:
                line = stream.readline()
                if line:
                    record = parse_record(line, args.source_type)
                    if record is None:
                        continue
                    batch.append(record)
                    if len(batch) >= args.batch_size:
                        code = flush_batch(batch)
                        if code:
                            return code
                    continue

                if batch:
                    code = flush_batch(batch)
                    if code:
                        return code

                try:
                    current = path.stat()
                    new_identity = (current.st_dev, current.st_ino)
                    if new_identity != identity or current.st_size < stream.tell():
                        stream.close()
                        stream = path.open("r", encoding="utf-8", errors="replace")
                        identity = new_identity
                except FileNotFoundError:
                    pass
                time.sleep(args.poll)
        except KeyboardInterrupt:
            if batch:
                try:
                    result = send_batch(args.url, token, args.source_type, batch)
                    print(f"Final upload: accepted={result.get('accepted', 0)}, alerts={result.get('alerts_created', 0)}")
                except Exception:
                    print("Some buffered records could not be sent. They were not written to this program's output.")
            print("Collector stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
