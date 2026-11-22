"""Command line interface."""
import argparse
from pathlib import Path
import json
from .store import Store
from .ingest import ingest_file
from .integrity import baseline,check
from .server import serve
from .posture import run_posture_audit
from .inventory import export_python_inventory
from .vulnerability import run_python_vulnerability_audit
from .agent import follow_file

def main():
    parser=argparse.ArgumentParser(prog="sentinelops",description="Local defensive endpoint monitoring and SIEM lab")
    parser.add_argument("--db",default="data/sentinelops.db",help="SQLite database path")
    sub=parser.add_subparsers(dest="command",required=True)
    sub.add_parser("init",help="initialize the local database")
    ing=sub.add_parser("ingest",help="ingest logs from a file")
    ing.add_argument("--file",required=True); ing.add_argument("--type",choices=["auto","ssh","windows","json"],default="auto")
    ing.add_argument("--rules",help="SentinelOps JSON rule pack exported by SigmaForge")
    monitor=sub.add_parser("monitor",help="follow a local log file and ingest new events")
    monitor.add_argument("--file",required=True); monitor.add_argument("--type",choices=["auto","ssh","windows","json"],default="auto")
    monitor.add_argument("--rules",help="SentinelOps JSON rule pack exported by SigmaForge")
    monitor.add_argument("--from-start",action="store_true",help="read existing file contents before following")
    monitor.add_argument("--poll",type=float,default=1.0)
    web=sub.add_parser("serve",help="start the local dashboard")
    web.add_argument("--host",default="127.0.0.1"); web.add_argument("--port",type=int,default=8787)
    sub.add_parser("summary",help="show database totals")
    posture=sub.add_parser("posture",help="run read-only local configuration baseline checks")
    posture.add_argument("--ssh-config",default="/etc/ssh/sshd_config")
    inv=sub.add_parser("inventory",help="export installed Python packages as CycloneDX SBOM")
    inv.add_argument("--output",default="data/python-sbom.json")
    vuln=sub.add_parser("vuln-audit",help="run optional pip-audit against the current Python environment")
    vuln.add_argument("--output",default="reports/pip-audit.json")
    fim=sub.add_parser("integrity",help="file-integrity monitoring")
    fim_sub=fim.add_subparsers(dest="fim_action",required=True)
    b=fim_sub.add_parser("baseline"); b.add_argument("--path",required=True)
    c=fim_sub.add_parser("check"); c.add_argument("--path",required=True)
    args=parser.parse_args()

    if args.command=="init":
        store=Store(args.db); store.close(); print(f"Initialized {args.db}")
    elif args.command=="ingest":
        result=ingest_file(args.file,args.type,args.db,args.rules)
        print(json.dumps(result,indent=2))
    elif args.command=="monitor":
        try:
            result=follow_file(args.file,args.type,args.db,args.rules,args.from_start,args.poll)
            print(json.dumps(result,indent=2))
        except KeyboardInterrupt:
            pass
    elif args.command=="posture":
        results=run_posture_audit(args.ssh_config)
        print(json.dumps(results,indent=2))
        print(f"\nChecks: {len(results)}")
    elif args.command=="inventory":
        print(json.dumps(export_python_inventory(args.output),indent=2))
    elif args.command=="vuln-audit":
        try:
            print(json.dumps(run_python_vulnerability_audit(args.output,args.db),indent=2))
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif args.command=="serve":
        serve(args.host,args.port,args.db)
    elif args.command=="summary":
        store=Store(args.db)
        try: print(json.dumps(store.summary(),indent=2))
        finally: store.close()
    elif args.command=="integrity":
        if args.fim_action=="baseline":
            count=baseline(args.path,args.db); print(f"Baselined {count} files.")
        else:
            changes=check(args.path,args.db); print(json.dumps(changes,indent=2))
            if not changes: print("No file changes detected.")
