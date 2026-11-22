"""Read-only baseline checks. Findings are review prompts, not compliance certifications."""
from __future__ import annotations
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

def _read_ssh_values(path: Path) -> dict:
    values={}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        match=re.match(r"(?i)^(PermitRootLogin|PasswordAuthentication)\s+(\S+)",line)
        if match:
            values[match.group(1).lower()]=match.group(2).lower()
    return values

def _firewall_status():
    """Return a best-effort status using read-only platform commands."""
    if shutil.which("ufw"):
        try:
            output=subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=5).stdout.lower()
            if "status: active" in output: return "pass","UFW reports active"
            if "status: inactive" in output: return "review","UFW reports inactive"
        except Exception: pass
    if shutil.which("firewall-cmd"):
        try:
            result=subprocess.run(["firewall-cmd","--state"],capture_output=True,text=True,timeout=5)
            if result.returncode==0 and result.stdout.strip()=="running":
                return "pass","firewalld reports running"
            if result.returncode==0:
                return "review",f"firewalld reports {result.stdout.strip() or 'not running'}"
        except Exception: pass
    if platform.system()=="Windows" and shutil.which("powershell"):
        return "review","Use scripts/audit_windows_posture.ps1 to inspect Windows Firewall and Defender state."
    return "review","Firewall state could not be determined with available read-only tools."

def run_posture_audit(ssh_config="/etc/ssh/sshd_config") -> list[dict]:
    checks=[]
    if platform.system()=="Linux":
        path=Path(ssh_config).expanduser()
        values=_read_ssh_values(path)
        if path.is_file():
            root=values.get("permitrootlogin")
            checks.append({
                "id":"LINUX-SSH-001","title":"SSH root login setting",
                "status":"pass" if root=="no" else "review",
                "finding":f"PermitRootLogin is {root or 'not explicitly set'}",
                "recommendation":"Review whether direct root SSH login is required; prefer named accounts and controlled privilege elevation.",
                "evidence":str(path),"reference":"CIS-style configuration review"
            })
            password=values.get("passwordauthentication")
            checks.append({
                "id":"LINUX-SSH-002","title":"SSH password authentication setting",
                "status":"pass" if password=="no" else "review",
                "finding":f"PasswordAuthentication is {password or 'not explicitly set'}",
                "recommendation":"Review the organization's approved authentication policy; use strong, managed authentication.",
                "evidence":str(path),"reference":"CIS-style configuration review"
            })
            mode=path.stat().st_mode & 0o777
            safe=(mode & 0o022)==0
            checks.append({
                "id":"LINUX-SSH-003","title":"SSH configuration file permissions",
                "status":"pass" if safe else "review",
                "finding":f"Permission mode is {oct(mode)}",
                "recommendation":"Ensure the SSH configuration is not writable by group or other users.",
                "evidence":str(path),"reference":"Local file-permission baseline"
            })
        else:
            checks.append({
                "id":"LINUX-SSH-000","title":"SSH configuration availability","status":"not_applicable",
                "finding":f"No SSH config found at {path}",
                "recommendation":"Supply the correct SSH config path if this host uses OpenSSH.",
                "evidence":str(path),"reference":"Local configuration review"
            })
    else:
        checks.append({
            "id":"HOST-SSH-000","title":"Linux SSH settings","status":"not_applicable",
            "finding":f"Native parser is scoped to Linux; detected {platform.system()}",
            "recommendation":"On Windows, run scripts/audit_windows_posture.ps1 for read-only Defender and firewall checks.",
            "evidence":platform.system(),"reference":"Platform-specific baseline"
        })
    status,finding=_firewall_status()
    checks.append({
        "id":"HOST-FW-001","title":"Host firewall status","status":status,
        "finding":finding,"recommendation":"Confirm that an approved host firewall is enabled and managed.",
        "evidence":platform.system(),"reference":"Host security baseline"
    })
    return checks
