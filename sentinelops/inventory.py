"""Generate a minimal CycloneDX-compatible inventory of installed Python packages."""
from __future__ import annotations
import json
import platform
import re
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

def _normalize_name(name):
    return re.sub(r"[-_.]+","-",name).lower()

def export_python_inventory(output="data/python-sbom.json") -> dict:
    components=[]
    distributions=sorted(metadata.distributions(),key=lambda d:(d.metadata.get("Name") or "").lower())
    for dist in distributions:
        name=dist.metadata.get("Name") or "unknown"
        version=dist.version or "unknown"
        components.append({
            "type":"library","name":name,"version":version,
            "purl":f"pkg:pypi/{_normalize_name(name)}@{version}"
        })
    bom={
        "bomFormat":"CycloneDX","specVersion":"1.5","version":1,
        "serialNumber":f"urn:uuid:{uuid.uuid4()}",
        "metadata":{"timestamp":datetime.now(timezone.utc).isoformat(),
                    "tools":[{"vendor":"SentinelOps","name":"sentinelops","version":"1.0.0"}],
                    "component":{"type":"operating-system","name":platform.system(),
                                 "version":platform.release()}},
        "components":components
    }
    path=Path(output); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(bom,indent=2)+"\n",encoding="utf-8")
    return {"output":str(path),"components":len(components),"format":"CycloneDX 1.5"}
