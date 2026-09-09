from __future__ import annotations
import json, sys
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass(frozen=True)
class Anomaly:
    rule_id: str
    severity: str
    source: str
    destination: str
    message: str

WEIGHTS={"critical":10,"high":7,"medium":4,"low":1}
ADMIN_PORTS={22,3389,5985,5986}

def key(flow): return f"{flow['source']}->{flow['destination']}"

def detect(baseline: dict, flows: list[dict]) -> list[Anomaly]:
    findings=[]
    approved=baseline.get("communications", {})
    known_external=set(baseline.get("known_external_destinations", []))
    for f in flows:
        pair=key(f); port=int(f["port"]); count=int(f.get("connections",1))
        entry=approved.get(pair)
        if entry is None:
            sev="high" if port in ADMIN_PORTS else "medium"
            findings.append(Anomaly("NET-01",sev,f["source"],f["destination"],f"First-seen communication pair on port {port}."))
        else:
            if port not in entry.get("ports",[]):
                findings.append(Anomaly("NET-02","high" if port in ADMIN_PORTS else "medium",f["source"],f["destination"],f"Port {port} is outside the approved baseline."))
            threshold=max(10,int(entry.get("avg_connections",1))*3)
            if count>threshold:
                findings.append(Anomaly("NET-03","medium",f["source"],f["destination"],f"Connection count {count} exceeds baseline threshold {threshold}."))
            if f.get("source_zone") and f.get("destination_zone") and [f["source_zone"],f["destination_zone"]] not in entry.get("zone_paths",[]):
                findings.append(Anomaly("NET-04","high",f["source"],f["destination"],"Observed zone transition is not approved."))
        if f.get("destination_type")=="external" and f["destination"] not in known_external:
            findings.append(Anomaly("NET-05","medium",f["source"],f["destination"],"First-seen external destination."))
    return findings

def score(findings): return min(100,sum(WEIGHTS[x.severity] for x in findings))

def main(baseline_path, flows_path):
    baseline=json.loads(Path(baseline_path).read_text())
    flows=json.loads(Path(flows_path).read_text())
    findings=detect(baseline,flows)
    print(json.dumps({"risk_score":score(findings),"findings":[asdict(x) for x in findings]},indent=2))
    return 0

if __name__=="__main__":
    if len(sys.argv)!=3: raise SystemExit("usage: python src/anomaly_engine.py <baseline.json> <flows.json>")
    raise SystemExit(main(sys.argv[1],sys.argv[2]))
