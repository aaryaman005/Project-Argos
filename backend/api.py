from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import json
import os
import uvicorn

from models import Incident
from main import SOCEngine
from ingestion.stream import AlertSimulator
from response.executor import ResponseExecutor

# Resolve audit path to root of Project-Argos (Argos/audit_records.json)
# /backend/api.py -> /backend/ -> /root/
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_PATH = os.path.join(base_dir, "audit_records.json")

app = FastAPI(title="Project Argos - Autonomous SOC Engine")
engine = SOCEngine()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditEntryIn(BaseModel):
    actor: str = "Operator"
    action: str
    target: str
    outcome: str
    incident_id: Optional[str] = None
    alert_type: Optional[str] = None

@app.get("/incidents")
async def get_incidents():
    """Returns all incidents (active and resolved) from the engine."""
    incidents = engine.get_all_incidents()
    
    # Simple serialization helper
    def serialize_inc(i):
        return {
            "id": i.id,
            "timestamp": i.alert.timestamp.isoformat(),
            "type": i.alert.type,
            "source": i.alert.source,
            "severity": i.alert.severity.name.lower(),
            "status": i.status,
            "priority_score": round(i.priority_score, 2),
            "asset_criticality": i.alert.asset_criticality,
            "ioc_confidence": i.alert.ioc_confidence,
            "description": i.alert.description,
            "target": i.alert.source, # source is the host in our mock
        }

    return {
        "status": "success",
        "count": len(incidents),
        "incidents": [serialize_inc(i) for i in incidents[::-1]] # Newest first
    }

@app.post("/simulate")
async def simulate_alerts(count: int = 5):
    for alert in AlertSimulator.get_stream(count):
        engine.process_new_alert(alert)
    return {"message": f"Started simulation of {count} alerts"}

@app.post("/run-cycle")
async def run_cycle():
    if not engine.queue.is_empty():
        engine.run_cycle()
        return {"status": "executed"}
    return {"status": "queue_empty"}

@app.post("/simulate-one")
async def simulate_one_alert():
    """Generate a single alert, process it through the full SOC pipeline, and return detailed results."""
    import time
    start = time.time()

    # 1. Generate alert
    alert = AlertSimulator.generate_alert()

    # 2. Process through engine (triage, blast radius, candidate actions, queue)
    enriched = engine.triage.enrich_alert(alert)
    blast_radius = engine.topology.calculate_blast_radius(enriched.source)
    incident = Incident(alert=enriched, blast_radius=blast_radius)
    actions = engine._generate_candidate_actions(incident)
    incident.recommended_actions = actions
    engine.queue.push(incident)

    # 3. Run cycle (optimize + execute + audit)
    popped = engine.queue.pop()
    popped.final_actions = engine.optimizer.select_optimal_actions(popped.recommended_actions)
    ResponseExecutor.execute_incident_plan(popped)
    engine.audit.log_incident(popped)

    elapsed = time.time() - start

    # Serialize everything
    def action_to_dict(a):
        return {
            "id": a.id,
            "type": a.type.value,
            "target": a.target,
            "security_gain": a.security_gain,
            "operational_cost": a.operational_cost,
            "business_risk": a.business_risk,
            "status": a.status
        }

    return {
        "incident_id": popped.id,
        "alert": {
            "id": popped.alert.id,
            "type": popped.alert.type,
            "source": popped.alert.source,
            "severity": popped.alert.severity.name,
            "description": popped.alert.description,
            "ioc_confidence": round(popped.alert.ioc_confidence, 3),
            "asset_criticality": round(popped.alert.asset_criticality, 3),
            "timestamp": popped.alert.timestamp.isoformat(),
        },
        "priority_score": round(popped.priority_score, 2),
        "blast_radius": round(popped.blast_radius, 2),
        "recommended_actions": [action_to_dict(a) for a in popped.recommended_actions],
        "final_actions": [action_to_dict(a) for a in popped.final_actions],
        "status": popped.status,
        "processing_time_ms": round(elapsed * 1000, 1),
    }

@app.get("/queue-status")
async def queue_status():
    return {"queue_size": engine.queue.size()}

@app.get("/stats")
async def get_stats():
    """Returns live stats from the SOC engine."""
    return engine.get_stats()

@app.get("/audit")
async def get_audit():
    """Returns all audit records from the standardized JSON array file."""
    try:
        if not os.path.exists(AUDIT_PATH):
            return {"status": "success", "count": 0, "records": []}
            
        with open(AUDIT_PATH, "r") as f:
            content = f.read().strip()
            if not content:
                return {"status": "success", "count": 0, "records": []}
            records = json.loads(content)
        return {"status": "success", "count": len(records), "records": records}
    except Exception as e:
        return {"status": "error", "message": str(e), "records": []}

@app.post("/audit")
async def post_audit(entry: AuditEntryIn):
    record = {
        "incident_id": entry.incident_id or "manual",
        "timestamp": datetime.now().isoformat(),
        "alert_type": entry.alert_type or "operator_action",
        "action": entry.action,
        "actor": entry.actor,
        "target": entry.target,
        "outcome": entry.outcome,
        "priority_score": 0,
        "actions_taken": [entry.action.lower().replace(" ", "_")],
        "status": "logged"
    }
    # Read existing, append, write back
    try:
        records = []
        if os.path.exists(AUDIT_PATH):
            with open(AUDIT_PATH, "r") as f:
                content = f.read().strip()
                if content:
                    records = json.loads(content) if content.startswith("[") else []
        
        records.append(record)
        with open(AUDIT_PATH, "w") as f:
            json.dump(records, f, indent=4)
        return {"status": "logged", "record": record}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
