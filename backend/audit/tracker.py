import json
from datetime import datetime
from typing import List
from models import Incident

class AuditLogger:
    """
    Audit & Learning Layer.
    Logs decisions, impacts, and tracks MTTR.
    """
    
    def __init__(self, log_path: str = "audit_records.json"):
        self.log_path = log_path

    def log_incident(self, incident: Incident):
        record = {
            "incident_id": incident.id,
            "timestamp": datetime.now().isoformat(),
            "alert_type": incident.alert.type,
            "priority_score": incident.priority_score,
            "actions_taken": [a.type.value for a in incident.final_actions],
            "status": incident.status
        }
        
        # In a real app, this would be a database. For this demo, we'll append to a list.
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            print(f"[!] Audit logging error: {e}")

    @staticmethod
    def calculate_mttr(incidents: List[Incident]) -> float:
        # Simplified MTTR calculation in seconds
        pass
