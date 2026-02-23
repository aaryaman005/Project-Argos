import json
import os
from datetime import datetime
from typing import List
from models import Incident

class AuditLogger:
    """
    Audit & Learning Layer.
    Logs decisions, impacts, and tracks MTTR.
    """
    
    def __init__(self, log_path: str = None):
        if log_path is None:
            # Point to root of project (two levels up from backend/audit/)
            # Wait, backend/audit/tracker.py -> backend/audit/ -> backend/ -> root/
            # That's 3 dirnames.
            base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            self.log_path = os.path.join(base, "audit_records.json")
        else:
            self.log_path = log_path

    def log_incident(self, incident: Incident):
        record = {
            "incident_id": incident.id,
            "timestamp": datetime.now().isoformat(),
            "alert_type": incident.alert.type,
            "priority_score": round(incident.priority_score, 2),
            "actions_taken": [a.type.value for a in incident.final_actions],
            "actor": "SOC Engine (Autonomous)",
            "target": incident.alert.source,
            "outcome": "Resolved",
            "status": incident.status
        }
        
        # Read existing, append, write back (JSON array format)
        try:
            records = []
            if os.path.exists(self.log_path):
                with open(self.log_path, "r") as f:
                    content = f.read().strip()
                    if content:
                        records = json.loads(content) if content.startswith("[") else []
            
            records.append(record)
            
            with open(self.log_path, "w") as f:
                json.dump(records, f, indent=4)
                
            print(f"[*] Audit logged for Incident {incident.id} at {self.log_path}")
        except Exception as e:
            print(f"[!] Audit logging error: {e}")

    def get_historical_stats(self) -> dict:
        """Reads the audit file and returns aggregated historical statistics."""
        stats = {
            "resolved_count": 0,
            "threat_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        try:
            if not os.path.exists(self.log_path):
                return stats
                
            with open(self.log_path, "r") as f:
                content = f.read().strip()
                if not content:
                    return stats
                records = json.loads(content)
                
            stats["resolved_count"] = len(records)
            for record in records:
                # Some manual logs might not have priority_score or specific structure
                # but simulated ones should have alert_type or severity (if we improved it)
                # For now, let's map alert types to severities as a fallback
                severity = record.get("severity", "medium").lower()
                if severity in stats["threat_levels"]:
                    stats["threat_levels"][severity] += 1
                else:
                    # Map known types if severity is missing
                    a_type = record.get("alert_type", "").lower()
                    if "ransomware" in a_type:
                        stats["threat_levels"]["critical"] += 1
                    elif "exfiltration" in a_type:
                        stats["threat_levels"]["high"] += 1
                    else:
                        stats["threat_levels"]["medium"] += 1
                    
            return stats
        except Exception as e:
            print(f"[!] Historical stats error: {e}")
            return stats

    @staticmethod
    def calculate_mttr(incidents: List[Incident]) -> float:
        # Simplified MTTR calculation in seconds
        pass
