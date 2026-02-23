import random
import time
from datetime import datetime
from models import Alert, Severity

class AlertSimulator:
    """
    Simulates a stream of SIEM/EDR alerts with varying metadata.
    """
    
    ALERT_TYPES = [
        ("ransomware", "Detected file encryption burst", 0.9, 0.8),
        ("ssh_brute_force", "Multiple failed logins from external IP", 0.7, 0.4),
        ("data_exfiltration", "Large outbound data transfer to unknown IP", 0.8, 0.9),
        ("malware_beacon", "Suspicious C2 beaconing pattern", 0.6, 0.6),
        ("privilege_escalation", "Unauthorized use of sudo", 0.95, 0.7)
    ]
    
    TARGETS = [
        "prod-db-01", "dev-laptop-12", "jump-box-ext", 
        "marketing-pc-04", "finance-workstation", "api-gateway-01"
    ]

    @staticmethod
    def generate_alert() -> Alert:
        alert_type, desc, conf_base, crit_base = random.choice(AlertSimulator.ALERT_TYPES)
        
        # Add some randomness to confidence and criticality
        confidence = min(1.0, conf_base + random.uniform(-0.2, 0.1))
        criticality = min(1.0, crit_base + random.uniform(-0.1, 0.2))
        
        return Alert(
            type=alert_type,
            source=random.choice(AlertSimulator.TARGETS),
            severity=Severity.MEDIUM, # Default, triage will fix
            ioc_confidence=confidence,
            asset_criticality=criticality,
            description=f"{desc} on {random.choice(AlertSimulator.TARGETS)}"
        )

    @classmethod
    def get_stream(cls, count: int = 10):
        for _ in range(count):
            yield cls.generate_alert()
            time.sleep(random.uniform(0.1, 0.5))
