from models import Alert, Severity

class TriageEngine:
    """
    Implements Decision Trees to determine initial severity and confidence.
    Maps SOC triage logic to automated classification.
    """
    
    @staticmethod
    def calculate_base_severity(alert: Alert) -> Severity:
        # Simple Decision Tree logic
        if alert.ioc_confidence > 0.9 and alert.asset_criticality > 0.8:
            return Severity.CRITICAL
        
        if alert.type in ["ransomware", "exfiltration", "credential_stuffing"]:
            if alert.asset_criticality > 0.5:
                return Severity.HIGH
            return Severity.MEDIUM
        
        if alert.ioc_confidence < 0.3:
            return Severity.LOW
            
        return alert.severity

    @staticmethod
    def enrich_alert(alert: Alert) -> Alert:
        # Enrich alert with calculated fields
        alert.severity = TriageEngine.calculate_base_severity(alert)
        return alert
