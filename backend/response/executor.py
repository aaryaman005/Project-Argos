import time
from models import Incident, ResponseAction, ActionType

class ResponseExecutor:
    """
    Executes SOC response actions.
    Simulates real-world impact with logging and delay.
    """
    
    @staticmethod
    def execute_action(action: ResponseAction) -> bool:
        print(f"[*] EXECUTING ACTION: {action.type.value} on TARGET: {action.target}")
        
        # Simulate execution delay
        time.sleep(0.5)
        
        # Logic for specific action types
        if action.type == ActionType.BLOCK_IP:
            print(f"[+] Firewall rule added: DROP from {action.target}")
        elif action.type == ActionType.KILL_PROCESS:
            print(f"[+] Sent SIGKILL to process on {action.target}")
        elif action.type == ActionType.ISOLATE_HOST:
            print(f"[+] Host {action.target} moved to Quarantine VLAN")
        elif action.type == ActionType.NOTIFY_HUMAN:
            print(f"[!] Notification sent to On-Call Analyst")
            
        action.status = "completed"
        return True

    @staticmethod
    def execute_incident_plan(incident: Incident):
        print(f"\n[!] PROCESSING INCIDENT: {incident.id}")
        print(f"    - Alert: {incident.alert.type} (Severity: {incident.alert.severity.name})")
        print(f"    - Priority Score: {incident.priority_score:.2f}")
        
        for action in incident.final_actions:
            ResponseExecutor.execute_action(action)
        
        incident.status = "resolved"
        incident.resolved_at = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[+] Incident {incident.id} RESOLVED.")
