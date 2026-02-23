from models import Incident, ResponseAction, ActionType
from engine.triage import TriageEngine
from engine.priority import PriorityQueue
from engine.topology import BlastRadiusAnalyzer
from engine.optimizer import GreedyOptimizer
from response.executor import ResponseExecutor
from audit.tracker import AuditLogger
from ingestion.stream import AlertSimulator

class SOCEngine:
    """
    Main Orchestrator for Project Argos.
    Ties together Triage -> Priority -> Analysis -> Optimization -> Execution.
    """
    
    def __init__(self):
        self.triage = TriageEngine()
        self.queue = PriorityQueue()
        self.topology = BlastRadiusAnalyzer()
        self.optimizer = GreedyOptimizer()
        self.audit = AuditLogger()
        self.topology.build_mock_infrastructure()

    def process_new_alert(self, alert):
        # 1. Triage (Decision Tree)
        enriched_alert = self.triage.enrich_alert(alert)
        
        # 2. Blast Radius (Graph Analysis)
        blast_radius = self.topology.calculate_blast_radius(enriched_alert.source)
        
        # 3. Create Incident
        incident = Incident(alert=enriched_alert, blast_radius=blast_radius)
        
        # 4. Generate Candidate Actions
        actions = self._generate_candidate_actions(incident)
        incident.recommended_actions = actions
        
        # 5. Priority (Max-Heap)
        self.queue.push(incident)
        print(f"[*] Queued Incident {incident.id} | Priority Score: {incident.priority_score:.2f}")

    def run_cycle(self):
        """Processes the highest priority incident in the queue."""
        if self.queue.is_empty():
            return
            
        incident = self.queue.pop()
        
        # 6. Optimization (Greedy Algorithm)
        incident.final_actions = self.optimizer.select_optimal_actions(incident.recommended_actions)
        
        # 7. Execution
        ResponseExecutor.execute_incident_plan(incident)
        
        # 8. Audit
        self.audit.log_incident(incident)

    def _generate_candidate_actions(self, incident: Incident) -> list:
        # Mocking possible responses for demonstration
        candidates = []
        source = incident.alert.source
        
        # High Impact / High Gain
        candidates.append(ResponseAction(
            type=ActionType.ISOLATE_HOST, 
            target=source, 
            security_gain=90, 
            operational_cost=40, 
            business_risk=30
        ))
        
        # Medium Impact
        candidates.append(ResponseAction(
            type=ActionType.KILL_PROCESS, 
            target=source, 
            security_gain=60, 
            operational_cost=10, 
            business_risk=5
        ))
        
        # Low Cost
        candidates.append(ResponseAction(
            type=ActionType.BLOCK_IP, 
            target="192.168.1.100", 
            security_gain=40, 
            operational_cost=5, 
            business_risk=2
        ))
        
        return candidates

if __name__ == "__main__":
    engine = SOCEngine()
    print("[*] Project Argos - Autonomous SOC Response Engine Started")
    
    # Simulate first stream of alerts
    for alert in AlertSimulator.get_stream(5):
        engine.process_new_alert(alert)
        
    # Process the queue
    print("\n[*] Starting Autonomous Response Cycles...")
    while not engine.queue.is_empty():
        engine.run_cycle()
