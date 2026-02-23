import heapq
from models import Incident

class PriorityQueue:
    """
    Heap-based Priority Queue to rank alerts.
    Priority Score = (Threat Severity x Asset Value x Confidence) - Estimated Response Cost
    Implemented as a Max-Heap using negative values (standard Python heapq is Min-Heap).
    """
    
    def __init__(self):
        self._queue = []
        self._incidents = {}

    def push(self, incident: Incident):
        # Calculate Priority Score: (Severity * Criticality * Confidence)
        # We'll normalize Severity to 1-4
        severity_val = incident.alert.severity.value
        score = (severity_val * incident.alert.asset_criticality * incident.alert.ioc_confidence * 100)
        
        # Adjust for response cost if actions are already pre-calculated
        total_cost = sum(a.operational_cost for a in incident.recommended_actions)
        priority_score = score - total_cost
        
        incident.priority_score = priority_score
        
        # heapq is a min-heap, so we store negative priority_score for max-heap behavior
        heapq.heappush(self._queue, (-priority_score, incident.id))
        self._incidents[incident.id] = incident

    def pop(self) -> Incident:
        if not self._queue:
            return None
        _, incident_id = heapq.heappop(self._queue)
        return self._incidents.pop(incident_id)

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)
