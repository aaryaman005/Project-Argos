from typing import List
from models import ResponseAction

class GreedyOptimizer:
    """
    Greedy Algorithm for Cost-Aware Optimization.
    Selects the best actions to maximize risk reduction per unit cost.
    """

    @staticmethod
    def select_optimal_actions(possible_actions: List[ResponseAction], budget: float = 100.0) -> List[ResponseAction]:
        """
        Greedy approach:
        1. Calculate Efficiency = Security Gain / (Operational Cost + Business Risk)
        2. Sort by Efficiency descending
        3. Select until budget is reached
        """
        
        # Pre-process actions to calculate efficiency
        refined_actions = []
        for action in possible_actions:
            total_impact = action.operational_cost + action.business_risk
            # Avoid division by zero
            efficiency = action.security_gain / max(total_impact, 0.1)
            refined_actions.append((efficiency, action))
            
        # Sort by efficiency
        refined_actions.sort(key=lambda x: x[0], reverse=True)
        
        selected = []
        current_cost = 0.0
        
        for efficiency, action in refined_actions:
            if current_cost + action.operational_cost <= budget:
                selected.append(action)
                current_cost += action.operational_cost
                
        return selected
