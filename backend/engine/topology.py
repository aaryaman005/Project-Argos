import networkx as nx


class BlastRadiusAnalyzer:
    """
    Graph-based dependency and blast radius analysis.
    Models: Process -> parent -> child, User -> device -> role.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_dependency(self, source: str, target: str, relationship: str):
        self.graph.add_edge(source, target, type=relationship)

    def calculate_blast_radius(self, node: str) -> float:
        """
        Calculates the blast radius of a node based on its downstream dependencies.
        Returns a normalized score 0.0 to 1.0.
        """
        if node not in self.graph:
            return 0.1 # Base risk for unknown node
            
        # Get all nodes reachable from this node (downstream impact)
        # Using simple DFS or BFS to count descendants
        descendants = nx.descendants(self.graph, node)
        impact_count = len(descendants)
        
        # Normalize score (simplified)
        # 1-5 nodes: 0.2, 5-15: 0.5, 15+: 1.0
        if impact_count == 0:
            return 0.1
        if impact_count < 5:
            return 0.3
        if impact_count < 15:
            return 0.7
        return 1.0

    def build_mock_infrastructure(self):
        # Build a sample graph for simulation
        # Processes
        self.add_dependency("systemd", "apache2", "parent")
        self.add_dependency("apache2", "php-fpm", "child")
        self.add_dependency("php-fpm", "mysql-client", "child")
        
        # Network/Users
        self.add_dependency("admin-user", "jump-box", "access")
        self.add_dependency("jump-box", "prod-db-cluster", "network")
        self.add_dependency("prod-db-cluster", "customer-data-s3", "storage")
