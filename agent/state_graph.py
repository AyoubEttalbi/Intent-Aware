import networkx as nx
from typing import Dict, Any, List, Optional

class StateGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        # Track unique paths to avoid duplicates
        self.explored_paths = set()

    def add_node(self, state_id: str, data: Optional[Dict[str, Any]] = None):
        """
        Adds a node (app state) to the graph.
        """
        if not self.graph.has_node(state_id):
            self.graph.add_node(state_id, **(data or {}))

    def add_edge(self, from_state: str, to_state: str, action: Dict[str, Any]):
        """
        Adds an edge (API call/Action) between states.
        """
        self.graph.add_edge(from_state, to_state, **action)

    def is_explored(self, method: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> bool:
        """
        Checks if a specific request has already been executed.
        """
        if isinstance(params, dict):
            param_str = str(sorted(params.items()))
        else:
            param_str = str(params) if params else ""
            
        path_key = f"{method}:{endpoint}:{param_str}"
        return path_key in self.explored_paths

    def mark_explored(self, method: str, endpoint: str, params: Optional[Dict[str, Any]] = None):
        """
        Marks a request as explored.
        """
        if isinstance(params, dict):
            param_str = str(sorted(params.items()))
        else:
            param_str = str(params) if params else ""
            
        path_key = f"{method}:{endpoint}:{param_str}"
        self.explored_paths.add(path_key)

    def get_summary(self) -> Dict[str, Any]:
        """
        Returns a summary of the graph state.
        """
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "unique_paths_explored": len(self.explored_paths)
        }

if __name__ == "__main__":
    print("State Graph initialized.")
