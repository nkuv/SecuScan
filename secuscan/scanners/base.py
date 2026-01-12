from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""
    
    def __init__(self, target: str):
        self.target = target
        self.results: List[Dict[str, Any]] = []

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Performs the scan and returns a list of findings.
        Each finding should be a dict with keys: 'type', 'file', 'severity', 'description'.
        """
        pass
    
    def add_vulnerability(self, type: str, file: str, severity: str, description: str):
        """Helper to append a vulnerability to results."""
        self.results.append({
            "type": type,
            "file": file,
            "severity": severity,
            "description": description
        })
