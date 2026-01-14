from abc import ABC, abstractmethod
from typing import List
from secuscan.scanners.models import Vulnerability

class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""
    
    def __init__(self, target: str):
        self.target = target
        self.results: List[Vulnerability] = []

    @abstractmethod
    def scan(self) -> List[Vulnerability]:
        """
        Performs the scan and returns a list of findings.
        """
        pass
    
    def add_vulnerability(self, type: str, file: str, severity: str, description: str, line: int = None, id: str = None):
        """Helper to append a vulnerability to results."""
        self.results.append(Vulnerability(
            type=type,
            file=file,
            severity=severity,
            description=description,
            line=line,
            id=id
        ))
