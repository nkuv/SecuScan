from dataclasses import dataclass
from typing import Optional

@dataclass
class Vulnerability:
    """Represents a security finding."""
    type: str
    file: str
    severity: str
    description: str
    line: Optional[int] = None
    id: Optional[str] = None
