from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(Enum):
    """Represents the severity of a finding."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """Represents a discovered privilege escalation vector or misconfiguration."""
    
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    check_id: str
    references: List[str] = field(default_factory=list)
