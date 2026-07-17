from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class ScanContext:
    """Shared state passed to every check during the scan."""
    
    hostname: str
    os_build: str
    os_version: str
    timestamp: str
    config: Dict[str, Any]
    is_elevated: bool
    current_user: str
    current_token_privileges: List[str] = field(default_factory=list)
