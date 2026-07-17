from abc import ABC, abstractmethod
from typing import List, Dict, Any
from privesc_assistant_win.core.finding import Finding
from privesc_assistant_win.core.scan_context import ScanContext

class BaseReporter(ABC):
    @abstractmethod
    def generate(self, context: ScanContext, findings: List[Finding]) -> str:
        """Generates a report from the findings."""
        pass
