import abc
import logging
from typing import List

from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding

try:
    import pywintypes
except ImportError:
    pywintypes = None


class BaseCheck(abc.ABC):
    """Abstract base class for all privilege escalation checks."""
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the check."""
        pass
        
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Description of what the check does."""
        pass
        
    @abc.abstractmethod
    def run(self, context: ScanContext) -> List[Finding]:
        """Core logic for the check. Must be implemented by subclasses."""
        pass
        
    def safe_run(self, context: ScanContext) -> List[Finding]:
        """Safe wrapper that catches exceptions and prevents the scan from crashing."""
        try:
            return self.run(context)
        except Exception as e:
            err_type = type(e).__name__
            if pywintypes and isinstance(e, pywintypes.error):
                err_type = "pywintypes.error"
                
            logging.error(f"Check {self.name} failed with {err_type}: {e}")
            return []
