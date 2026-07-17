import time
import logging
from typing import List, Dict, Any

from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding
from privesc_assistant_win.core.registry import registry


class ScanEngine:
    """Discovers and runs enabled checks."""
    
    def __init__(self, context: ScanContext):
        self.context = context
        self.findings: List[Finding] = []
        self.timing: Dict[str, float] = {}
        
    def run_all(self) -> List[Finding]:
        """Runs all enabled checks."""
        all_checks = registry.get_all_checks()
        enabled_check_ids = self.context.config.get("checks", [])
        
        # If config is empty or "all", run everything registered
        run_all = not enabled_check_ids or "all" in enabled_check_ids
        
        for name, check in all_checks.items():
            if run_all or name in enabled_check_ids:
                logging.info(f"Running check: {name}")
                start_time = time.time()
                
                check_findings = check.safe_run(self.context)
                self.findings.extend(check_findings)
                
                duration = time.time() - start_time
                self.timing[name] = duration
                logging.debug(f"Check {name} completed in {duration:.2f} seconds and found {len(check_findings)} issues.")
                
        return self.findings
