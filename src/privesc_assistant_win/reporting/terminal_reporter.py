from typing import List
from privesc_assistant_win.core.finding import Finding
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.reporting.base_reporter import BaseReporter

class TerminalReporter(BaseReporter):
    def generate(self, context: ScanContext, findings: List[Finding]) -> str:
        lines = []
        lines.append("="*60)
        lines.append(f"Windows Privesc Scan Report")
        lines.append(f"Hostname: {context.hostname} | Build: {context.os_build} | User: {context.current_user}")
        lines.append(f"Is Elevated: {context.is_elevated}")
        lines.append(f"Timestamp: {context.timestamp}")
        lines.append("="*60)
        
        if not findings:
            lines.append("No privesc vectors found.")
            return "\n".join(lines)
            
        # Group by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.name, 99))
        
        lines.append(f"Found {len(sorted_findings)} potential escalation vectors:\n")
        
        for idx, f in enumerate(sorted_findings):
            lines.append(f"[{idx+1}] {f.severity.name}: {f.title}")
            lines.append(f"    Check: {f.check_id}")
            lines.append(f"    Description: {f.description}")
            if f.evidence:
                lines.append(f"    Evidence: {f.evidence}")
            lines.append(f"    Remediation: {f.remediation}")
            lines.append("-" * 40)
            
        return "\n".join(lines)
