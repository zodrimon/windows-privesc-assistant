from typing import List
from privesc_assistant_win.core.finding import Finding
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.reporting.base_reporter import BaseReporter
from privesc_assistant_win.scoring.risk_scorer import aggregate_findings

class TerminalReporter(BaseReporter):
    def generate(self, context: ScanContext, findings: List[Finding]) -> str:
        lines = []
        lines.append("="*60)
        lines.append(f"Windows Privesc Scan Report")
        lines.append(f"Hostname: {context.hostname} | Build: {context.os_build} | User: {context.current_user}")
        lines.append(f"Is Elevated: {context.is_elevated}")
        lines.append(f"Timestamp: {context.timestamp}")
        
        if not findings:
            lines.append("="*60)
            lines.append("No privesc vectors found.")
            return "\n".join(lines)
            
        agg = aggregate_findings(findings)
        lines.append(f"OVERALL RISK: {agg['overall_risk_level']} (Score: {agg['total_score_sum']})")
        lines.append("="*60)
        
        counts = agg["counts"]
        lines.append(f"Found {len(findings)} potential escalation vectors:")
        lines.append(f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | INFO: {counts['INFO']}\n")
        
        for idx, f in enumerate(agg["priority_list"]):
            lines.append(f"[{idx+1}] {f.severity.name}: {f.title}")
            lines.append(f"    Check: {f.check_id}")
            lines.append(f"    Description: {f.description}")
            if f.evidence:
                lines.append(f"    Evidence: {f.evidence}")
            lines.append(f"    Remediation: {f.remediation}")
            lines.append("-" * 40)
            
        return "\n".join(lines)
