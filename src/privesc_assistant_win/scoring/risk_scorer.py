from typing import List, Dict, Any
from privesc_assistant_win.core.finding import Finding, Severity

def assign_severity_score(finding: Finding) -> int:
    """Assigns a numerical risk score based on finding severity."""
    score_map = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 75,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 0
    }
    return score_map.get(finding.severity, 0)

def generate_priority_list(findings: List[Finding]) -> List[Finding]:
    """Sorts findings into a recommended attack-order list (Critical -> Info)."""
    return sorted(findings, key=lambda f: assign_severity_score(f), reverse=True)

def aggregate_findings(findings: List[Finding]) -> Dict[str, Any]:
    """Groups findings by severity and computes overall system risk score."""
    priority_list = generate_priority_list(findings)
    total_score = sum(assign_severity_score(f) for f in priority_list)
    
    # Cap maximum overall score at 100 conceptually, or just return sum
    overall_risk = "LOW"
    if any(f.severity == Severity.CRITICAL for f in findings):
        overall_risk = "CRITICAL"
    elif any(f.severity == Severity.HIGH for f in findings):
        overall_risk = "HIGH"
    elif any(f.severity == Severity.MEDIUM for f in findings):
        overall_risk = "MEDIUM"
        
    counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == Severity.CRITICAL),
        "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
        "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
        "INFO": sum(1 for f in findings if f.severity == Severity.INFO),
    }
    
    return {
        "overall_risk_level": overall_risk,
        "total_score_sum": total_score,
        "counts": counts,
        "priority_list": priority_list
    }
