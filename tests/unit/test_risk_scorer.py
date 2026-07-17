import pytest
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.scoring.risk_scorer import (
    assign_severity_score,
    generate_priority_list,
    aggregate_findings
)

def test_assign_severity_score():
    assert assign_severity_score(Finding(title="", severity=Severity.CRITICAL, description="", evidence="", remediation="", check_id="")) == 100
    assert assign_severity_score(Finding(title="", severity=Severity.LOW, description="", evidence="", remediation="", check_id="")) == 25

def test_generate_priority_list():
    f1 = Finding(title="1", severity=Severity.LOW, description="", evidence="", remediation="", check_id="")
    f2 = Finding(title="2", severity=Severity.CRITICAL, description="", evidence="", remediation="", check_id="")
    f3 = Finding(title="3", severity=Severity.MEDIUM, description="", evidence="", remediation="", check_id="")
    
    findings = [f1, f2, f3]
    priority = generate_priority_list(findings)
    assert priority[0].severity == Severity.CRITICAL
    assert priority[1].severity == Severity.MEDIUM
    assert priority[2].severity == Severity.LOW

def test_aggregate_findings():
    f1 = Finding(title="1", severity=Severity.LOW, description="", evidence="", remediation="", check_id="")
    f2 = Finding(title="2", severity=Severity.CRITICAL, description="", evidence="", remediation="", check_id="")
    
    findings = [f1, f2]
    agg = aggregate_findings(findings)
    assert agg["overall_risk_level"] == "CRITICAL"
    assert agg["total_score_sum"] == 125
    assert agg["counts"]["CRITICAL"] == 1
    assert agg["counts"]["LOW"] == 1
    assert len(agg["priority_list"]) == 2
