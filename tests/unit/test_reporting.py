import pytest
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.reporting.terminal_reporter import TerminalReporter
from privesc_assistant_win.reporting.json_reporter import JsonReporter

def test_terminal_reporter():
    ctx = ScanContext(hostname="TestHost", os_build="19044", os_version="10", timestamp="2023", config={}, is_elevated=False, current_user="TestUser")
    findings = [
        Finding(title="Test", severity=Severity.CRITICAL, description="Desc", evidence="", remediation="", check_id="test")
    ]
    
    reporter = TerminalReporter()
    output = reporter.generate(ctx, findings)
    assert "TestHost" in output
    assert "CRITICAL: Test" in output

def test_json_reporter():
    ctx = ScanContext(hostname="TestHost", os_build="19044", os_version="10", timestamp="2023", config={}, is_elevated=False, current_user="TestUser")
    findings = [
        Finding(title="Test", severity=Severity.CRITICAL, description="Desc", evidence="", remediation="", check_id="test")
    ]
    
    reporter = JsonReporter()
    output = reporter.generate(ctx, findings)
    import json
    data = json.loads(output)
    assert data["context"]["hostname"] == "TestHost"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "CRITICAL"
