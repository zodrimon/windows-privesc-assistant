import pytest
from typing import List

from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.checks.base import BaseCheck

class DummyFailingCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy_failing_check"
        
    @property
    def description(self) -> str:
        return "Always throws an exception"
        
    def run(self, context: ScanContext) -> List[Finding]:
        raise ValueError("Intentional crash for testing")


class DummySuccessfulCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy_successful_check"
        
    @property
    def description(self) -> str:
        return "Always returns one finding"
        
    def run(self, context: ScanContext) -> List[Finding]:
        return [
            Finding(
                title="Test Finding",
                severity=Severity.HIGH,
                description="This is a test.",
                evidence="N/A",
                remediation="N/A",
                check_id=self.name,
                references=[]
            )
        ]


def test_finding_instantiation():
    finding = Finding(
        title="Test Title",
        severity=Severity.CRITICAL,
        description="Desc",
        evidence="Ev",
        remediation="Rem",
        check_id="test_check"
    )
    assert finding.title == "Test Title"
    assert finding.severity == Severity.CRITICAL
    assert len(finding.references) == 0


def test_scan_context_instantiation():
    ctx = ScanContext(
        hostname="TEST-PC",
        os_build="19045",
        os_version="10.0",
        timestamp="2026-07-17",
        config={"checks": []},
        is_elevated=False,
        current_user="TEST-PC\\User"
    )
    assert ctx.hostname == "TEST-PC"
    assert not ctx.is_elevated
    assert len(ctx.current_token_privileges) == 0


def test_base_check_safe_wrapper_success():
    ctx = ScanContext(
        hostname="TEST-PC", os_build="19045", os_version="10.0",
        timestamp="2026-07-17", config={}, is_elevated=False, current_user="TEST-PC\\User"
    )
    check = DummySuccessfulCheck()
    findings = check.safe_run(ctx)
    
    assert len(findings) == 1
    assert findings[0].title == "Test Finding"


def test_base_check_safe_wrapper_failure():
    ctx = ScanContext(
        hostname="TEST-PC", os_build="19045", os_version="10.0",
        timestamp="2026-07-17", config={}, is_elevated=False, current_user="TEST-PC\\User"
    )
    check = DummyFailingCheck()
    
    # Should catch the ValueError and return empty list without crashing
    findings = check.safe_run(ctx)
    
    assert len(findings) == 0
