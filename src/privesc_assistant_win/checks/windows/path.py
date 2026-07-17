import os
from typing import List

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def enumerate_system_path() -> List[str]:
    """
    Returns a list of directories in the system PATH environment variable.
    """
    path_var = os.environ.get("PATH", "")
    return [p.strip() for p in path_var.split(";") if p.strip()]


def check_writable_paths(paths: List[str]) -> List[str]:
    """
    Checks which directories in the provided list are writable by the current user.
    """
    writable = []
    for p in paths:
        if os.path.exists(p) and os.path.isdir(p):
            if os.access(p, os.W_OK):
                writable.append(p)
    return writable


@register_check
class WritablePathCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "writable_path_dll"
        
    @property
    def description(self) -> str:
        return "Checks if any directories in the system PATH are writable by the current user, enabling DLL hijacking."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        paths = enumerate_system_path()
        writable_paths = check_writable_paths(paths)
        
        for w_path in writable_paths:
            findings.append(Finding(
                title=f"Writable PATH Directory: {w_path}",
                severity=Severity.HIGH,
                description=f"The directory {w_path} is in the system PATH and is writable by the current user. This allows an attacker to plant a malicious DLL (DLL hijacking) or executable, which may be executed by privileged processes.",
                evidence=w_path,
                remediation="Remove write permissions for standard users on this directory.",
                check_id=self.name
            ))
            
        return findings
