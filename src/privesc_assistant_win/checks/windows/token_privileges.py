import win32security
import win32api
import win32con
from typing import List, Dict, Any

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def enumerate_current_token_privileges() -> List[Dict[str, Any]]:
    """
    Enumerates the privileges of the current process token.
    Returns a list of dicts with name, enabled, and default_enabled status.
    """
    privileges = []
    
    # Open the current process token
    hProcess = win32api.GetCurrentProcess()
    hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_QUERY)
    
    # Get privileges
    token_privs = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)
    
    for luid, flags in token_privs:
        name = win32security.LookupPrivilegeName(None, luid)
        
        enabled = (flags & win32security.SE_PRIVILEGE_ENABLED) != 0
        default = (flags & win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
        
        privileges.append({
            "name": name,
            "enabled": enabled,
            "default_enabled": default
        })
        
    return privileges


@register_check
class TokenPrivilegesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "token_privileges"
        
    @property
    def description(self) -> str:
        return "Checks the current access token for exploitable privileges like SeDebugPrivilege, SeImpersonatePrivilege, etc."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        privileges = enumerate_current_token_privileges()
        
        abusable_privs = {
            "SeImpersonatePrivilege": "Allows impersonation of any token. Can be abused (e.g. via PrintSpoofer/Potato attacks) to escalate to SYSTEM.",
            "SeAssignPrimaryTokenPrivilege": "Allows assigning a primary token to a new process. Similar to SeImpersonate, can be used for SYSTEM escalation.",
            "SeDebugPrivilege": "Allows the user to attach a debugger to any process. Can be used to inject code into SYSTEM processes (e.g. lsass.exe, winlogon.exe).",
            "SeTakeOwnershipPrivilege": "Allows the user to take ownership of any securable object, bypassing DACLs. Can be used to take ownership of sensitive files/keys.",
            "SeRestorePrivilege": "Allows the user to bypass write/owner checks. Can be used to modify system binaries or registry keys.",
            "SeBackupPrivilege": "Allows the user to bypass read checks. Can be used to read SAM database, LSA secrets, or other sensitive files.",
            "SeLoadDriverPrivilege": "Allows loading arbitrary drivers into the kernel. Can be abused to execute code in kernel mode.",
            "SeManageVolumePrivilege": "Allows managing volume settings. Can be abused to gain code execution or alter file permissions."
        }
        
        for priv in privileges:
            name = priv["name"]
            if name in abusable_privs:
                findings.append(Finding(
                    title=f"Exploitable Token Privilege: {name}",
                    severity=Severity.HIGH,
                    description=f"The current user token holds the {name} privilege. {abusable_privs[name]}",
                    evidence=f"Privilege: {name}, Enabled: {priv['enabled']}",
                    remediation="Remove this privilege from the user/group via Local Security Policy if not strictly required.",
                    check_id=self.name
                ))
                
        return findings
