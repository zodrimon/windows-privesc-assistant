import os
import win32security
import pywintypes
from typing import List, Dict, Any

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def get_acl_for_path(path: str) -> List[Dict[str, Any]]:
    """
    Returns a normalized structure of the DACL for a given file/directory.
    """
    if not os.path.exists(path):
        return []
        
    acls = []
    try:
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return []
            
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            acls.append({
                "type": ace[0][0],
                "mask": ace[1],
                "sid": win32security.ConvertSidToStringSid(ace[2])
            })
    except pywintypes.error:
        pass
        
    return acls


def check_sam_system_readable() -> List[str]:
    """
    Checks if SAM and SYSTEM hives are readable by the current user.
    """
    readable = []
    sysroot = os.environ.get("SystemRoot", "C:\\Windows")
    
    files_to_check = [
        os.path.join(sysroot, "System32", "config", "SAM"),
        os.path.join(sysroot, "System32", "config", "SYSTEM")
    ]
    
    for f in files_to_check:
        if os.path.exists(f) and os.access(f, os.R_OK):
            readable.append(f)
            
    backup_dir = os.path.join(sysroot, "Repair")
    if os.path.exists(backup_dir):
        sam_backup = os.path.join(backup_dir, "SAM")
        if os.path.exists(sam_backup) and os.access(sam_backup, os.R_OK):
            readable.append(sam_backup)
            
    return readable


def check_unattend_files() -> List[str]:
    """
    Hunts for unattend.xml, sysprep.inf, and sysprep.xml which might contain cleartext passwords.
    """
    found = []
    system_drive = os.environ.get("SystemDrive", "C:")
    
    common_locations = [
        os.path.join(system_drive, "\\unattend.xml"),
        os.path.join(system_drive, "\\Windows\\Panther\\Unattend.xml"),
        os.path.join(system_drive, "\\Windows\\Panther\\Unattended.xml"),
        os.path.join(system_drive, "\\Windows\\System32\\sysprep\\unattend.xml"),
        os.path.join(system_drive, "\\Windows\\System32\\sysprep\\sysprep.inf"),
        os.path.join(system_drive, "\\Windows\\System32\\sysprep\\sysprep.xml"),
    ]
    
    for loc in common_locations:
        if os.path.exists(loc) and os.access(loc, os.R_OK):
            found.append(loc)
            
    return found


@register_check
class WeakPermissionsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "weak_permissions"
        
    @property
    def description(self) -> str:
        return "Checks for readable SAM/SYSTEM hives and unattended installation files."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        # 1. SAM/SYSTEM readable
        readable_hives = check_sam_system_readable()
        for hive in readable_hives:
            findings.append(Finding(
                title=f"Readable Registry Hive: {os.path.basename(hive)}",
                severity=Severity.CRITICAL,
                description=f"The registry hive {hive} is readable by the current user. An attacker can extract password hashes.",
                evidence=hive,
                remediation="Restrict read access to the SAM and SYSTEM files.",
                check_id=self.name
            ))
            
        # 2. Unattended install files
        unattend_files = check_unattend_files()
        for u_file in unattend_files:
            findings.append(Finding(
                title=f"Unattended Installation File Found: {os.path.basename(u_file)}",
                severity=Severity.HIGH,
                description=f"An unattended installation file was found at {u_file}. These files often contain plaintext or Base64 encoded Administrator passwords.",
                evidence=u_file,
                remediation="Delete unattended installation files if they are no longer needed, or secure them.",
                check_id=self.name
            ))
            
        return findings
