import os
import winreg
import glob
from typing import List

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def check_always_install_elevated() -> bool:
    """
    Checks if AlwaysInstallElevated is set in both HKLM and HKCU.
    Both must be 1 to be exploitable.
    """
    key_path = r"Software\Policies\Microsoft\Windows\Installer"
    value_name = "AlwaysInstallElevated"
    
    def get_reg_value(hive, path, name):
        try:
            with winreg.OpenKey(hive, path) as key:
                val, _ = winreg.QueryValueEx(key, name)
                return val == 1
        except FileNotFoundError:
            return False
            
    hklm_set = get_reg_value(winreg.HKEY_LOCAL_MACHINE, key_path, value_name)
    hkcu_set = get_reg_value(winreg.HKEY_CURRENT_USER, key_path, value_name)
    
    return hklm_set and hkcu_set


def check_wsl_bash_history() -> List[str]:
    """
    Checks for readable WSL bash history files which might contain credentials.
    """
    found = []
    user_profile = os.environ.get("USERPROFILE", "")
    if not user_profile:
        return found
        
    pattern = os.path.join(user_profile, "AppData", "Local", "Packages", "*", "LocalState", "rootfs", "home", "*", ".bash_history")
    for match in glob.glob(pattern):
        if os.path.exists(match) and os.access(match, os.R_OK):
            found.append(match)
            
    return found


def check_wsl_history() -> List[str]:
    """
    Checks for readable WSL history files.
    """
    found = []
    user_profile = os.environ.get("USERPROFILE", "")
    if not user_profile:
        return found
        
    pattern = os.path.join(user_profile, "AppData", "Local", "Packages", "*", "LocalState", "rootfs", "home", "*", ".wsl_history")
    for match in glob.glob(pattern):
        if os.path.exists(match) and os.access(match, os.R_OK):
            found.append(match)
            
    return found


@register_check
class GeneralMisconfigurationsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "general_misconfigs"
        
    @property
    def description(self) -> str:
        return "Checks for general misconfigurations like AlwaysInstallElevated and exposed WSL histories."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        if check_always_install_elevated():
            findings.append(Finding(
                title="AlwaysInstallElevated is Enabled",
                severity=Severity.CRITICAL,
                description="The AlwaysInstallElevated policy is enabled in both HKLM and HKCU. This allows a standard user to run any MSI installer with SYSTEM privileges.",
                evidence="HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated=1\nHKCU\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated=1",
                remediation="Disable the AlwaysInstallElevated policy in both HKLM and HKCU via Group Policy or Registry.",
                check_id=self.name
            ))
            
        wsl_bash = check_wsl_bash_history()
        for f in wsl_bash:
            findings.append(Finding(
                title=f"Readable WSL bash_history: {os.path.basename(f)}",
                severity=Severity.MEDIUM,
                description=f"A readable WSL bash history file was found at {f}. This may contain passwords or sensitive commands.",
                evidence=f,
                remediation="Clear the history file and ensure sensitive data is not stored in it.",
                check_id=self.name
            ))
            
        wsl_hist = check_wsl_history()
        for f in wsl_hist:
            findings.append(Finding(
                title=f"Readable WSL wsl_history: {os.path.basename(f)}",
                severity=Severity.MEDIUM,
                description=f"A readable WSL history file was found at {f}. This may contain passwords or sensitive commands.",
                evidence=f,
                remediation="Clear the history file and ensure sensitive data is not stored in it.",
                check_id=self.name
            ))
            
        return findings
