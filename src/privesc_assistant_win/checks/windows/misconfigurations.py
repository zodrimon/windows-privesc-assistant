import os
import winreg
import glob
import subprocess
from typing import List, Dict, Any

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def check_always_install_elevated() -> bool:
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
    found = []
    user_profile = os.environ.get("USERPROFILE", "")
    if not user_profile:
        return found
        
    pattern = os.path.join(user_profile, "AppData", "Local", "Packages", "*", "LocalState", "rootfs", "home", "*", ".wsl_history")
    for match in glob.glob(pattern):
        if os.path.exists(match) and os.access(match, os.R_OK):
            found.append(match)
            
    return found


def enumerate_autorun_registry_keys() -> List[Dict[str, str]]:
    autoruns = []
    keys_to_check = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    
    for hive, path in keys_to_check:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        autoruns.append({
                            "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            "key": path,
                            "name": name,
                            "value": str(value)
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
            
    return autoruns

def check_autorun_targets_writable(autoruns: List[Dict[str, str]]) -> List[Dict[str, str]]:
    writable = []
    for entry in autoruns:
        val = entry["value"]
        target = ""
        if val.startswith('"'):
            parts = val.split('"')
            if len(parts) >= 3:
                target = parts[1]
        else:
            target = val.split()[0] if val else ""
            
        if target and os.path.exists(target):
            if os.access(target, os.W_OK):
                writable.append(entry)
    return writable

def enumerate_startup_folder_items() -> List[str]:
    items = []
    profiles = [
        os.environ.get("USERPROFILE", ""),
        os.environ.get("ALLUSERSPROFILE", "")
    ]
    
    for profile in profiles:
        if not profile: continue
        startup_path = os.path.join(profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if profile == os.environ.get("ALLUSERSPROFILE", ""):
            startup_path = os.path.join(profile, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            
        if os.path.exists(startup_path):
            for f in os.listdir(startup_path):
                items.append(os.path.join(startup_path, f))
    return items

def check_startup_folder_writable() -> List[str]:
    writable = []
    for f in enumerate_startup_folder_items():
        if os.access(f, os.W_OK):
            writable.append(f)
    return writable

def check_uac_settings() -> Dict[str, Any]:
    settings = {}
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            for name in ["EnableLUA", "ConsentPromptBehaviorAdmin", "LocalAccountTokenFilterPolicy"]:
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    settings[name] = val
                except FileNotFoundError:
                    settings[name] = None
    except FileNotFoundError:
        pass
    return settings

def check_saved_credentials_cmdkey() -> str:
    try:
        output = subprocess.check_output("cmdkey /list", stderr=subprocess.DEVNULL, shell=True).decode("mbcs", errors="ignore")
        if "Target:" in output or "Cible" in output:
            return output.strip()
    except Exception:
        pass
    return ""

def check_unattended_install_files() -> List[str]:
    found = []
    paths = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Autounattend.xml",
        r"C:\Windows\System32\sysprep\unattend.xml",
        r"C:\Windows\System32\sysprep\sysprep.xml",
        r"C:\Windows\System32\sysprep\sysprep.inf"
    ]
    for p in paths:
        if os.path.exists(p) and os.access(p, os.R_OK):
            found.append(p)
    return found

def check_powershell_history_file() -> str:
    up = os.environ.get("USERPROFILE", "")
    if up:
        p = os.path.join(up, r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(p) and os.access(p, os.R_OK):
            return p
    return ""

def check_saved_wifi_passwords() -> bool:
    try:
        output = subprocess.check_output("netsh wlan show profile", stderr=subprocess.DEVNULL, shell=True).decode("mbcs", errors="ignore")
        if "All User Profile" in output:
            return True
    except Exception:
        pass
    return False

def check_autologon_credentials() -> Dict[str, str]:
    creds = {}
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            try:
                auto_logon, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
                if auto_logon == "1" or auto_logon == 1:
                    creds["AutoAdminLogon"] = "1"
                    for val in ["DefaultUserName", "DefaultDomainName", "DefaultPassword"]:
                        try:
                            v, _ = winreg.QueryValueEx(key, val)
                            creds[val] = v
                        except FileNotFoundError:
                            pass
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass
    return creds


@register_check
class GeneralMisconfigurationsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "general_misconfigs"
        
    @property
    def description(self) -> str:
        return "Checks for general misconfigurations: AutoRun, Startup, UAC, cmdkey, Unattend, history, Winlogon."
        
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
            
        for f in check_wsl_bash_history():
            findings.append(Finding(title=f"Readable WSL bash_history: {os.path.basename(f)}", severity=Severity.MEDIUM, description=f"Found readable WSL bash history at {f}.", evidence=f, remediation="Clear the history file.", check_id=self.name))
            
        for f in check_wsl_history():
            findings.append(Finding(title=f"Readable WSL wsl_history: {os.path.basename(f)}", severity=Severity.MEDIUM, description=f"Found readable WSL history at {f}.", evidence=f, remediation="Clear the history file.", check_id=self.name))
            
        autoruns = enumerate_autorun_registry_keys()
        writable_autoruns = check_autorun_targets_writable(autoruns)
        for a in writable_autoruns:
            findings.append(Finding(title=f"Writable Autorun Binary: {a['name']}", severity=Severity.HIGH, description=f"The autorun {a['name']} at {a['hive']}\\{a['key']} points to a writable file.", evidence=a['value'], remediation="Fix file permissions.", check_id=self.name))
            
        writable_startup = check_startup_folder_writable()
        for f in writable_startup:
            findings.append(Finding(title=f"Writable Startup Folder Item: {os.path.basename(f)}", severity=Severity.HIGH, description=f"Writable file found in Startup folder: {f}.", evidence=f, remediation="Fix file permissions or remove the item.", check_id=self.name))
            
        uac = check_uac_settings()
        if uac.get("EnableLUA") == 0:
            findings.append(Finding(title="UAC is Disabled (EnableLUA=0)", severity=Severity.MEDIUM, description="User Account Control is completely disabled.", evidence="EnableLUA=0", remediation="Enable UAC.", check_id=self.name))
            
        cmdkey = check_saved_credentials_cmdkey()
        if cmdkey:
            findings.append(Finding(title="Stored Credentials Found (cmdkey)", severity=Severity.HIGH, description="Stored Windows credentials found.", evidence=cmdkey, remediation="Remove stored credentials if not needed.", check_id=self.name))
            
        for uf in check_unattended_install_files():
            findings.append(Finding(title=f"Unattended Install File Found: {os.path.basename(uf)}", severity=Severity.MEDIUM, description=f"Found {uf} which may contain passwords.", evidence=uf, remediation="Remove the file or delete passwords from it.", check_id=self.name))
            
        ps_hist = check_powershell_history_file()
        if ps_hist:
            findings.append(Finding(title="PowerShell History File Readable", severity=Severity.LOW, description=f"Found PowerShell history at {ps_hist}.", evidence=ps_hist, remediation="Clear history if it contains secrets.", check_id=self.name))
            
        if check_saved_wifi_passwords():
            findings.append(Finding(title="Saved WiFi Profiles Found", severity=Severity.INFO, description="Saved WiFi profiles exist and their passwords might be readable.", evidence="netsh wlan show profile", remediation="Forget WiFi networks if not needed.", check_id=self.name))
            
        autologon = check_autologon_credentials()
        if autologon:
            findings.append(Finding(title="AutoAdminLogon Credentials in Registry", severity=Severity.HIGH, description="Plaintext AutoAdminLogon credentials found in Winlogon registry keys.", evidence=str(autologon), remediation="Remove AutoAdminLogon or delete the DefaultPassword key.", check_id=self.name))
            
        return findings
