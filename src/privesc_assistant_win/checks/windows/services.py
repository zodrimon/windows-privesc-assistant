import win32service
import pywintypes
from typing import List, Dict, Any


def enumerate_services() -> List[Dict[str, Any]]:
    """
    Enumerates all services on the system.
    Returns a list of dictionaries containing service details:
    name, display_name, binary_path, start_type, run_as
    """
    services = []
    scm_handle = None
    
    try:
        # Open the Service Control Manager
        scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        
        # Enumerate services (active and inactive)
        statuses = win32service.EnumServicesStatus(scm_handle, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
        
        for short_name, display_name, _ in statuses:
            service_info = {
                "name": short_name,
                "display_name": display_name,
                "binary_path": None,
                "start_type": None,
                "run_as": None
            }
            
            # Open individual service to get config
            try:
                svc_handle = win32service.OpenService(scm_handle, short_name, win32service.SERVICE_QUERY_CONFIG)
                config = win32service.QueryServiceConfig(svc_handle)
                
                # QueryServiceConfig returns a tuple:
                # (ServiceType, StartType, ErrorControl, BinaryPathName, LoadOrderGroup, TagId, Dependencies, ServiceStartName, DisplayName)
                service_info["start_type"] = config[1]
                service_info["binary_path"] = config[3]
                service_info["run_as"] = config[7]  # ServiceStartName is the account it runs under
                
                win32service.CloseServiceHandle(svc_handle)
            except pywintypes.error:
                # If we lack permissions to query this specific service, skip its details but keep the name
                pass
                
            services.append(service_info)
            
    except pywintypes.error as e:
        # If we can't open SCM, just raise it up to be caught by the safe wrapper
        raise e
    finally:
        if scm_handle:
            win32service.CloseServiceHandle(scm_handle)
            
    return services


def check_unquoted_service_paths(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flags service binary paths with spaces and no surrounding quotes.
    Returns a list of flagged services.
    """
    flagged = []
    for svc in services:
        path = svc.get("binary_path")
        if not path:
            continue
            
        if not path.startswith('"') and not path.startswith("'"):
            if " " in path and ".exe" in path.lower():
                idx = path.lower().find(".exe")
                base_path = path[:idx + 4]
                if " " in base_path:
                    flagged.append(svc)
    return flagged


def _extract_binary_path(full_path: str) -> str:
    """Helper to extract the actual executable path from a service command line."""
    if not full_path:
        return ""
    if full_path.startswith('"') or full_path.startswith("'"):
        quote = full_path[0]
        end_idx = full_path.find(quote, 1)
        if end_idx != -1:
            return full_path[1:end_idx]
    
    idx = full_path.lower().find(".exe")
    if idx != -1:
        return full_path[:idx + 4]
        
    return full_path.split(" ")[0]


def check_service_binary_writable(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Checks if the current user has write access to the service binary.
    """
    import os
    flagged = []
    for svc in services:
        path = svc.get("binary_path")
        if not path:
            continue
            
        bin_path = _extract_binary_path(path)
        if not bin_path or not os.path.exists(bin_path):
            continue
            
        if os.access(bin_path, os.W_OK):
            flagged.append(svc)
            
    return flagged


def check_service_registry_key_writable(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Checks if the current user has write access to the service's registry key.
    """
    import winreg
    flagged = []
    for svc in services:
        name = svc.get("name")
        if not name:
            continue
            
        key_path = f"SYSTEM\\CurrentControlSet\\Services\\{name}"
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.CloseKey(hkey)
            flagged.append(svc)
        except OSError:
            pass
            
    return flagged


def check_service_control_permissions(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Checks if the current user can reconfigure a given service.
    """
    flagged = []
    scm_handle = None
    try:
        scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        
        for svc in services:
            name = svc.get("name")
            if not name:
                continue
                
            try:
                access = win32service.SERVICE_CHANGE_CONFIG
                svc_handle = win32service.OpenService(scm_handle, name, access)
                win32service.CloseServiceHandle(svc_handle)
                flagged.append(svc)
            except pywintypes.error:
                pass
                
    except pywintypes.error:
        pass
    finally:
        if scm_handle:
            win32service.CloseServiceHandle(scm_handle)
            
    return flagged


def cross_reference_known_vulnerable_services(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Checks services against a known vulnerable services database.
    """
    import json
    import os
    
    flagged = []
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_file = os.path.abspath(os.path.join(current_dir, "..", "..", "..", "..", "data", "known_vulnerable_services.json"))
    
    if not os.path.exists(data_file):
        return []
        
    with open(data_file, "r", encoding="utf-8") as f:
        known_vulns = json.load(f)
        
    for svc in services:
        name = svc.get("name", "").lower()
        if name in known_vulns:
            svc["vuln_note"] = known_vulns[name]
            flagged.append(svc)
            
    return flagged


from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check

@register_check
class ServicesCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "service_misconfigurations"
        
    @property
    def description(self) -> str:
        return "Checks for unquoted service paths, writable service binaries, writable service registry keys, and permissive service ACLs."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        services = enumerate_services()
        
        # 1. Unquoted Service Paths
        unquoted = check_unquoted_service_paths(services)
        for svc in unquoted:
            findings.append(Finding(
                title=f"Unquoted Service Path: {svc['name']}",
                severity=Severity.MEDIUM,
                description=f"The service {svc['name']} has an unquoted binary path: {svc['binary_path']}. This may allow an attacker to hijack the service by placing an executable in a matching path.",
                evidence=svc['binary_path'],
                remediation="Enclose the service binary path in quotes in the registry.",
                check_id=self.name
            ))
            
        # 2. Writable Service Binaries
        writable_bins = check_service_binary_writable(services)
        for svc in writable_bins:
            severity = Severity.CRITICAL if str(svc.get("start_type")) == "2" else Severity.HIGH
            findings.append(Finding(
                title=f"Writable Service Binary: {svc['name']}",
                severity=severity,
                description=f"The service {svc['name']} points to a binary that is writable by the current user: {svc['binary_path']}.",
                evidence=svc['binary_path'],
                remediation="Restrict write access to the service binary.",
                check_id=self.name
            ))
            
        # 3. Writable Service Registry Keys
        writable_keys = check_service_registry_key_writable(services)
        for svc in writable_keys:
            severity = Severity.CRITICAL if str(svc.get("start_type")) == "2" else Severity.HIGH
            findings.append(Finding(
                title=f"Writable Service Registry Key: {svc['name']}",
                severity=severity,
                description=f"The current user has write access to the registry key for service {svc['name']}.",
                evidence=f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc['name']}",
                remediation="Restrict write access to the service registry key.",
                check_id=self.name
            ))
            
        # 4. Service Control Permissions
        control_perms = check_service_control_permissions(services)
        for svc in control_perms:
            findings.append(Finding(
                title=f"Service Reconfiguration Rights: {svc['name']}",
                severity=Severity.HIGH,
                description=f"The current user has SERVICE_CHANGE_CONFIG rights over service {svc['name']}.",
                evidence=svc['name'],
                remediation="Restrict access controls on the service via sc sdset.",
                check_id=self.name
            ))
            
        # 5. Known Vulnerable Services
        known_vulns = cross_reference_known_vulnerable_services(services)
        for svc in known_vulns:
            findings.append(Finding(
                title=f"Known Vulnerable Service Installed: {svc['name']}",
                severity=Severity.MEDIUM,
                description=f"A known vulnerable service was detected: {svc['name']}. Note: {svc['vuln_note']}",
                evidence=svc['name'],
                remediation="Apply patches or disable the service if not required.",
                check_id=self.name
            ))
            
        return findings
