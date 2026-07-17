import sys
import subprocess
import json
import os
from typing import List, Dict, Any

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def get_os_version_build() -> str:
    """
    Returns the Windows build number.
    """
    try:
        return str(sys.getwindowsversion().build)
    except AttributeError:
        return "Unknown"


def get_installed_hotfixes() -> List[str]:
    """
    Returns a list of installed KB strings by querying wmic.
    """
    hotfixes = []
    try:
        output = subprocess.check_output(["wmic", "qfe", "list", "brief"], stderr=subprocess.DEVNULL)
        decoded = output.decode("mbcs", errors="replace")
        
        for line in decoded.splitlines():
            line = line.strip()
            if not line:
                continue
                
            parts = line.split()
            for p in parts:
                if p.upper().startswith("KB"):
                    hotfixes.append(p.upper())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    return list(set(hotfixes))


def cross_reference_known_cves(os_build: str, hotfixes: List[str]) -> List[Dict[str, Any]]:
    """
    Queries data/known_cves.json to find unpatched vulnerabilities for the current OS build.
    """
    vulnerabilities = []
    
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "data")
    cve_file = os.path.join(data_dir, "known_cves.json")
    
    if not os.path.exists(cve_file):
        cve_file = os.path.join(sys.prefix, "share", "privesc_assistant_win", "data", "known_cves.json")
        
    if not os.path.exists(cve_file):
        return []
        
    with open(cve_file, "r", encoding="utf-8") as f:
        cve_db = json.load(f)
        
    hotfixes_upper = [h.upper() for h in hotfixes]
    
    for cve in cve_db:
        if os_build in cve.get("affected_builds", []):
            is_patched = False
            for patch in cve.get("patched_by", []):
                if patch.upper() in hotfixes_upper:
                    is_patched = True
                    break
                    
            if not is_patched:
                vulnerabilities.append(cve)
                
    return vulnerabilities


@register_check
class PatchAndCveCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "patch_cve"
        
    @property
    def description(self) -> str:
        return "Checks the OS build and installed hotfixes against a database of known LPE vulnerabilities."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        
        os_build = context.os_build
        if not os_build or os_build == "Unknown":
            os_build = get_os_version_build()
            
        hotfixes = get_installed_hotfixes()
        
        cves = cross_reference_known_cves(os_build, hotfixes)
        
        for cve in cves:
            findings.append(Finding(
                title=f"Unpatched Vulnerability: {cve['cve']} ({cve['name']})",
                severity=Severity.HIGH,
                description=f"The system (Build {os_build}) appears to be vulnerable to {cve['name']} ({cve['cve']}). {cve['description']}",
                evidence=f"Build: {os_build}, Missing Patches: {', '.join(cve.get('patched_by', []))}",
                remediation="Apply the relevant security updates (KBs) to patch this vulnerability.",
                check_id=self.name
            ))
            
        return findings
