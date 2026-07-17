import subprocess
import csv
import io
import os
from typing import List, Dict, Any

from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.finding import Finding, Severity
from privesc_assistant_win.core.registry import register_check


def enumerate_scheduled_tasks() -> List[Dict[str, Any]]:
    """
    Enumerates scheduled tasks using schtasks.exe.
    """
    tasks = []
    try:
        output = subprocess.check_output(["schtasks", "/query", "/fo", "CSV", "/v"], stderr=subprocess.DEVNULL)
        decoded = output.decode("mbcs", errors="replace")
        
        reader = csv.reader(io.StringIO(decoded))
        
        headers = []
        for row in reader:
            if not headers:
                if row and len(row) > 5:
                    headers = [h.strip().lower() for h in row]
                continue
                
            if len(row) != len(headers):
                continue
                
            task = dict(zip(headers, row))
            
            task_name = task.get("taskname", "")
            run_as = task.get("run as user", task.get("run as", ""))
            task_to_run = task.get("task to run", "")
            
            if not task_name:
                for k, v in task.items():
                    if "name" in k: task_name = v
                    if "run as" in k or "user" in k: run_as = v
                    if "task to run" in k or "action" in k: task_to_run = v
            
            if task_name and task_to_run and task_to_run.lower() != "com handler" and task_to_run != "N/A":
                tasks.append({
                    "name": task_name.strip(),
                    "run_as": run_as.strip(),
                    "task_to_run": task_to_run.strip()
                })
                
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    return tasks


def _extract_task_binary_path(task_to_run: str) -> str:
    """Extracts binary path from the task action."""
    if not task_to_run:
        return ""
        
    if task_to_run.startswith('"') or task_to_run.startswith("'"):
        quote = task_to_run[0]
        end_idx = task_to_run.find(quote, 1)
        if end_idx != -1:
            return task_to_run[1:end_idx]
            
    idx = task_to_run.lower().find(".exe")
    if idx != -1:
        return task_to_run[:idx + 4]
        
    return task_to_run.split(" ")[0]


def check_task_binary_writable(tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flags tasks running as SYSTEM/Admin with a binary writable by the current user.
    """
    flagged = []
    
    privileged_users = ["system", "nt authority\\system", "administrators", "builtin\\administrators"]
    
    for task in tasks:
        run_as = task.get("run_as", "").lower()
        if not run_as:
            continue
            
        is_privileged = False
        for pu in privileged_users:
            if pu in run_as:
                is_privileged = True
                break
                
        if not is_privileged:
            continue
            
        bin_path = _extract_task_binary_path(task.get("task_to_run", ""))
        if not bin_path or not os.path.exists(bin_path):
            continue
            
        if os.access(bin_path, os.W_OK):
            flagged.append(task)
            
    return flagged


@register_check
class ScheduledTasksCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "scheduled_tasks"
        
    @property
    def description(self) -> str:
        return "Checks for privileged scheduled tasks whose binaries are writable by the current user."
        
    def run(self, context: ScanContext) -> List[Finding]:
        findings = []
        tasks = enumerate_scheduled_tasks()
        writable_tasks = check_task_binary_writable(tasks)
        
        for task in writable_tasks:
            findings.append(Finding(
                title=f"Writable Scheduled Task Binary: {task['name']}",
                severity=Severity.HIGH,
                description=f"The scheduled task {task['name']} runs as {task['run_as']}, but its binary is writable by the current user: {task['task_to_run']}. An attacker can replace this binary to execute code as {task['run_as']}.",
                evidence=task['task_to_run'],
                remediation="Restrict write access to the scheduled task binary.",
                check_id=self.name
            ))
            
        return findings
