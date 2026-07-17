import pytest
from unittest.mock import patch
import os
import subprocess

from privesc_assistant_win.checks.windows.scheduled_tasks import (
    enumerate_scheduled_tasks,
    check_task_binary_writable,
    _extract_task_binary_path,
    ScheduledTasksCheck
)

@patch("subprocess.check_output")
def test_enumerate_scheduled_tasks(mock_run):
    csv_out = b'"TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months"\n"\\TestTask","N/A","Ready","Interactive/Background","N/A","1","TestAuthor","C:\\App\\app.exe","N/A","N/A","Enabled","Disabled","","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","One Time Only","00:00:00","2023-01-01","N/A","N/A","N/A"'
    mock_run.return_value = csv_out
    
    tasks = enumerate_scheduled_tasks()
    assert len(tasks) == 1
    assert tasks[0]["name"] == "\\TestTask"
    assert tasks[0]["run_as"] == "SYSTEM"
    assert tasks[0]["task_to_run"] == "C:\\App\\app.exe"


def test_extract_task_binary_path():
    assert _extract_task_binary_path('"C:\\Program Files\\app.exe" -arg') == 'C:\\Program Files\\app.exe'
    assert _extract_task_binary_path('C:\\App\\app.exe -arg') == 'C:\\App\\app.exe'


@patch("os.path.exists")
@patch("os.access")
def test_check_task_binary_writable(mock_access, mock_exists):
    mock_exists.return_value = True
    mock_access.return_value = True
    
    tasks = [
        {"name": "test1", "run_as": "system", "task_to_run": "C:\\App\\app.exe"},
        {"name": "test2", "run_as": "user", "task_to_run": "C:\\App\\app2.exe"}
    ]
    
    flagged = check_task_binary_writable(tasks)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "test1"


@patch("privesc_assistant_win.checks.windows.scheduled_tasks.enumerate_scheduled_tasks")
@patch("privesc_assistant_win.checks.windows.scheduled_tasks.check_task_binary_writable")
def test_scheduled_tasks_check(mock_check, mock_enum):
    mock_enum.return_value = []
    mock_check.return_value = [{"name": "vuln_task", "run_as": "system", "task_to_run": "C:\\App\\app.exe"}]
    
    check = ScheduledTasksCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="1", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "vuln_task" in findings[0].title
