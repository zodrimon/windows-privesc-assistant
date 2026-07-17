import pytest
from unittest.mock import patch
import win32security

from privesc_assistant_win.checks.windows.token_privileges import (
    enumerate_current_token_privileges,
    TokenPrivilegesCheck
)

@patch("win32api.GetCurrentProcess")
@patch("win32security.OpenProcessToken")
@patch("win32security.GetTokenInformation")
@patch("win32security.LookupPrivilegeName")
def test_enumerate_current_token_privileges(mock_lookup, mock_getinfo, mock_open, mock_getproc):
    mock_getproc.return_value = "hProcess"
    mock_open.return_value = "hToken"
    
    mock_getinfo.return_value = [
        (1234, win32security.SE_PRIVILEGE_ENABLED),
        (5678, 0)
    ]
    
    def lookup_side_effect(system_name, luid):
        if luid == 1234:
            return "SeImpersonatePrivilege"
        return "SeChangeNotifyPrivilege"
        
    mock_lookup.side_effect = lookup_side_effect
    
    privs = enumerate_current_token_privileges()
    assert len(privs) == 2
    assert privs[0]["name"] == "SeImpersonatePrivilege"
    assert privs[0]["enabled"] == True
    
    assert privs[1]["name"] == "SeChangeNotifyPrivilege"
    assert privs[1]["enabled"] == False


@patch("privesc_assistant_win.checks.windows.token_privileges.enumerate_current_token_privileges")
def test_token_privileges_check(mock_enum):
    mock_enum.return_value = [
        {"name": "SeImpersonatePrivilege", "enabled": True, "default_enabled": True},
        {"name": "SeChangeNotifyPrivilege", "enabled": True, "default_enabled": True},
    ]
    
    check = TokenPrivilegesCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="1", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "SeImpersonatePrivilege" in findings[0].title
