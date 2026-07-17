import pytest
from unittest.mock import patch
import os

from privesc_assistant_win.checks.windows.weak_permissions import (
    get_acl_for_path,
    check_sam_system_readable,
    check_unattend_files,
    WeakPermissionsCheck
)

@patch("os.path.exists")
@patch("win32security.GetFileSecurity")
def test_get_acl_for_path(mock_get_sec, mock_exists):
    mock_exists.return_value = True
    
    class MockSD:
        def GetSecurityDescriptorDacl(self):
            return None
    mock_get_sec.return_value = MockSD()
    
    acls = get_acl_for_path("C:\\test")
    assert len(acls) == 0


@patch("os.path.exists")
@patch("os.access")
def test_check_sam_system_readable(mock_access, mock_exists):
    mock_exists.return_value = True
    
    def access_side_effect(path, mode):
        if "SAM" in path:
            return True
        return False
    mock_access.side_effect = access_side_effect
    
    readable = check_sam_system_readable()
    assert len(readable) == 2


@patch("os.path.exists")
@patch("os.access")
def test_check_unattend_files(mock_access, mock_exists):
    mock_exists.return_value = True
    
    def access_side_effect(path, mode):
        if "unattend.xml" in path.lower():
            return True
        return False
    mock_access.side_effect = access_side_effect
    
    found = check_unattend_files()
    assert len(found) > 0


@patch("privesc_assistant_win.checks.windows.weak_permissions.check_sam_system_readable")
@patch("privesc_assistant_win.checks.windows.weak_permissions.check_unattend_files")
def test_weak_permissions_check(mock_unattend, mock_sam):
    mock_sam.return_value = ["C:\\Windows\\System32\\config\\SAM"]
    mock_unattend.return_value = ["C:\\unattend.xml"]
    
    check = WeakPermissionsCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="1", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 2
