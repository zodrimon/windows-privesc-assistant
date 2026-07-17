import pytest
from unittest.mock import patch
import os

from privesc_assistant_win.checks.windows.path import (
    enumerate_system_path,
    check_writable_paths,
    WritablePathCheck
)

@patch.dict(os.environ, {"PATH": "C:\\Windows\\System32;C:\\Program Files\\App; ;"})
def test_enumerate_system_path():
    paths = enumerate_system_path()
    assert len(paths) == 2
    assert "C:\\Windows\\System32" in paths
    assert "C:\\Program Files\\App" in paths

@patch("os.path.exists")
@patch("os.path.isdir")
@patch("os.access")
def test_check_writable_paths(mock_access, mock_isdir, mock_exists):
    mock_exists.return_value = True
    mock_isdir.return_value = True
    
    def access_side_effect(path, mode):
        if path == "C:\\Writable":
            return True
        return False
    mock_access.side_effect = access_side_effect
    
    paths = ["C:\\Windows", "C:\\Writable"]
    writable = check_writable_paths(paths)
    assert len(writable) == 1
    assert writable[0] == "C:\\Writable"

@patch("privesc_assistant_win.checks.windows.path.check_writable_paths")
@patch("privesc_assistant_win.checks.windows.path.enumerate_system_path")
def test_writable_path_check(mock_enum, mock_check):
    mock_enum.return_value = ["C:\\Writable"]
    mock_check.return_value = ["C:\\Writable"]
    
    check = WritablePathCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="1", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "C:\\Writable" in findings[0].title
