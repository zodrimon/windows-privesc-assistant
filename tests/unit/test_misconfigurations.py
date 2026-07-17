import pytest
from unittest.mock import patch
import os

from privesc_assistant_win.checks.windows.misconfigurations import (
    check_always_install_elevated,
    check_wsl_bash_history,
    check_wsl_history,
    GeneralMisconfigurationsCheck
)

@patch("winreg.QueryValueEx")
@patch("winreg.OpenKey")
def test_check_always_install_elevated(mock_open, mock_query):
    mock_query.return_value = (1, 4)
    assert check_always_install_elevated() == True
    
    mock_query.return_value = (0, 4)
    assert check_always_install_elevated() == False

@patch("os.environ.get")
@patch("glob.glob")
@patch("os.path.exists")
@patch("os.access")
def test_check_wsl_bash_history(mock_access, mock_exists, mock_glob, mock_env):
    mock_env.return_value = "C:\\Users\\Test"
    mock_glob.return_value = ["C:\\Users\\Test\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\\LocalState\\rootfs\\home\\test\\.bash_history"]
    mock_exists.return_value = True
    mock_access.return_value = True
    
    found = check_wsl_bash_history()
    assert len(found) == 1
    assert ".bash_history" in found[0]

@patch("os.environ.get")
@patch("glob.glob")
@patch("os.path.exists")
@patch("os.access")
def test_check_wsl_history(mock_access, mock_exists, mock_glob, mock_env):
    mock_env.return_value = "C:\\Users\\Test"
    mock_glob.return_value = ["C:\\Users\\Test\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\\LocalState\\rootfs\\home\\test\\.wsl_history"]
    mock_exists.return_value = True
    mock_access.return_value = True
    
    found = check_wsl_history()
    assert len(found) == 1
    assert ".wsl_history" in found[0]

@patch("privesc_assistant_win.checks.windows.misconfigurations.check_always_install_elevated")
@patch("privesc_assistant_win.checks.windows.misconfigurations.check_wsl_bash_history")
@patch("privesc_assistant_win.checks.windows.misconfigurations.check_wsl_history")
def test_general_misconfigs_check(mock_wsl, mock_bash, mock_aie):
    mock_aie.return_value = True
    mock_bash.return_value = ["C:\\test\\.bash_history"]
    mock_wsl.return_value = ["C:\\test\\.wsl_history"]
    
    check = GeneralMisconfigurationsCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="19044", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 3
