import pytest
from unittest.mock import patch, MagicMock
import os
import winreg

from privesc_assistant_win.checks.windows.misconfigurations import (
    check_always_install_elevated,
    check_wsl_bash_history,
    check_wsl_history,
    enumerate_autorun_registry_keys,
    check_autorun_targets_writable,
    enumerate_startup_folder_items,
    check_startup_folder_writable,
    check_uac_settings,
    check_saved_credentials_cmdkey,
    check_unattended_install_files,
    check_powershell_history_file,
    check_saved_wifi_passwords,
    check_autologon_credentials,
    GeneralMisconfigurationsCheck
)
from privesc_assistant_win.core.scan_context import ScanContext

@patch("winreg.QueryValueEx")
@patch("winreg.OpenKey")
def test_check_always_install_elevated(mock_open, mock_query):
    mock_query.return_value = (1, 4)
    assert check_always_install_elevated() == True
    
    mock_query.return_value = (0, 4)
    assert check_always_install_elevated() == False

@patch("winreg.EnumValue")
@patch("winreg.OpenKey")
def test_enumerate_autorun_registry_keys(mock_open, mock_enum):
    # Only return values on the very first call, then OSError
    call_count = [0]
    def mock_enum_val(key, i):
        if call_count[0] == 0:
            call_count[0] += 1
            return ("App1", "C:\\App1.exe", 1)
        raise OSError()
        
    mock_enum.side_effect = mock_enum_val
    autoruns = enumerate_autorun_registry_keys()
    assert len(autoruns) > 0
    assert autoruns[0]["name"] == "App1"

@patch("os.path.exists")
@patch("os.access")
def test_check_autorun_targets_writable(mock_access, mock_exists):
    mock_exists.return_value = True
    mock_access.return_value = True
    autoruns = [{"hive": "HKCU", "key": "Run", "name": "App1", "value": "C:\\App1.exe"}]
    writable = check_autorun_targets_writable(autoruns)
    assert len(writable) == 1

@patch("os.path.exists")
@patch("os.listdir")
def test_enumerate_startup_folder_items(mock_listdir, mock_exists):
    mock_exists.return_value = True
    mock_listdir.return_value = ["App1.lnk"]
    items = enumerate_startup_folder_items()
    assert len(items) > 0
    assert "App1.lnk" in items[0]

@patch("winreg.QueryValueEx")
@patch("winreg.OpenKey")
def test_check_uac_settings(mock_open, mock_query):
    mock_query.return_value = (0, 4)
    settings = check_uac_settings()
    assert settings.get("EnableLUA") == 0

@patch("subprocess.check_output")
def test_check_saved_credentials_cmdkey(mock_subprocess):
    mock_subprocess.return_value = b"Target: LegacyGeneric"
    assert "Target:" in check_saved_credentials_cmdkey()

@patch("os.path.exists")
@patch("os.access")
def test_check_unattended_install_files(mock_access, mock_exists):
    mock_exists.return_value = True
    mock_access.return_value = True
    files = check_unattended_install_files()
    assert len(files) == 5

@patch("os.path.exists")
@patch("os.access")
def test_check_powershell_history_file(mock_access, mock_exists):
    mock_exists.return_value = True
    mock_access.return_value = True
    assert check_powershell_history_file() != ""

@patch("subprocess.check_output")
def test_check_saved_wifi_passwords(mock_subprocess):
    mock_subprocess.return_value = b"All User Profile: MyWiFi"
    assert check_saved_wifi_passwords() == True

@patch("winreg.QueryValueEx")
@patch("winreg.OpenKey")
def test_check_autologon_credentials(mock_open, mock_query):
    mock_query.side_effect = [("1", 1), ("User", 1), ("Domain", 1), ("Pass", 1)]
    creds = check_autologon_credentials()
    assert creds.get("AutoAdminLogon") == "1"
    assert creds.get("DefaultPassword") == "Pass"
