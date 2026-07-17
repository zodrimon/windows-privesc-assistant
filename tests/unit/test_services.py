import pytest
from unittest.mock import patch

from privesc_assistant_win.checks.windows.services import (
    _extract_binary_path,
    check_unquoted_service_paths,
    check_service_binary_writable,
    check_service_registry_key_writable,
    check_service_control_permissions,
    cross_reference_known_vulnerable_services
)

def test_extract_binary_path():
    assert _extract_binary_path('"C:\\Program Files\\app.exe" -arg') == 'C:\\Program Files\\app.exe'
    assert _extract_binary_path('C:\\Program Files\\app.exe -arg') == 'C:\\Program Files\\app.exe'
    assert _extract_binary_path('C:\\Windows\\System32\\svchost.exe -k netsvcs') == 'C:\\Windows\\System32\\svchost.exe'

def test_check_unquoted_service_paths():
    services = [
        {"name": "vuln1", "binary_path": 'C:\\Program Files\\Vuln App\\app.exe -arg'},
        {"name": "safe1", "binary_path": '"C:\\Program Files\\Vuln App\\app.exe" -arg'},
        {"name": "safe2", "binary_path": 'C:\\Windows\\System32\\svchost.exe -k'}
    ]
    flagged = check_unquoted_service_paths(services)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "vuln1"

@patch("os.access")
@patch("os.path.exists")
def test_check_service_binary_writable(mock_exists, mock_access):
    mock_exists.return_value = True
    mock_access.return_value = True
    
    services = [{"name": "test", "binary_path": 'C:\\App\\app.exe'}]
    flagged = check_service_binary_writable(services)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "test"

@patch("winreg.OpenKey")
@patch("winreg.CloseKey")
def test_check_service_registry_key_writable(mock_close, mock_open):
    services = [{"name": "test", "binary_path": 'C:\\App\\app.exe'}]
    flagged = check_service_registry_key_writable(services)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "test"

@patch("win32service.OpenSCManager")
@patch("win32service.OpenService")
@patch("win32service.CloseServiceHandle")
def test_check_service_control_permissions(mock_close, mock_open, mock_scm):
    services = [{"name": "test"}]
    flagged = check_service_control_permissions(services)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "test"
    
@patch("os.path.exists")
@patch("builtins.open")
@patch("json.load")
def test_cross_reference_known_vulnerable_services(mock_load, mock_open, mock_exists):
    mock_exists.return_value = True
    mock_load.return_value = {"vuln_svc": "Test note"}
    
    services = [{"name": "vuln_svc"}, {"name": "safe_svc"}]
    flagged = cross_reference_known_vulnerable_services(services)
    assert len(flagged) == 1
    assert flagged[0]["name"] == "vuln_svc"
    assert flagged[0]["vuln_note"] == "Test note"
