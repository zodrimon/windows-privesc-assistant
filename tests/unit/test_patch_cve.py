import pytest
from unittest.mock import patch
import os
import sys

from privesc_assistant_win.checks.windows.patch_cve import (
    get_os_version_build,
    get_installed_hotfixes,
    cross_reference_known_cves,
    PatchAndCveCheck
)

@patch("sys.getwindowsversion")
def test_get_os_version_build(mock_getwin):
    class MockWinVer:
        build = 19044
    mock_getwin.return_value = MockWinVer()
    assert get_os_version_build() == "19044"


@patch("subprocess.check_output")
def test_get_installed_hotfixes(mock_run):
    output = b"http://support.microsoft.com/?kbid=5004945  Update  KB5004945\n"
    mock_run.return_value = output
    hotfixes = get_installed_hotfixes()
    assert "KB5004945" in hotfixes


@patch("os.path.exists")
@patch("builtins.open")
@patch("json.load")
def test_cross_reference_known_cves(mock_load, mock_open, mock_exists):
    mock_exists.return_value = True
    mock_load.return_value = [
        {
            "cve": "CVE-TEST",
            "name": "TestVuln",
            "affected_builds": ["19044"],
            "patched_by": ["KB1234567"]
        }
    ]
    
    cves = cross_reference_known_cves("19044", ["KB0000000"])
    assert len(cves) == 1
    
    cves = cross_reference_known_cves("19044", ["KB1234567"])
    assert len(cves) == 0
    
    cves = cross_reference_known_cves("10000", ["KB0000000"])
    assert len(cves) == 0


@patch("privesc_assistant_win.checks.windows.patch_cve.get_installed_hotfixes")
@patch("privesc_assistant_win.checks.windows.patch_cve.cross_reference_known_cves")
def test_patch_cve_check(mock_cves, mock_hotfixes):
    mock_hotfixes.return_value = []
    mock_cves.return_value = [{"cve": "CVE-TEST", "name": "Test", "description": "desc"}]
    
    check = PatchAndCveCheck()
    from privesc_assistant_win.core.scan_context import ScanContext
    ctx = ScanContext(hostname="Test", os_build="19044", os_version="1", timestamp="t", config={}, is_elevated=False, current_user="u")
    
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "CVE-TEST" in findings[0].title
