import pytest
from unittest.mock import patch, MagicMock

from privesc_assistant_win.cli import list_checks, scan


@patch("privesc_assistant_win.cli.registry")
@patch("builtins.print")
def test_cli_list_checks(mock_print, mock_registry):
    mock_check = MagicMock()
    mock_check.name = "test_check"
    mock_check.description = "Test Check"
    mock_registry.get_all_checks.return_value = {"test_check": mock_check}
    
    list_checks()
    
    mock_print.assert_any_call("  - test_check: Test Check")


@patch("privesc_assistant_win.cli.ScanEngine")
@patch("privesc_assistant_win.cli.load_config")
@patch("privesc_assistant_win.cli.get_reporter")
def test_cli_scan(mock_reporter, mock_load_config, mock_engine_class):
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine
    mock_engine.run_all.return_value = (MagicMock(), [MagicMock()])
    
    class Args:
        config = "test.yaml"
        output = None
        format = "text"
    
    args = Args()
    scan(args)
    
    mock_engine_class.assert_called_once()
    mock_engine.run_all.assert_called_once()
