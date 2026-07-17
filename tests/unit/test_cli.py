import pytest
from unittest.mock import patch

from privesc_assistant_win.cli import main


@patch("sys.argv", ["privesc-assistant-win", "--list-checks"])
@patch("privesc_assistant_win.cli.cmd_list_checks")
def test_cli_list_checks(mock_cmd):
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    mock_cmd.assert_called_once()


@patch("sys.argv", ["privesc-assistant-win", "scan"])
@patch("privesc_assistant_win.cli.cmd_scan")
def test_cli_scan(mock_cmd):
    main()
    mock_cmd.assert_called_once()


@patch("sys.argv", ["privesc-assistant-win"])
@patch("privesc_assistant_win.cli.argparse.ArgumentParser.print_help")
def test_cli_no_args(mock_help):
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1
    mock_help.assert_called_once()
