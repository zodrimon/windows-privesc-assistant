from privesc_assistant_win.reporting.base_reporter import BaseReporter
from privesc_assistant_win.reporting.terminal_reporter import TerminalReporter
from privesc_assistant_win.reporting.json_reporter import JsonReporter

REPORTERS = {
    "text": TerminalReporter(),
    "json": JsonReporter()
}

def get_reporter(format_name: str) -> BaseReporter:
    return REPORTERS.get(format_name, TerminalReporter())
