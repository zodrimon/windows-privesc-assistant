import argparse
import sys
import logging
from datetime import datetime
import platform

from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.core.engine import ScanEngine
from privesc_assistant_win.core.utils import is_elevated
from privesc_assistant_win.core.registry import registry

VERSION = "0.1.0"


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def cmd_scan(args):
    setup_logging(args.verbose)
    logging.info("Starting privesc-assistant-win scan...")
    
    # Parse --checks argument if provided
    checks_list = []
    if args.checks:
        checks_list = [c.strip() for c in args.checks.split(",")]
        
    config = {
        "checks": checks_list
    }
    
    context = ScanContext(
        hostname=platform.node(),
        os_build=platform.version(),
        os_version=platform.release(),
        timestamp=datetime.now().isoformat(),
        config=config,
        is_elevated=is_elevated(),
        current_user="Unknown" # We will populate this properly later or via win32api
    )
    
    engine = ScanEngine(context)
    findings = engine.run_all()
    
    # Simple print for now until reporting engine is built
    print(f"{len(findings)} findings")


def cmd_list_checks(args):
    all_checks = registry.get_all_checks()
    if not all_checks:
        print("No checks registered.")
        return
        
    print("Registered Checks:")
    for name, check in all_checks.items():
        print(f"  - {name}: {check.description}")


def main():
    parser = argparse.ArgumentParser(
        description="windows-privesc-assistant: A CLI tool for Windows privilege escalation enumeration."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # 'scan' command
    scan_parser = subparsers.add_parser("scan", help="Run the privilege escalation scan")
    scan_parser.add_argument("--config", type=str, help="Path to YAML configuration file")
    scan_parser.add_argument("--output", type=str, help="Path to write output report")
    scan_parser.add_argument(
        "--format", 
        type=str, 
        choices=["terminal", "json", "md", "html"], 
        default="terminal",
        help="Output format (default: terminal)"
    )
    scan_parser.add_argument("--checks", type=str, help="Comma-separated list of check IDs to run (overrides config)")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")
    
    # 'list-checks' command (could also be a root flag --list-checks, but sub-command is cleaner, TASK-021 asks for commands)
    # Actually TASK-021 says "Add --version and --list-checks commands". I will add it as an argument or sub-command.
    # The wording "commands" implies either sub-commands or flags. Let's make it a root flag for simplicity.
    parser.add_argument("--list-checks", action="store_true", help="List all registered checks and exit")

    args = parser.parse_args()
    
    if args.list_checks:
        cmd_list_checks(args)
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
