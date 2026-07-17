import argparse
import sys
import os
import platform
import ctypes
import datetime

from privesc_assistant_win.core.engine import ScanEngine
from privesc_assistant_win.core.registry import registry
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.config.loader import load_config
from privesc_assistant_win.reporting import get_reporter

# Import checks to trigger registration
import privesc_assistant_win.checks

VERSION = "0.1.1"


def create_parser():
    parser = argparse.ArgumentParser(
        description="Windows Privilege Escalation Assistant",
        prog="privesc-assistant-win"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"%(prog)s {VERSION}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run privesc checks")
    scan_parser.add_argument(
        "--config", 
        type=str, 
        help="Path to custom config file"
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format"
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        help="Output file path (default is stdout)"
    )
    
    # List command
    subparsers.add_parser("list", help="List available checks")
    
    return parser

def list_checks():
    checks = registry.get_all_checks()
    if not checks:
        print("No checks registered.")
        return
        
    print(f"Registered Checks ({len(checks)}):")
    for check_name, check_obj in checks.items():
        print(f"  - {check_obj.name}: {check_obj.description}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def scan(args):
    config = load_config(args.config)
    
    context = ScanContext(
        hostname=platform.node(),
        os_build=platform.version(),
        os_version=platform.platform(),
        timestamp=datetime.datetime.now().isoformat(),
        config=config,
        is_elevated=is_admin(),
        current_user=os.environ.get("USERNAME", "Unknown")
    )
    
    engine = ScanEngine(context)
    
    # Run the engine
    findings = engine.run_all()
    
    # Generate report
    reporter = get_reporter(args.format)
    report_str = reporter.generate(context, findings)
    
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_str)
        print(f"Report saved to {args.output}")
    else:
        print(report_str)


def main():
    parser = create_parser()
    
    # If double-clicked without arguments, pause before exiting so the window doesn't immediately close
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n[!] You must run this tool from the Command Prompt or PowerShell, or pass arguments.")
        input("Press Enter to exit...")
        sys.exit(1)
        
    args = parser.parse_args()
    
    if args.command == "scan":
        scan(args)
    elif args.command == "list":
        list_checks()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
