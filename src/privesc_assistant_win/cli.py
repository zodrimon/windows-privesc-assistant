import argparse
import sys

from privesc_assistant_win.core.engine import ScanEngine
from privesc_assistant_win.core.registry import registry
from privesc_assistant_win.config.loader import load_config
from privesc_assistant_win.reporting import get_reporter

# Import checks to trigger registration
import privesc_assistant_win.checks

VERSION = "0.1.0"


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

def scan(args):
    config = load_config(args.config)
    engine = ScanEngine(config)
    
    # Run the engine
    context, findings = engine.run_all()
    
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
