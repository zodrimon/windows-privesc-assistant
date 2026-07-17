# Windows Privilege Escalation Assistant

A modular, extensible command-line tool for enumerating privilege escalation vectors on Windows systems.

> **Disclaimer:** This tool is intended for authorized security auditing, penetration testing, and red teaming only. Ensure you have explicit permission before scanning any systems you do not own.

## Features
- **Extensible Plugin Architecture**: Easily add new checks by extending `BaseCheck`.
- **Comprehensive Scans**: Checks Services, Token Privileges, Writable Paths, Scheduled Tasks, Registry Misconfigurations, and OS Patch levels (CVEs).
- **Flexible Reporting**: Output results to the terminal or structured JSON.
- **Configurable**: Scope scans using a custom `config.yaml` file to avoid scanning slow or irrelevant locations.

## Installation

### From Source
```powershell
git clone https://github.com/zodrimon/windows-privesc-assistant.git
cd windows-privesc-assistant
pip install .
```

### Standalone Executable
You can build a standalone executable using PyInstaller:
```powershell
pip install pyinstaller
pyinstaller --onefile src/privesc_assistant_win/cli.py --name privesc-assistant-win
```

## Quickstart

Run a full scan with default configuration and output to terminal:
```powershell
privesc-assistant-win scan
```

Output results in JSON format:
```powershell
privesc-assistant-win scan --format json --output report.json
```

List available checks:
```powershell
privesc-assistant-win list
```

## Requirements
- Windows OS (Tested on Windows 10/11)
- Python 3.10+
- Administrative privileges (optional, but highly recommended for full visibility)
