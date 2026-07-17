# Windows Privilege Escalation Assistant

A modular, extensible command-line tool for enumerating privilege escalation vectors on Windows systems.

> **Disclaimer:** This tool is intended for authorized security auditing, penetration testing, and red teaming only. Ensure you have explicit permission before scanning any systems you do not own.

## Features
- **Extensible Plugin Architecture**: Easily add new checks by extending `BaseCheck`.
- **Comprehensive Scans**: Checks Services, Token Privileges, Writable Paths, Scheduled Tasks, Registry Misconfigurations, and OS Patch levels (CVEs).
- **Flexible Reporting**: Output results to the terminal or structured JSON.
- **Configurable**: Scope scans using a custom `config.yaml` file to avoid scanning slow or irrelevant locations.

## Installation

### Method 1: Download the Pre-compiled Binary (Easiest)
For a normal Windows user, you do not need to install Python or Git. You can simply download the standalone executable:
1. Navigate to the [Releases page](https://github.com/zodrimon/windows-privesc-assistant/releases) on GitHub.
2. Download the latest `privesc-assistant-win.exe` file.
3. Open Command Prompt or PowerShell, navigate to where you downloaded it, and run the tool directly:
```powershell
cd C:\Users\YourName\Downloads
.\privesc-assistant-win.exe scan
```

### Method 2: Install from Source (For Developers)
If you have Python and Git installed and want the latest source version:
```powershell
git clone https://github.com/zodrimon/windows-privesc-assistant.git
cd windows-privesc-assistant
pip install .
```

> **Note:** If you see a warning that `privesc-assistant-win.exe` is installed in a directory that is not on your PATH (like `C:\Users\<User>\AppData\Roaming\Python\Python313\Scripts`), you can either add that directory to your Windows `PATH` environment variable, or run the tool using `python -m privesc_assistant_win.cli scan`.

### Method 3: Build Standalone Executable Yourself
You can build your own standalone executable using PyInstaller. If `pyinstaller` is not on your PATH, you can run it via Python:
```powershell
pip install pyinstaller
python -m PyInstaller --onefile src/privesc_assistant_win/cli.py --name privesc-assistant-win
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
