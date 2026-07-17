# Usage Guide

## Command Line Interface (CLI)

The tool provides the `privesc-assistant-win` command when installed via pip.

```powershell
privesc-assistant-win [scan|list] [options]
```

### Commands

* `scan`: Runs the privilege escalation checks.
* `list`: Lists all registered checks.

### Options for `scan`

* `--config <path>`: Specifies a custom YAML configuration file. If not provided, it defaults to checking `config.yaml` in the current directory or uses fallback defaults.
* `--format <format>`: Specifies the output report format. Options are `text` or `json`. Defaults to `text`.
* `--output <path>`: Saves the report to a specified file. If not provided, the report is printed to standard output.

## Configuration File

The `config.yaml` file allows you to define custom scopes and exclusions. Here is an example:

```yaml
scope:
  sensitive_dirs:
    - C:\Windows\System32
    - C:\Program Files
  include_network_drives: false
  max_depth: 5

exclusions:
  paths:
    - C:\Windows\Temp
  services:
    - Spooler
```

## Adding a New Check

To add a custom check module:
1. Create a Python file in `src/privesc_assistant_win/checks/windows/`.
2. Inherit from `BaseCheck` and implement `run(self, context)`.
3. Use the `@register_check` decorator.
4. Return a list of `Finding` objects.

```python
from privesc_assistant_win.checks.base import BaseCheck
from privesc_assistant_win.core.registry import register_check
from privesc_assistant_win.core.finding import Finding, Severity

@register_check
class MyCustomCheck(BaseCheck):
    @property
    def name(self): return "custom_check"
    
    @property
    def description(self): return "My custom check description."
    
    def run(self, context):
        findings = []
        if context.is_elevated:
            findings.append(Finding(title="Example", severity=Severity.LOW, description="Elevated context.", evidence="", remediation="", check_id=self.name))
        return findings
```
