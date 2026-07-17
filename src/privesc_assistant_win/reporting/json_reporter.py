import json
from typing import List
from privesc_assistant_win.core.finding import Finding
from privesc_assistant_win.core.scan_context import ScanContext
from privesc_assistant_win.reporting.base_reporter import BaseReporter

class JsonReporter(BaseReporter):
    def generate(self, context: ScanContext, findings: List[Finding]) -> str:
        data = {
            "context": {
                "hostname": context.hostname,
                "os_version": context.os_version,
                "os_build": context.os_build,
                "timestamp": context.timestamp,
                "is_elevated": context.is_elevated,
                "current_user": context.current_user
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.name,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "check_id": f.check_id
                } for f in findings
            ]
        }
        return json.dumps(data, indent=2)
