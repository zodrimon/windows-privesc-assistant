CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "scan": {
            "type": "object",
            "properties": {
                "timeout_per_check": {"type": "number", "minimum": 1}
            },
            "additionalProperties": False
        },
        "output": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["terminal", "json", "md", "html"]},
                "path": {"type": "string"},
                "verbosity": {"type": "string", "enum": ["debug", "info", "warn", "error"]}
            },
            "additionalProperties": False
        },
        "checks": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "additionalProperties": False
}
