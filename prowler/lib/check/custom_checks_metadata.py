from prowler.config.config import valid_severities

custom_checks_metadata_schema = {
    "type": "object",
    "properties": {
        "Checks": {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "type": "object",
                    "properties": {
                        "Severity": {
                            "type": "string",
                            "enum": valid_severities,
                        }
                    },
                    "required": ["Severity"],
                    "additionalProperties": False,
                }
            },
            "additionalProperties": False,
        }
    },
    "required": ["Checks"],
    "additionalProperties": False,
}


