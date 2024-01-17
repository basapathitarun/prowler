import sys

import yaml
from jsonschema import validate

from prowler.config.config import valid_severities
from prowler.lib.logger import logger

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

def update_check_metadata(check_metadata, custom_metadata):
    """update_check_metadata updates the check_metadata fields present in the custom_metadata and returns the updated version of the check_metadata. If some field is not present or valid the check_metadata is returned with the original fields."""
    try:
        if custom_metadata:
            for attribute in custom_metadata:
                try:
                    setattr(check_metadata, attribute, custom_metadata[attribute])
                except ValueError:
                    pass
    finally:
        return check_metadata
