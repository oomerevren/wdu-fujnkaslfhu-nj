"""Event schema registry — JSON Schema definitions for all PentestAI events.

Each schema is registered in the ``event_catalog`` dict keyed by event type
so that producers and consumers can validate events at runtime.
"""

from __future__ import annotations

from typing import Any

# ── Event schemas (JSON Schema draft-07) ────────────────────────────────

scan_created_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "ScanCreatedEvent",
    "description": "Emitted when a new security scan is created and dispatched.",
    "properties": {
        "type": {"const": "scan.created"},
        "payload": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of the created scan.",
                },
                "target_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of the target being scanned.",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["nuclei", "zap", "promptfoo"],
                    "description": "Type of scanner to run.",
                },
                "user_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of the user who owns the scan.",
                },
            },
            "required": ["scan_id", "target_id", "scan_type", "user_id"],
            "additionalProperties": False,
        },
        "metadata": {
            "type": "object",
            "description": "Envelope metadata (timestamp, correlation_id, source, version).",
        },
    },
    "required": ["type", "payload", "metadata"],
}

scan_progress_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "ScanProgressEvent",
    "description": "Emitted periodically to report scan execution progress.",
    "properties": {
        "type": {"const": "scan.progress"},
        "payload": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "format": "uuid",
                },
                "progress": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Progress percentage (0–100).",
                },
                "status": {
                    "type": "string",
                    "enum": ["queued", "running", "completed", "failed"],
                    "description": "Current scan status.",
                },
            },
            "required": ["scan_id", "progress", "status"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

scan_completed_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "ScanCompletedEvent",
    "description": "Emitted when a scan finishes successfully.",
    "properties": {
        "type": {"const": "scan.completed"},
        "payload": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "format": "uuid"},
                "findings_count": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of findings discovered.",
                },
                "duration_seconds": {
                    "type": "number",
                    "description": "Total scan duration in seconds.",
                },
            },
            "required": ["scan_id", "findings_count"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

scan_failed_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "ScanFailedEvent",
    "description": "Emitted when a scan fails with an error.",
    "properties": {
        "type": {"const": "scan.failed"},
        "payload": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "format": "uuid"},
                "error": {
                    "type": "string",
                    "description": "Error message describing the failure.",
                },
            },
            "required": ["scan_id", "error"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

finding_created_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "FindingCreatedEvent",
    "description": "Emitted when a new security finding is persisted.",
    "properties": {
        "type": {"const": "finding.created"},
        "payload": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "format": "uuid"},
                "scan_id": {"type": "string", "format": "uuid"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "name": {"type": "string"},
                "cve_id": {"type": "string"},
            },
            "required": ["finding_id", "scan_id", "severity"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

finding_status_changed_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "FindingStatusChangedEvent",
    "description": "Emitted when a finding's triage status changes.",
    "properties": {
        "type": {"const": "finding.status_changed"},
        "payload": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "format": "uuid"},
                "old_status": {
                    "type": "string",
                    "enum": ["open", "false_positive", "fixed", "acknowledged"],
                },
                "new_status": {
                    "type": "string",
                    "enum": ["open", "false_positive", "fixed", "acknowledged"],
                },
            },
            "required": ["finding_id", "old_status", "new_status"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

user_registered_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "UserRegisteredEvent",
    "description": "Emitted when a new user account is created.",
    "properties": {
        "type": {"const": "user.registered"},
        "payload": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "format": "uuid"},
                "email": {"type": "string", "format": "email"},
            },
            "required": ["user_id", "email"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

user_login_event_schema: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "title": "UserLoginEvent",
    "description": "Emitted when a user logs in successfully.",
    "properties": {
        "type": {"const": "user.login"},
        "payload": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "format": "uuid"},
                "ip_address": {
                    "type": "string",
                    "format": "ipv4",
                    "description": "Source IP of the login request.",
                },
            },
            "required": ["user_id", "ip_address"],
            "additionalProperties": False,
        },
        "metadata": {"type": "object"},
    },
    "required": ["type", "payload", "metadata"],
}

# ── Event catalog ───────────────────────────────────────────────────────

event_catalog: dict[str, dict[str, Any]] = {
    "scan.created": scan_created_event_schema,
    "scan.progress": scan_progress_event_schema,
    "scan.completed": scan_completed_event_schema,
    "scan.failed": scan_failed_event_schema,
    "finding.created": finding_created_event_schema,
    "finding.status_changed": finding_status_changed_event_schema,
    "user.registered": user_registered_event_schema,
    "user.login": user_login_event_schema,
}


def validate_event(event_type: str, payload: dict[str, Any]) -> list[str]:
    """Validate *payload* against the registered schema for *event_type*.

    Returns a list of validation error messages (empty = valid).
    This is a lightweight check — for production, consider using a full
    JSON Schema validator library.
    """
    import jsonschema

    schema = event_catalog.get(event_type)
    if schema is None:
        return [f"No schema registered for event type '{event_type}'"]

    errors: list[str] = []
    try:
        jsonschema.validate(instance={"type": event_type, "payload": payload}, schema=schema)
    except jsonschema.ValidationError as exc:
        errors.append(exc.message)
    return errors
