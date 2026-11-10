"""Unit tests for recursive JSON Schema traversal engine and deeply nested detection."""

from mcpscan.models import Confidence, ServerManifest
from mcpscan.rules.sec_002_excessive_execution import ExcessiveExecutionRule
from mcpscan.rules.sec_004_secret_exposure import SecretExposureRule
from mcpscan.rules.sec_005_token_exhaustion import TokenExhaustionRule
from mcpscan.rules.sec_006_ssrf_egress import SSRFNetworkEgressRule
from mcpscan.schema_utils import walk_schema


def test_walk_schema_flat_object():
    """Flat schema yields its properties."""
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    nodes = list(walk_schema(schema))
    names = {n.name for n in nodes}
    assert names == {"name", "count"}
    assert all(n.depth == 0 for n in nodes)


def test_walk_schema_deeply_nested_objects():
    """Properties nested 3 levels deep are discovered with correct paths."""
    schema = {
        "type": "object",
        "properties": {
            "level1": {
                "type": "object",
                "properties": {
                    "level2": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                    }
                },
            }
        },
    }
    nodes = list(walk_schema(schema))
    paths = {n.json_path for n in nodes}
    assert "level1" in paths
    assert "level1.level2" in paths
    assert "level1.level2.command" in paths

    cmd_node = next(n for n in nodes if n.name == "command")
    assert cmd_node.depth == 2
    assert cmd_node.json_path == "level1.level2.command"


def test_walk_schema_array_items():
    """Array item schemas are recursively traversed."""
    schema = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "script": {"type": "string"},
                    },
                },
            }
        },
    }
    nodes = list(walk_schema(schema))
    names = {n.name for n in nodes}
    assert "tasks" in names
    assert "script" in names

    script_node = next(n for n in nodes if n.name == "script")
    assert script_node.json_path == "tasks.items.script"


def test_walk_schema_composition_keywords():
    """allOf, anyOf, oneOf branches are traversed."""
    schema = {
        "type": "object",
        "oneOf": [
            {
                "properties": {
                    "cmd_a": {"type": "string"},
                }
            },
            {
                "properties": {
                    "cmd_b": {"type": "string"},
                }
            },
        ],
    }
    nodes = list(walk_schema(schema))
    names = {n.name for n in nodes}
    assert "cmd_a" in names
    assert "cmd_b" in names


def test_walk_schema_local_ref_resolution():
    """Local $defs / definitions references are resolved."""
    schema = {
        "$defs": {
            "ExecutionPayload": {
                "type": "object",
                "properties": {
                    "exec": {"type": "string"},
                },
            }
        },
        "type": "object",
        "properties": {
            "config": {"$ref": "#/$defs/ExecutionPayload"},
        },
    }
    nodes = list(walk_schema(schema))
    names = {n.name for n in nodes}
    assert "config" in names
    assert "exec" in names


def test_walk_schema_cycle_protection():
    """Circular $ref references do not cause infinite recursion."""
    schema = {
        "$defs": {
            "Node": {
                "type": "object",
                "properties": {
                    "val": {"type": "string"},
                    "next": {"$ref": "#/$defs/Node"},
                },
            }
        },
        "type": "object",
        "properties": {
            "root": {"$ref": "#/$defs/Node"},
        },
    }
    # Must terminate without RecursionError
    nodes = list(walk_schema(schema))
    assert len(nodes) > 0


def test_sec_002_detects_nested_command_parameter():
    """SEC-002 must detect dangerous command parameter hidden inside a nested object."""
    rule = ExcessiveExecutionRule()
    manifest = ServerManifest(
        tools=[
            {
                "name": "cluster_manager",
                "description": "Manage cluster jobs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_config": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"},
                            },
                        }
                    },
                },
            }
        ]
    )
    findings = rule.evaluate(manifest)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-002"
    assert "job_config.command" in findings[0].location.path
    assert findings[0].confidence == Confidence.MEDIUM  # nested = MEDIUM


def test_sec_004_detects_nested_secret_default():
    """SEC-004 must detect secret default hidden inside nested object."""
    rule = SecretExposureRule()
    manifest = ServerManifest(
        tools=[
            {
                "name": "ai_gateway",
                "description": "Proxy requests",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "auth": {
                            "type": "object",
                            "properties": {
                                "api_key": {
                                    "type": "string",
                                    "default": "sk-proj-abc123456789012345678901234567890",
                                }
                            },
                        }
                    },
                },
            }
        ]
    )
    findings = rule.evaluate(manifest)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-004"
    assert "auth.api_key" in findings[0].location.path
    assert findings[0].confidence == Confidence.HIGH


def test_sec_005_detects_nested_unbounded_array():
    """SEC-005 must detect unbounded array inside nested object."""
    rule = TokenExhaustionRule()
    manifest = ServerManifest(
        tools=[
            {
                "name": "batch_importer",
                "description": "Imports batch records",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "object",
                            "properties": {
                                "records": {"type": "array"},
                            },
                        }
                    },
                },
            }
        ]
    )
    findings = rule.evaluate(manifest)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-005"
    assert "payload.records" in findings[0].location.path


def test_sec_006_detects_nested_unconstrained_url():
    """SEC-006 must detect unconstrained URL inside nested object."""
    rule = SSRFNetworkEgressRule()
    manifest = ServerManifest(
        tools=[
            {
                "name": "webhook_router",
                "description": "Routes events",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "destination": {
                            "type": "object",
                            "properties": {
                                "webhook_url": {"type": "string"},
                            },
                        }
                    },
                },
            }
        ]
    )
    findings = rule.evaluate(manifest)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-006"
    assert "destination.webhook_url" in findings[0].location.path
