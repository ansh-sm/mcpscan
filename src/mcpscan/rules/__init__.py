"""Security rules registry loader."""

from mcpscan.rules.base import registry
from mcpscan.rules.sec_001_tool_poisoning import ToolPoisoningRule
from mcpscan.rules.sec_002_excessive_execution import ExcessiveExecutionRule
from mcpscan.rules.sec_003_resource_wildcards import BroadResourceURIRule

# Register default core rules
registry.register(ToolPoisoningRule)
registry.register(ExcessiveExecutionRule)
registry.register(BroadResourceURIRule)

__all__ = [
    "registry",
    "ToolPoisoningRule",
    "ExcessiveExecutionRule",
    "BroadResourceURIRule",
]
