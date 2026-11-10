"""Security rules registry loader."""

from mcpscan.rules.base import registry
from mcpscan.rules.sec_001_tool_poisoning import ToolPoisoningRule
from mcpscan.rules.sec_002_excessive_execution import ExcessiveExecutionRule
from mcpscan.rules.sec_003_resource_wildcards import BroadResourceURIRule
from mcpscan.rules.sec_004_secret_exposure import SecretExposureRule
from mcpscan.rules.sec_005_token_exhaustion import TokenExhaustionRule
from mcpscan.rules.sec_006_ssrf_egress import SSRFNetworkEgressRule
from mcpscan.rules.sec_007_prompt_template_injection import DynamicPromptInjectionRule
from mcpscan.rules.sec_008_sensitive_resource_snooping import (
    SensitiveResourceSnoopingRule,
)

# Register default core rules
registry.register(ToolPoisoningRule)
registry.register(ExcessiveExecutionRule)
registry.register(BroadResourceURIRule)
registry.register(SecretExposureRule)
registry.register(TokenExhaustionRule)
registry.register(SSRFNetworkEgressRule)
registry.register(DynamicPromptInjectionRule)
registry.register(SensitiveResourceSnoopingRule)

__all__ = [
    "BroadResourceURIRule",
    "DynamicPromptInjectionRule",
    "ExcessiveExecutionRule",
    "SSRFNetworkEgressRule",
    "SecretExposureRule",
    "SensitiveResourceSnoopingRule",
    "TokenExhaustionRule",
    "ToolPoisoningRule",
    "registry",
]
