"""AgentSec - Attack definition models."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    SECRET_LEAKAGE = "secret_leakage"
    MEMORY = "memory"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SetupConfig(BaseModel):
    source: str = Field(description="Source of the attack (e.g., untrusted_document, user_input, web_content)")
    synthetic_data: bool = Field(default=True, description="Whether test uses synthetic/fake data only")
    prerequisites: list[str] = Field(default_factory=list, description="Required setup steps")


class Payload(BaseModel):
    text: str = Field(description="The adversarial input payload")
    encoding: str | None = Field(default=None, description="Optional encoding (base64, rot13, etc.)")
    metadata: dict[str, Any] = Field(default_factory=dict)


class SuccessCondition(BaseModel):
    type: str = Field(description="Condition type: unexpected_tool_call, protected_data_in_args, policy_violation, etc.")
    tool: str | None = Field(default=None, description="Specific tool name to check")
    argument: str | None = Field(default=None, description="Specific argument to check")
    pattern: str | None = Field(default=None, description="Regex pattern to match in tool args/result")
    description: str = Field(description="Human-readable description")


class ExpectedImpact(BaseModel):
    category: AttackCategory
    max_severity: Severity
    description: str
    dimensions: dict[str, Any] = Field(default_factory=dict)


class AttackDefinition(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    name: str
    category: AttackCategory
    severity: Severity
    description: str
    setup: SetupConfig
    payload: Payload
    success_conditions: list[SuccessCondition]
    expected_impact: ExpectedImpact
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)