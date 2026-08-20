"""AgentSec - Event models for tracing agent execution."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass(kw_only=True)
class Event:
    """Base event type for all traced actions."""
    type: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    attack_id: str | None = None
    session_id: str = field(default_factory=lambda: str(uuid4())[:8])
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(kw_only=True)
class AgentInputEvent(Event):
    input: str
    type: str = "agent_input"


@dataclass(kw_only=True)
class AgentResponseEvent(Event):
    response: str
    type: str = "agent_response"


@dataclass(kw_only=True)
class ToolCallEvent(Event):
    tool: str
    arguments: dict[str, Any]
    result: Any = None
    error: str | None = None
    duration_ms: float | None = None
    type: str = "tool_call"


@dataclass(kw_only=True)
class PolicyDecisionEvent(Event):
    tool: str
    allowed: bool
    reason: str
    type: str = "policy_decision"


@dataclass(kw_only=True)
class AttackStartEvent(Event):
    attack_id: str
    attack_name: str
    type: str = "attack_start"


@dataclass(kw_only=True)
class AttackEndEvent(Event):
    attack_id: str
    success: bool
    evidence: list[str]
    type: str = "attack_end"


def event_to_dict(event: Event) -> dict[str, Any]:
    """Convert event to dictionary for serialization."""
    return {
        "type": event.type,
        "timestamp": event.timestamp,
        "attack_id": event.attack_id,
        "session_id": event.session_id,
        "metadata": event.metadata,
        **{k: v for k, v in event.__dict__.items() 
           if k not in ("type", "timestamp", "attack_id", "session_id", "metadata")}
    }


def dict_to_event(data: dict[str, Any]) -> Event:
    """Convert dictionary back to event (best effort)."""
    event_type = data.pop("type", "unknown")
    if event_type == "agent_input":
        return AgentInputEvent(**data)
    elif event_type == "agent_response":
        return AgentResponseEvent(**data)
    elif event_type == "tool_call":
        return ToolCallEvent(**data)
    elif event_type == "policy_decision":
        return PolicyDecisionEvent(**data)
    elif event_type == "attack_start":
        return AttackStartEvent(**data)
    elif event_type == "attack_end":
        return AttackEndEvent(**data)
    return Event(type=event_type, **data)