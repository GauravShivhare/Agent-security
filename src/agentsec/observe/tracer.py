"""AgentSec - Event tracer for capturing agent execution."""

from contextlib import contextmanager
from typing import Any

from agentsec.observe.events import (
    Event,
    AgentInputEvent,
    AgentResponseEvent,
    ToolCallEvent,
    PolicyDecisionEvent,
    AttackStartEvent,
    AttackEndEvent,
    event_to_dict,
)


class EventTracer:
    """Captures and stores events during attack execution."""

    def __init__(self, attack_id: str | None = None):
        self.attack_id = attack_id
        self._events: list[Event] = []
        self._session_id = None

    def start_attack(self, attack_id: str, attack_name: str) -> None:
        self.attack_id = attack_id
        self._events.clear()
        self.record(AttackStartEvent(attack_id=attack_id, attack_name=attack_name))

    def end_attack(self, success: bool, evidence: list[str]) -> None:
        self.record(AttackEndEvent(attack_id=self.attack_id, success=success, evidence=evidence))

    def record(self, event: Event) -> None:
        if self.attack_id and not event.attack_id:
            event.attack_id = self.attack_id
        self._events.append(event)

    def record_input(self, input: str) -> None:
        self.record(AgentInputEvent(input=input, attack_id=self.attack_id))

    def record_response(self, response: str) -> None:
        self.record(AgentResponseEvent(response=response, attack_id=self.attack_id))

    def record_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        result: Any = None,
        error: str | None = None,
        duration_ms: float | None = None,
    ) -> None:
        self.record(ToolCallEvent(
            tool=tool,
            arguments=arguments,
            result=result,
            error=error,
            duration_ms=duration_ms,
            attack_id=self.attack_id,
        ))

    def record_policy_decision(self, tool: str, allowed: bool, reason: str) -> None:
        self.record(PolicyDecisionEvent(
            tool=tool,
            allowed=allowed,
            reason=reason,
            attack_id=self.attack_id,
        ))

    def get_events(self) -> list[Event]:
        return self._events.copy()

    def get_events_as_dicts(self) -> list[dict[str, Any]]:
        return [event_to_dict(e) for e in self._events]

    def clear(self) -> None:
        self._events.clear()

    @contextmanager
    def trace_attack(self, attack_id: str, attack_name: str):
        """Context manager for tracing a single attack."""
        self.start_attack(attack_id, attack_name)
        try:
            yield self
        finally:
            pass  # end_attack called manually with result


# Global tracer instance (can be replaced per test)
_global_tracer: EventTracer | None = None


def get_tracer() -> EventTracer:
    global _global_tracer
    if _global_tracer is None:
        _global_tracer = EventTracer()
    return _global_tracer


def set_tracer(tracer: EventTracer) -> None:
    global _global_tracer
    _global_tracer = tracer