"""AgentSec - Custom callable adapter for simple Python agents."""

from typing import Any, Callable

from agentsec.adapters.base import AgentTarget


class CustomAdapter(AgentTarget):
    """Adapter for a simple Python callable agent.

    Usage:
        def my_agent(input: str) -> str:
            # your agent logic
            return response

        adapter = CustomAdapter(my_agent, tools=[...])
    """

    def __init__(
        self,
        agent_fn: Callable[[str], str],
        tools: list[dict[str, Any]] | None = None,
        reset_fn: Callable[[], None] | None = None,
        events_fn: Callable[[], list[dict[str, Any]]] | None = None,
    ):
        self._agent_fn = agent_fn
        self._tools = tools or []
        self._reset_fn = reset_fn
        self._events_fn = events_fn
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        response = self._agent_fn(input)
        self._events.append({
            "type": "agent_response",
            "input": input,
            "response": response,
        })
        return response

    def list_tools(self) -> list[dict[str, Any]]:
        return self._tools

    def reset(self) -> None:
        self._events.clear()
        if self._reset_fn:
            self._reset_fn()

    def get_events(self) -> list[dict[str, Any]]:
        events = self._events.copy()
        if self._events_fn:
            events.extend(self._events_fn())
        return events

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "CustomAdapter",
            "agent_fn": self._agent_fn.__name__,
            "tool_count": len(self._tools),
        }