"""AgentSec - CrewAI adapter."""

from typing import Any

from agentsec.adapters.base import AgentTarget


class CrewAIAdapter(AgentTarget):
    """Adapter for CrewAI crews/agents."""

    def __init__(
        self,
        crew: Any,  # CrewAI Crew instance
        inputs: dict[str, Any] | None = None,
    ):
        self.crew = crew
        self.default_inputs = inputs or {}
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        try:
            inputs = {**self.default_inputs, "input": input}
            result = self.crew.kickoff(inputs=inputs)
            output = str(result)

        except Exception as e:
            output = f"ERROR: {e}"

        self._events.append({
            "type": "agent_response",
            "input": input,
            "response": output,
        })
        return output

    def list_tools(self) -> list[dict[str, Any]]:
        tools = []
        # Extract tools from agents in the crew
        if hasattr(self.crew, "agents"):
            for agent in self.crew.agents:
                if hasattr(agent, "tools"):
                    for tool in agent.tools:
                        tools.append({
                            "name": getattr(tool, "name", tool.__class__.__name__),
                            "description": getattr(tool, "description", ""),
                            "parameters": getattr(tool, "args_schema", {}),
                        })
        return tools

    def reset(self) -> None:
        self._events.clear()
        # CrewAI doesn't have built-in reset, would need new crew instance

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "CrewAIAdapter",
            "crew_name": getattr(self.crew, "name", "Unnamed Crew"),
        }