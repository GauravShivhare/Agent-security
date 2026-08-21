"""AgentSec - LangChain adapter."""

from typing import Any

from agentsec.adapters.base import AgentTarget


class LangChainAdapter(AgentTarget):
    """Adapter for LangChain agents."""

    def __init__(
        self,
        agent_executor: Any,  # LangChain AgentExecutor
        include_tools: bool = True,
    ):
        self.agent_executor = agent_executor
        self.include_tools = include_tools
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        try:
            # Handle different LangChain versions
            if hasattr(self.agent_executor, "invoke"):
                result = self.agent_executor.invoke({"input": input})
            else:
                result = self.agent_executor({"input": input})

            # Extract output
            if isinstance(result, dict):
                output = result.get("output", result.get("text", str(result)))
            else:
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
        if not self.include_tools:
            return []

        tools = []
        if hasattr(self.agent_executor, "tools"):
            for tool in self.agent_executor.tools:
                tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": getattr(tool, "args_schema", {}),
                })
        return tools

    def reset(self) -> None:
        self._events.clear()
        # Reset memory if present
        if hasattr(self.agent_executor, "memory") and self.agent_executor.memory:
            self.agent_executor.memory.clear()

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "LangChainAdapter",
            "agent_type": type(self.agent_executor).__name__,
        }