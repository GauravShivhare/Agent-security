"""AgentSec - MCP (Model Context Protocol) adapter."""

from typing import Any

from agentsec.adapters.base import AgentTarget


class MCPAdapter(AgentTarget):
    """Adapter for agents using MCP (Model Context Protocol) tools."""

    def __init__(
        self,
        client: Any,  # MCP Client (from mcp package)
        server_name: str = "default",
    ):
        self.client = client
        self.server_name = server_name
        self._events: list[dict[str, Any]] = []
        self._tools_cache: list[dict[str, Any]] | None = None

    def send(self, input: str) -> str:
        # MCP doesn't have a standard "send" - this is for agents that USE MCP tools
        # The actual agent would be separate; this adapter exposes MCP tools for testing
        try:
            # For testing: call a generic tool if available
            tools = self.list_tools()
            if tools:
                # Try to call first tool as test
                tool_name = tools[0]["name"]
                result = self.client.call_tool(self.server_name, tool_name, {"input": input})
                output = str(result)
            else:
                output = "No MCP tools available"

        except Exception as e:
            output = f"ERROR: {e}"

        self._events.append({
            "type": "agent_response",
            "input": input,
            "response": output,
        })
        return output

    def list_tools(self) -> list[dict[str, Any]]:
        if self._tools_cache is not None:
            return self._tools_cache

        try:
            tools = self.client.list_tools(self.server_name)
            self._tools_cache = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema,
                }
                for tool in tools
            ]
        except Exception:
            self._tools_cache = []

        return self._tools_cache

    def reset(self) -> None:
        self._events.clear()
        self._tools_cache = None

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "MCPAdapter",
            "server_name": self.server_name,
            "tool_count": len(self.list_tools()),
        }

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Direct tool call for testing."""
        try:
            result = self.client.call_tool(self.server_name, tool_name, arguments)
            self._events.append({
                "type": "tool_call",
                "tool": tool_name,
                "arguments": arguments,
                "result": str(result),
            })
            return result
        except Exception as e:
            self._events.append({
                "type": "tool_call",
                "tool": tool_name,
                "arguments": arguments,
                "error": str(e),
            })
            raise