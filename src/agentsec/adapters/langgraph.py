"""AgentSec - LangGraph adapter."""

from typing import Any

from agentsec.adapters.base import AgentTarget


class LangGraphAdapter(AgentTarget):
    """Adapter for LangGraph agents."""

    def __init__(
        self,
        graph: Any,  # Compiled LangGraph StateGraph
        config: dict[str, Any] | None = None,
    ):
        self.graph = graph
        self.config = config or {"configurable": {"thread_id": "agentsec-test"}}
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        try:
            # LangGraph expects messages format
            from langchain_core.messages import HumanMessage

            state = {"messages": [HumanMessage(content=input)]}
            result = self.graph.invoke(state, config=self.config)

            # Extract last AI message
            messages = result.get("messages", [])
            ai_messages = [m for m in messages if m.__class__.__name__ == "AIMessage"]
            if ai_messages:
                output = ai_messages[-1].content
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
        tools = []
        # Try to extract tools from graph nodes
        if hasattr(self.graph, "nodes"):
            for node_name, node in self.graph.nodes.items():
                if "tool" in node_name.lower():
                    # This is heuristic - would need better introspection
                    pass
        return tools

    def reset(self) -> None:
        self._events.clear()
        # Create new thread for isolation
        import uuid
        self.config = {"configurable": {"thread_id": f"agentsec-{uuid.uuid4().hex[:8]}"}}

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "LangGraphAdapter",
            "graph_type": type(self.graph).__name__,
        }