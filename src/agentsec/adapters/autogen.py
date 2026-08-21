"""AgentSec - AutoGen adapter."""

from typing import Any

from agentsec.adapters.base import AgentTarget


class AutoGenAdapter(AgentTarget):
    """Adapter for AutoGen agents."""

    def __init__(
        self,
        agent: Any,  # AutoGen Agent (UserProxyAgent, AssistantAgent, etc.)
        user_proxy: Any | None = None,
    ):
        self.agent = agent
        self.user_proxy = user_proxy
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        try:
            if self.user_proxy:
                # Use user proxy to initiate chat
                result = self.user_proxy.initiate_chat(
                    self.agent,
                    message=input,
                    clear_history=True,
                )
                # Extract last message from agent
                if hasattr(result, "chat_history") and result.chat_history:
                    last_msg = result.chat_history[-1]
                    output = last_msg.get("content", str(last_msg))
                else:
                    output = str(result)
            else:
                # Direct agent call
                if hasattr(self.agent, "generate_reply"):
                    messages = [{"role": "user", "content": input}]
                    reply = self.agent.generate_reply(messages=messages)
                    output = reply.get("content", str(reply)) if isinstance(reply, dict) else str(reply)
                else:
                    output = "Agent does not support direct messaging"

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
        # AutoGen tools are typically functions registered with the agent
        if hasattr(self.agent, "_function_map"):
            for name, func in self.agent._function_map.items():
                tools.append({
                    "name": name,
                    "description": getattr(func, "__doc__", ""),
                    "parameters": getattr(func, "_schema", {}),
                })
        return tools

    def reset(self) -> None:
        self._events.clear()
        if hasattr(self.agent, "clear_history"):
            self.agent.clear_history()
        if self.user_proxy and hasattr(self.user_proxy, "clear_history"):
            self.user_proxy.clear_history()

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "AutoGenAdapter",
            "agent_type": type(self.agent).__name__,
        }