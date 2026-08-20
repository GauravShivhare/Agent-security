"""AgentSec - Base target adapter interface."""

from abc import ABC, abstractmethod
from typing import Any


class AgentTarget(ABC):
    """Minimal interface that all target agents must implement."""

    @abstractmethod
    def send(self, input: str) -> str:
        """Send input to the agent and return its response."""
        ...

    @abstractmethod
    def list_tools(self) -> list[dict[str, Any]]:
        """Return list of available tools with their schemas."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset agent state (clear memory, context, etc.)."""
        ...

    @abstractmethod
    def get_events(self) -> list[dict[str, Any]]:
        """Return captured events since last reset."""
        ...

    def get_metadata(self) -> dict[str, Any]:
        """Optional metadata about the target."""
        return {"name": self.__class__.__name__}