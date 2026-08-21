"""AgentSec Adapters Package."""

from agentsec.adapters.base import AgentTarget
from agentsec.adapters.custom import CustomAdapter
from agentsec.adapters.http import HttpAdapter

# Optional adapters - try importing, but don't fail if dependencies missing
LangChainAdapter = None
LangGraphAdapter = None
AutoGenAdapter = None
CrewAIAdapter = None
MCPAdapter = None

try:
    from agentsec.adapters.langchain import LangChainAdapter as _LangChainAdapter
    LangChainAdapter = _LangChainAdapter
except ImportError:
    pass

try:
    from agentsec.adapters.langgraph import LangGraphAdapter as _LangGraphAdapter
    LangGraphAdapter = _LangGraphAdapter
except ImportError:
    pass

try:
    from agentsec.adapters.autogen import AutoGenAdapter as _AutoGenAdapter
    AutoGenAdapter = _AutoGenAdapter
except ImportError:
    pass

try:
    from agentsec.adapters.crewai import CrewAIAdapter as _CrewAIAdapter
    CrewAIAdapter = _CrewAIAdapter
except ImportError:
    pass

try:
    from agentsec.adapters.mcp import MCPAdapter as _MCPAdapter
    MCPAdapter = _MCPAdapter
except ImportError:
    pass

__all__ = [
    "AgentTarget",
    "CustomAdapter",
    "HttpAdapter",
    "LangChainAdapter",
    "LangGraphAdapter",
    "AutoGenAdapter",
    "CrewAIAdapter",
    "MCPAdapter",
]