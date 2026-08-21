"""AgentSec - HTTP adapter for remote agents."""

import json
import time
from typing import Any

import httpx

from agentsec.adapters.base import AgentTarget


class HttpAdapter(AgentTarget):
    """Adapter for HTTP-based agents (REST API)."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._headers = headers or {}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(timeout=timeout, headers=self._headers)
        self._events: list[dict[str, Any]] = []

    def send(self, input: str) -> str:
        start = time.time()
        try:
            response = self._client.post(
                f"{self.base_url}/chat",
                json={"input": input},
            )
            response.raise_for_status()
            data = response.json()
            result = data.get("response", data.get("output", str(data)))
        except Exception as e:
            result = f"ERROR: {e}"

        duration = (time.time() - start) * 1000
        self._events.append({
            "type": "agent_response",
            "input": input,
            "response": result,
            "duration_ms": duration,
        })
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        try:
            response = self._client.get(f"{self.base_url}/tools")
            response.raise_for_status()
            return response.json()
        except Exception:
            return []

    def reset(self) -> None:
        try:
            self._client.post(f"{self.base_url}/reset")
        except Exception:
            pass
        self._events.clear()

    def get_events(self) -> list[dict[str, Any]]:
        return self._events.copy()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": "HttpAdapter",
            "base_url": self.base_url,
        }

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()