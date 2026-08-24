"""Tests for the HTTP target adapter and CLI configuration."""

import httpx
import pytest

from agentsec.adapters.http import HttpAdapter
from agentsec.cli import load_adapter
from agentsec.config import AdapterConfig


def make_adapter(requests: list[httpx.Request]) -> HttpAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/chat":
            return httpx.Response(200, json={"response": "safe response"})
        if request.url.path == "/api/tools":
            return httpx.Response(200, json=[{"name": "search"}])
        if request.url.path == "/api/reset":
            return httpx.Response(204)
        return httpx.Response(404)

    adapter = HttpAdapter(
        "https://agent.example",
        api_key="test-key",
        endpoints={"chat": "/api/chat", "tools": "/api/tools", "reset": "/api/reset"},
    )
    adapter._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers=adapter._headers,
    )
    return adapter


def test_http_adapter_uses_configured_endpoints_and_auth_header() -> None:
    requests: list[httpx.Request] = []
    adapter = make_adapter(requests)

    assert adapter.send("hello") == "safe response"
    assert adapter.list_tools() == [{"name": "search"}]
    adapter.reset()

    assert [request.url.path for request in requests] == ["/api/chat", "/api/tools", "/api/reset"]
    assert all(request.headers["authorization"] == "Bearer test-key" for request in requests)
    assert adapter.get_events() == []

    adapter.close()


def test_load_adapter_constructs_http_adapter_from_config() -> None:
    adapter = load_adapter(
        AdapterConfig(
            type="http",
            args={"base_url": "http://localhost:8000", "timeout": 5.0},
        )
    )

    assert isinstance(adapter, HttpAdapter)
    assert adapter.base_url == "http://localhost:8000"
    assert adapter.timeout == 5.0
    adapter.close()


def test_load_adapter_requires_http_base_url() -> None:
    with pytest.raises(Exception, match="target.args.base_url"):
        load_adapter(AdapterConfig(type="http"))


def test_http_adapter_strips_trailing_slashes() -> None:
    adapter = HttpAdapter("http://localhost:8000///")
    assert adapter.base_url == "http://localhost:8000"
    adapter.close()
