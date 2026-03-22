"""
Connectivity and capability tests.

Verifies:
  - GET /sse returns HTTP 200 with text/event-stream
  - The full MCP initialize handshake completes (tested implicitly by the fixture)
  - All 15 expected tools are registered and have descriptions
"""

import httpx
import pytest
from .conftest import SERVER_URL, EXPECTED_TOOLS


async def test_sse_endpoint_http_200():
    """GET /sse must return 200 with text/event-stream content-type."""
    async with httpx.AsyncClient(base_url=SERVER_URL) as http:
        async with http.stream("GET", "/sse", headers={"Accept": "text/event-stream"}) as resp:
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            ct = resp.headers.get("content-type", "")
            assert "text/event-stream" in ct, f"Expected SSE content-type, got: {ct!r}"


async def test_mcp_handshake_completes(mcp_client):
    """
    The MCPClient fixture opens /sse, reads the endpoint event, POSTs initialize,
    reads the response, and sends notifications/initialized — if we reach this line
    the full handshake succeeded.
    """
    assert mcp_client._endpoint is not None


async def test_all_tools_registered(mcp_client):
    """All 15 expected tools must be present."""
    tools = await mcp_client.list_tools()
    registered = {t["name"] for t in tools}
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"Missing tools: {missing}"


async def test_tool_count(mcp_client):
    """Tool count must be at least 15."""
    tools = await mcp_client.list_tools()
    assert len(tools) >= 15, f"Expected at least 15 tools, got {len(tools)}"


async def test_each_tool_has_description(mcp_client):
    """Every registered tool must have a non-empty description."""
    tools = await mcp_client.list_tools()
    for tool in tools:
        assert tool.get("description"), f"Tool {tool['name']!r} has no description"
