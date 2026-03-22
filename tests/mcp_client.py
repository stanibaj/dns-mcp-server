"""
Minimal MCP client over SSE transport.

Implements the exact wire protocol a real MCP client (e.g. Claude) uses:

  1. GET /sse  — open the SSE stream
  2. Read the first `endpoint` SSE event to get the POST URL
  3. POST {endpoint}  — send JSON-RPC `initialize` request
  4. Read the `initialize` response from the SSE stream
  5. POST {endpoint}  — send `notifications/initialized`
  6. POST {endpoint}  — call tools with `tools/call`
  7. Read tool responses from the SSE stream

No MCP SDK is used — only httpx for HTTP.
"""

import asyncio
import json
from typing import Any

import httpx


class MCPClient:
    """
    Raw MCP-over-SSE client.

    Usage:
        async with MCPClient("http://localhost:8000") as client:
            tools = await client.list_tools()
            result = await client.call_tool("query_a_record", {"domain": "google.com"})
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(base_url=self.base_url, timeout=30.0)
        # Relative endpoint URL received from the server (e.g. /messages?session_id=xxx)
        self._endpoint: str | None = None
        # Map of request-id → Future, resolved when the matching SSE response arrives
        self._pending: dict[int, asyncio.Future[dict]] = {}
        self._sse_task: asyncio.Task | None = None
        self._request_id = 0

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "MCPClient":
        await self._connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._close()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def _connect(self) -> None:
        """Open SSE stream and complete the MCP initialize handshake."""
        endpoint_received = asyncio.Event()
        self._sse_task = asyncio.create_task(self._sse_reader(endpoint_received))

        # Block until server sends the POST endpoint URL via SSE
        await asyncio.wait_for(endpoint_received.wait(), timeout=10.0)

        # Send MCP initialize request
        resp = await self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test-client",
                    "version": "1.0.0",
                },
            },
        )
        if "error" in resp:
            raise RuntimeError(f"MCP initialize failed: {resp['error']}")

        # Confirm handshake (notification — no response expected)
        await self._notify("notifications/initialized", {})

    async def _close(self) -> None:
        if self._sse_task and not self._sse_task.done():
            self._sse_task.cancel()
            try:
                await self._sse_task
            except (asyncio.CancelledError, Exception):
                pass
        await self._http.aclose()

    # ------------------------------------------------------------------
    # SSE reader — runs as a background task for the lifetime of the session
    # ------------------------------------------------------------------

    async def _sse_reader(self, endpoint_received: asyncio.Event) -> None:
        """
        Consume the SSE stream and dispatch events:
          - `endpoint` event  → stores the POST URL and signals readiness
          - `message`  event  → resolves the matching pending Future
        """
        async with self._http.stream(
            "GET",
            "/sse",
            headers={"Accept": "text/event-stream"},
        ) as response:
            response.raise_for_status()

            event_type = ""
            event_data = ""

            async for raw_line in response.aiter_lines():
                if raw_line.startswith("event:"):
                    event_type = raw_line[6:].strip()
                elif raw_line.startswith("data:"):
                    event_data = raw_line[5:].strip()
                elif raw_line == "":
                    # Blank line = end of one SSE event
                    if event_type == "endpoint" and event_data:
                        self._endpoint = event_data  # relative URL
                        endpoint_received.set()

                    elif event_type == "message" and event_data:
                        try:
                            msg = json.loads(event_data)
                        except json.JSONDecodeError:
                            pass
                        else:
                            msg_id = msg.get("id")
                            if msg_id is not None:
                                fut = self._pending.get(msg_id)
                                if fut and not fut.done():
                                    fut.set_result(msg)

                    event_type = ""
                    event_data = ""

    # ------------------------------------------------------------------
    # JSON-RPC transport helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _post(self, payload: dict) -> None:
        """POST one JSON-RPC message to the server's messages endpoint."""
        if not self._endpoint:
            raise RuntimeError("Not connected — endpoint URL not received yet")
        await self._http.post(self._endpoint, json=payload)

    async def _request(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request and block until the response arrives."""
        msg_id = self._next_id()
        loop = asyncio.get_event_loop()
        future: asyncio.Future[dict] = loop.create_future()
        self._pending[msg_id] = future

        await self._post(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
        )

        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=15.0)
        finally:
            self._pending.pop(msg_id, None)

    async def _notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (fire-and-forget, no response expected)."""
        await self._post(
            {"jsonrpc": "2.0", "method": method, "params": params or {}}
        )

    # ------------------------------------------------------------------
    # MCP API
    # ------------------------------------------------------------------

    async def list_tools(self) -> list[dict]:
        """Send tools/list and return the list of tool descriptors."""
        resp = await self._request("tools/list")
        if "error" in resp:
            raise RuntimeError(f"tools/list failed: {resp['error']}")
        return resp["result"]["tools"]

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """
        Send tools/call and return the result dict.
        Raises RuntimeError if the server returns a JSON-RPC error.
        """
        resp = await self._request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        if "error" in resp:
            raise RuntimeError(f"tools/call '{name}' failed: {resp['error']}")
        return resp["result"]


def parse_tool_result(result: dict) -> dict:
    """
    Extract and deserialize the JSON payload from a tools/call result.

    MCP tools return content as a list of typed blocks; FastMCP wraps
    the Python return value as a 'text' block containing serialized JSON.
    """
    return json.loads(result["content"][0]["text"])
