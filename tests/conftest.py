import json
import os
import pytest_asyncio
from .mcp_client import MCPClient

# Strip trailing /sse if someone passes the full SSE URL
_raw_url = os.getenv("MCP_SERVER_URL", "http://localhost:8000")
SERVER_URL = _raw_url.rstrip("/").removesuffix("/sse")

EXPECTED_TOOLS = {
    "query_a_record",
    "query_aaaa_record",
    "query_mx_record",
    "query_txt_record",
    "query_ns_record",
    "query_cname_record",
    "query_soa_record",
    "query_ptr_record",
    "query_srv_record",
    "query_caa_record",
    "query_all_records",
    "check_dnssec",
    "whois_lookup",
    "check_domain_availability",
    "trace_dns_delegation",
}


@pytest_asyncio.fixture
async def mcp_client():
    """
    Yields a connected raw MCPClient.

    Uses the HTTP SSE transport directly (httpx + manual JSON-RPC),
    the same wire protocol Claude uses — no fastmcp SDK involved.
    """
    async with MCPClient(SERVER_URL) as client:
        yield client


def extract(result: dict) -> dict:
    """Pull the JSON payload out of a tools/call result dict."""
    return json.loads(result["content"][0]["text"])
