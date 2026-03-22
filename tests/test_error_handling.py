"""
Error-handling tests.

Verify that the server returns a well-formed error payload (never crashes)
when given invalid, non-existent, or malformed input.
"""

import pytest
from .conftest import extract

# A domain that is guaranteed not to resolve
NONEXISTENT = "thisdoesnotexist-xyz-12345.invalid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def assert_failure(data: dict, expected_key: str = "domain"):
    """Common assertions for a failed tool call."""
    assert data["success"] is False, "Expected success=False for invalid domain"
    assert "error" in data, "Expected an 'error' key in failure response"
    assert data[expected_key] == NONEXISTENT


# ---------------------------------------------------------------------------
# A record — nonexistent domain
# ---------------------------------------------------------------------------

async def test_query_a_record_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_a_record", {"domain": NONEXISTENT})
    data = extract(result)
    assert_failure(data)
    assert data["record_type"] == "A"


# ---------------------------------------------------------------------------
# MX record — nonexistent domain
# ---------------------------------------------------------------------------

async def test_query_mx_record_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_mx_record", {"domain": NONEXISTENT})
    data = extract(result)
    assert_failure(data)
    assert data["record_type"] == "MX"


# ---------------------------------------------------------------------------
# NS record — nonexistent domain
# ---------------------------------------------------------------------------

async def test_query_ns_record_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_ns_record", {"domain": NONEXISTENT})
    data = extract(result)
    assert_failure(data)
    assert data["record_type"] == "NS"


# ---------------------------------------------------------------------------
# TXT record — nonexistent domain
# ---------------------------------------------------------------------------

async def test_query_txt_record_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_txt_record", {"domain": NONEXISTENT})
    data = extract(result)
    assert_failure(data)
    assert data["record_type"] == "TXT"


# ---------------------------------------------------------------------------
# SOA record — nonexistent domain
# ---------------------------------------------------------------------------

async def test_query_soa_record_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_soa_record", {"domain": NONEXISTENT})
    data = extract(result)
    assert_failure(data)
    assert data["record_type"] == "SOA"


# ---------------------------------------------------------------------------
# PTR record — invalid IP address
# ---------------------------------------------------------------------------

async def test_query_ptr_record_invalid_ip(mcp_client):
    result = await mcp_client.call_tool(
        "query_ptr_record", {"ip_address": "999.999.999.999"}
    )
    data = extract(result)
    assert data["success"] is False
    assert "error" in data


# ---------------------------------------------------------------------------
# check_domain_availability — nonexistent domain should have no records
# ---------------------------------------------------------------------------

async def test_check_domain_availability_nonexistent(mcp_client):
    result = await mcp_client.call_tool(
        "check_domain_availability", {"domain": NONEXISTENT}
    )
    data = extract(result)
    assert data["domain"] == NONEXISTENT
    assert data["has_dns_records"] is False
    assert data["configured_record_types"] == []


# ---------------------------------------------------------------------------
# query_all_records — nonexistent domain returns structure without crashing
# ---------------------------------------------------------------------------

async def test_query_all_records_nonexistent(mcp_client):
    result = await mcp_client.call_tool("query_all_records", {"domain": NONEXISTENT})
    data = extract(result)
    # Should return the records dict; every type should have an error entry
    assert data["domain"] == NONEXISTENT
    assert "records" in data
    # No record type should have produced real results
    for rtype, val in data["records"].items():
        if isinstance(val, dict):
            assert "error" in val, \
                f"Record type {rtype!r} should have an error for nonexistent domain"


# ---------------------------------------------------------------------------
# trace_dns_delegation — nonexistent domain
# ---------------------------------------------------------------------------

async def test_trace_dns_delegation_nonexistent(mcp_client):
    result = await mcp_client.call_tool(
        "trace_dns_delegation", {"domain": NONEXISTENT}
    )
    data = extract(result)
    assert data["domain"] == NONEXISTENT
    # Server should not crash; authoritative_nameservers will be empty
    assert "authoritative_nameservers" in data
    assert isinstance(data["authoritative_nameservers"], list)
