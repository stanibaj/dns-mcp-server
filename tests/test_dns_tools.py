"""
DNS tool integration tests.

Uses well-known, stable domains so results are predictable.
Every test validates:
  - the call completes without raising
  - the response has the correct schema
  - the key business fields are populated
"""

import re
import pytest
from .conftest import extract

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# A record
# ---------------------------------------------------------------------------

async def test_query_a_record_success(mcp_client):
    result = await mcp_client.call_tool("query_a_record", {"domain": "google.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["domain"] == "google.com"
    assert data["record_type"] == "A"
    assert len(data["records"]) > 0

    for rec in data["records"]:
        assert IPV4_RE.match(rec["data"]), f"Not an IPv4 address: {rec['data']!r}"
        assert isinstance(rec["ttl"], int)
        assert rec["type"] == "A"


# ---------------------------------------------------------------------------
# AAAA record
# ---------------------------------------------------------------------------

async def test_query_aaaa_record_success(mcp_client):
    result = await mcp_client.call_tool("query_aaaa_record", {"domain": "google.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "AAAA"
    assert len(data["records"]) > 0
    for rec in data["records"]:
        assert ":" in rec["data"], f"Not an IPv6 address: {rec['data']!r}"


# ---------------------------------------------------------------------------
# MX record
# ---------------------------------------------------------------------------

async def test_query_mx_record_success(mcp_client):
    result = await mcp_client.call_tool("query_mx_record", {"domain": "gmail.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "MX"
    assert len(data["records"]) > 0

    for rec in data["records"]:
        assert isinstance(rec["priority"], int)
        assert rec["mail_server"].endswith("."), \
            f"Mail server should be a FQDN ending in '.': {rec['mail_server']!r}"


# ---------------------------------------------------------------------------
# TXT record
# ---------------------------------------------------------------------------

async def test_query_txt_record_success(mcp_client):
    result = await mcp_client.call_tool("query_txt_record", {"domain": "google.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "TXT"
    assert len(data["records"]) > 0

    texts = [rec["data"] for rec in data["records"]]
    # Google publishes an SPF record
    assert any("v=spf1" in t for t in texts), \
        f"Expected an SPF TXT record, got: {texts}"


# ---------------------------------------------------------------------------
# NS record
# ---------------------------------------------------------------------------

async def test_query_ns_record_success(mcp_client):
    result = await mcp_client.call_tool("query_ns_record", {"domain": "google.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "NS"
    assert len(data["records"]) > 0


# ---------------------------------------------------------------------------
# CNAME record
# ---------------------------------------------------------------------------

async def test_query_cname_record_success(mcp_client):
    # www.github.com → github.com (reliable CNAME)
    result = await mcp_client.call_tool("query_cname_record", {"domain": "www.github.com"})
    data = extract(result)

    # CNAME may or may not exist; only validate schema when successful
    assert "success" in data
    if data["success"]:
        assert data["record_type"] == "CNAME"
        assert len(data["records"]) > 0


# ---------------------------------------------------------------------------
# SOA record
# ---------------------------------------------------------------------------

async def test_query_soa_record_success(mcp_client):
    result = await mcp_client.call_tool("query_soa_record", {"domain": "google.com"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "SOA"
    assert len(data["records"]) == 1

    soa = data["records"][0]
    assert soa["primary_ns"]
    assert isinstance(soa["serial"], int)
    assert isinstance(soa["refresh"], int)


# ---------------------------------------------------------------------------
# PTR record
# ---------------------------------------------------------------------------

async def test_query_ptr_record_success(mcp_client):
    result = await mcp_client.call_tool("query_ptr_record", {"ip_address": "8.8.8.8"})
    data = extract(result)

    assert data["success"] is True
    assert data["record_type"] == "PTR"
    assert len(data["records"]) > 0
    # 8.8.8.8 → dns.google.
    assert any("google" in rec["data"] for rec in data["records"])


# ---------------------------------------------------------------------------
# SRV record
# ---------------------------------------------------------------------------

async def test_query_srv_record_success(mcp_client):
    # _xmpp-client._tcp.gmail.com has SRV records
    result = await mcp_client.call_tool(
        "query_srv_record",
        {"service": "xmpp-client", "protocol": "tcp", "domain": "gmail.com"},
    )
    data = extract(result)

    assert "success" in data
    if data["success"]:
        assert data["record_type"] == "SRV"
        for rec in data["records"]:
            assert isinstance(rec["priority"], int)
            assert isinstance(rec["port"], int)
            assert rec["target"]


# ---------------------------------------------------------------------------
# CAA record
# ---------------------------------------------------------------------------

async def test_query_caa_record_success(mcp_client):
    result = await mcp_client.call_tool("query_caa_record", {"domain": "google.com"})
    data = extract(result)

    assert "success" in data
    if data["success"]:
        assert data["record_type"] == "CAA"
        for rec in data["records"]:
            assert rec["tag"] in ("issue", "issuewild", "iodef")


# ---------------------------------------------------------------------------
# query_all_records
# ---------------------------------------------------------------------------

async def test_query_all_records_success(mcp_client):
    result = await mcp_client.call_tool("query_all_records", {"domain": "google.com"})
    data = extract(result)

    assert data["domain"] == "google.com"
    assert "records" in data
    # At minimum A, NS, SOA should be present for google.com
    for rtype in ("A", "NS", "SOA"):
        assert rtype in data["records"], f"Expected record type {rtype!r} in results"


# ---------------------------------------------------------------------------
# check_dnssec
# ---------------------------------------------------------------------------

async def test_check_dnssec_schema(mcp_client):
    result = await mcp_client.call_tool("check_dnssec", {"domain": "cloudflare.com"})
    data = extract(result)

    assert data["domain"] == "cloudflare.com"
    assert "dnssec_enabled" in data
    assert isinstance(data["dnssec_enabled"], bool)
    assert isinstance(data["ds_records"], list)
    assert isinstance(data["dnskey_records"], list)


async def test_check_dnssec_enabled_for_cloudflare(mcp_client):
    # cloudflare.com has DNSSEC enabled
    result = await mcp_client.call_tool("check_dnssec", {"domain": "cloudflare.com"})
    data = extract(result)
    assert data["dnssec_enabled"] is True


# ---------------------------------------------------------------------------
# whois_lookup
# ---------------------------------------------------------------------------

async def test_whois_lookup_success(mcp_client):
    result = await mcp_client.call_tool("whois_lookup", {"domain": "github.com"})
    data = extract(result)

    assert data["domain"] == "github.com"
    assert len(data["nameservers"]) > 0
    assert len(data["ip_addresses"]["ipv4"]) > 0
    assert data["soa_info"] is not None
    assert data["soa_info"]["primary_ns"]


# ---------------------------------------------------------------------------
# check_domain_availability
# ---------------------------------------------------------------------------

async def test_check_domain_availability_registered(mcp_client):
    result = await mcp_client.call_tool(
        "check_domain_availability", {"domain": "google.com"}
    )
    data = extract(result)

    assert data["domain"] == "google.com"
    assert data["has_dns_records"] is True
    assert len(data["configured_record_types"]) > 0


# ---------------------------------------------------------------------------
# trace_dns_delegation
# ---------------------------------------------------------------------------

async def test_trace_dns_delegation_success(mcp_client):
    result = await mcp_client.call_tool(
        "trace_dns_delegation", {"domain": "google.com"}
    )
    data = extract(result)

    assert data["domain"] == "google.com"
    assert len(data["authoritative_nameservers"]) > 0
    assert len(data["delegation_chain"]) > 0

    for entry in data["delegation_chain"]:
        assert entry["zone"]
        assert isinstance(entry["nameservers"], list)
