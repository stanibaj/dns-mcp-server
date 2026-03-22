#!/usr/bin/env python3
"""
MCP healthcheck.

Simulates a real MCP client over SSE (stdlib only — no third-party deps):
  1. GET /sse            — open the SSE stream
  2. Read endpoint event — learn the session POST URL
  3. POST initialize     — complete the MCP handshake
  4. POST tools/call ×3  — verify core DNS tools work end-to-end:
       • query_a_record   google.com  → must return ≥1 A record
       • query_txt_record google.com  → must contain an SPF record
       • whois_lookup     github.com  → must return nameservers

Exits 0 (healthy) or 1 (unhealthy).
"""

import http.client
import json
import os
import sys

HOST = os.getenv("MCP_HOST", "127.0.0.1")
if HOST in ("0.0.0.0", ""):
    HOST = "127.0.0.1"
PORT = int(os.getenv("MCP_PORT", "8000"))

_request_id = 0


def die(msg: str) -> None:
    print(f"HEALTHCHECK FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


# ── 1. Open the SSE stream ──────────────────────────────────────────────────

try:
    sse = http.client.HTTPConnection(HOST, PORT, timeout=15)
    sse.request("GET", "/sse", headers={"Accept": "text/event-stream"})
    sse_resp = sse.getresponse()
except Exception as exc:
    die(f"cannot reach server at {HOST}:{PORT} — {exc}")

if sse_resp.status != 200:
    die(f"GET /sse returned HTTP {sse_resp.status}")


# ── SSE reader ──────────────────────────────────────────────────────────────

def read_event() -> tuple[str, str]:
    """Block until one complete SSE event is received; return (type, data)."""
    etype, edata = "", ""
    while True:
        try:
            raw = sse_resp.readline()
        except Exception as exc:
            die(f"SSE read error: {exc}")
        if not raw:
            die("SSE stream closed unexpectedly")
        line = raw.decode().rstrip("\r\n")
        if line.startswith("event:"):
            etype = line[6:].strip()
        elif line.startswith("data:"):
            edata = line[5:].strip()
        elif line == "" and (etype or edata):
            return etype, edata


# ── 2. Read the POST endpoint URL ──────────────────────────────────────────

etype, endpoint_path = read_event()
if etype != "endpoint":
    die(f"expected 'endpoint' SSE event, got {etype!r}")


# ── JSON-RPC helpers ────────────────────────────────────────────────────────

def _post(payload: dict) -> None:
    body = json.dumps(payload).encode()
    try:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
        conn.request(
            "POST", endpoint_path, body=body,
            headers={"Content-Type": "application/json"},
        )
        conn.getresponse().read()
        conn.close()
    except Exception as exc:
        die(f"POST {endpoint_path} failed: {exc}")


def rpc(method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC request and return the full response dict."""
    global _request_id
    _request_id += 1
    _post({
        "jsonrpc": "2.0",
        "id": _request_id,
        "method": method,
        "params": params or {},
    })
    etype, edata = read_event()
    if etype != "message":
        die(f"expected 'message' SSE event, got {etype!r}")
    try:
        return json.loads(edata)
    except json.JSONDecodeError as exc:
        die(f"malformed JSON in SSE message: {exc}")


def notify(method: str, params: dict | None = None) -> None:
    """Send a JSON-RPC notification (no response expected)."""
    _post({"jsonrpc": "2.0", "method": method, "params": params or {}})


# ── 3. MCP initialize handshake ────────────────────────────────────────────

resp = rpc("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "healthcheck", "version": "1.0"},
})
if "error" in resp:
    die(f"initialize error: {resp['error']}")

notify("notifications/initialized")


# ── 4. Probe tools ──────────────────────────────────────────────────────────

def call_tool(name: str, args: dict) -> dict:
    resp = rpc("tools/call", {"name": name, "arguments": args})
    if "error" in resp:
        die(f"tools/call '{name}' RPC error: {resp['error']}")
    try:
        return json.loads(resp["result"]["content"][0]["text"])
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        die(f"tools/call '{name}' — unexpected result shape: {exc}")


# query_a_record
data = call_tool("query_a_record", {"domain": "google.com"})
if not data.get("success"):
    die(f"query_a_record: {data.get('error', 'success=False')}")
if not data.get("records"):
    die("query_a_record: no A records returned for google.com")

# query_txt_record
data = call_tool("query_txt_record", {"domain": "google.com"})
if not data.get("success"):
    die(f"query_txt_record: {data.get('error', 'success=False')}")
if not any("v=spf1" in r.get("data", "") for r in data.get("records", [])):
    die("query_txt_record: SPF record not found for google.com")

# whois_lookup
data = call_tool("whois_lookup", {"domain": "github.com"})
if not data.get("nameservers"):
    die(f"whois_lookup: no nameservers returned for github.com")


print("OK — A record, TXT/SPF, and WHOIS all passed")
sys.exit(0)
