import asyncio
from fastmcp import Client

# For local testing, use localhost
# For deployed server, replace with your FastMCP Cloud URL
client = Client("http://localhost:8000/mcp")

async def main():
    async with client:
        print("=== DNS MCP Server Test ===\n")
        
        # Ensure client can connect
        await client.ping()
        print("✓ Connected to server\n")

        # List available tools
        tools = await client.list_tools()
        print(f"Available tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool['name']}")
        print()

        # Test A record query
        print("Testing A record query for google.com:")
        result = await client.call_tool("query_a_record", {"domain": "google.com"})
        print(f"  Result: {result}\n")

        # Test MX record query
        print("Testing MX record query for gmail.com:")
        result = await client.call_tool("query_mx_record", {"domain": "gmail.com"})
        print(f"  Result: {result}\n")

        # Test all records query
        print("Testing all records query for cloudflare.com:")
        result = await client.call_tool("query_all_records", {"domain": "cloudflare.com"})
        print(f"  Result: {result}\n")

        # Test reverse DNS
        print("Testing reverse DNS for 8.8.8.8:")
        result = await client.call_tool("query_ptr_record", {"ip_address": "8.8.8.8"})
        print(f"  Result: {result}\n")

        # Test DNSSEC check
        print("Testing DNSSEC check for cloudflare.com:")
        result = await client.call_tool("check_dnssec", {"domain": "cloudflare.com"})
        print(f"  Result: {result}\n")

        print("=== All tests completed ===")

asyncio.run(main())