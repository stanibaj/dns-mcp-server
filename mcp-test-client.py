import asyncio
import json
from fastmcp import Client

# For local testing, use localhost
# For deployed server, replace with your FastMCP Cloud URL
client = Client("http://localhost:8000/sse")

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
            # Access Tool object attributes directly
            print(f"  - {tool.name}: {tool.description}")
        print()

        def extract_result(result):
            """Extract JSON data from CallToolResult"""
            if result.content and len(result.content) > 0:
                text_content = result.content[0].text
                return json.loads(text_content)
            return None

        # Test A record query
        print("Testing A record query for google.com:")
        result = await client.call_tool("query_a_record", {"domain": "google.com"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        # Test MX record query
        print("Testing MX record query for gmail.com:")
        result = await client.call_tool("query_mx_record", {"domain": "gmail.com"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        # Test TXT record query (SPF, DKIM, DMARC)
        print("Testing TXT record query for google.com:")
        result = await client.call_tool("query_txt_record", {"domain": "google.com"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        # Test reverse DNS
        print("Testing reverse DNS for 8.8.8.8:")
        result = await client.call_tool("query_ptr_record", {"ip_address": "8.8.8.8"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        # Test DNSSEC check
        print("Testing DNSSEC check for cloudflare.com:")
        result = await client.call_tool("check_dnssec", {"domain": "cloudflare.com"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        # Test WHOIS-style lookup
        print("Testing WHOIS-style lookup for github.com:")
        result = await client.call_tool("whois_lookup", {"domain": "github.com"})
        data = extract_result(result)
        print(f"  Result: {json.dumps(data, indent=2)}\n")

        print("=== All tests completed ===")

asyncio.run(main())