# DNS MCP Server

A comprehensive DNS query server built with FastMCP that provides tools to query all types of DNS records and gather complete domain information.

## Features

### DNS Record Query Tools

- **A Records** - Query IPv4 addresses
- **AAAA Records** - Query IPv6 addresses
- **MX Records** - Query mail exchange servers with priorities
- **TXT Records** - Query text records (SPF, DKIM, DMARC, verification)
- **NS Records** - Query authoritative nameservers
- **CNAME Records** - Query canonical name aliases
- **SOA Records** - Query Start of Authority information
- **PTR Records** - Reverse DNS lookups
- **SRV Records** - Query service location records
- **CAA Records** - Query Certificate Authority Authorization
- **DS/DNSKEY Records** - Check DNSSEC configuration

### Advanced Tools

- **Query All Records** - Get all DNS records for a domain in one call
- **DNSSEC Check** - Verify DNSSEC configuration
- **WHOIS-style Lookup** - Comprehensive domain information via DNS
- **Domain Availability Check** - Check if domain has DNS configured
- **DNS Delegation Trace** - Trace delegation chain from root to authoritative nameservers

## Installation

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server locally:
```bash
python dns_server.py
```

The server will start on `http://localhost:8000` by default.

### Deploy to FastMCP Cloud

1. Install FastMCP CLI if you haven't already:
```bash
pip install fastmcp
```

2. Login to FastMCP Cloud:
```bash
fastmcp login
```

3. Deploy the server:
```bash
fastmcp deploy dns_server.py
```

4. The CLI will provide you with a public URL where your MCP server is accessible.

## Usage Examples

### Using with MCP Client

```python
import asyncio
from fastmcp import Client

# Replace with your deployed URL
client = Client("https://your-server.fastmcp.app/mcp")

async def main():
    async with client:
        # Query A records
        result = await client.call_tool("query_a_record", {"domain": "google.com"})
        print(result)
        
        # Query all records
        result = await client.call_tool("query_all_records", {"domain": "example.com"})
        print(result)
        
        # Reverse DNS lookup
        result = await client.call_tool("query_ptr_record", {"ip_address": "8.8.8.8"})
        print(result)
        
        # Check DNSSEC
        result = await client.call_tool("check_dnssec", {"domain": "cloudflare.com"})
        print(result)

asyncio.run(main())
```

### Available Tools

#### Basic DNS Queries

- `query_a_record(domain: str)` - Get IPv4 addresses
- `query_aaaa_record(domain: str)` - Get IPv6 addresses
- `query_mx_record(domain: str)` - Get mail servers
- `query_txt_record(domain: str)` - Get TXT records
- `query_ns_record(domain: str)` - Get nameservers
- `query_cname_record(domain: str)` - Get CNAME alias
- `query_soa_record(domain: str)` - Get SOA information
- `query_caa_record(domain: str)` - Get CAA records

#### Advanced Queries

- `query_ptr_record(ip_address: str)` - Reverse DNS lookup
- `query_srv_record(service: str, protocol: str, domain: str)` - Service location
- `query_all_records(domain: str)` - Get all DNS records at once
- `check_dnssec(domain: str)` - Check DNSSEC status
- `whois_lookup(domain: str)` - Comprehensive domain info
- `check_domain_availability(domain: str)` - Check if domain is configured
- `trace_dns_delegation(domain: str)` - Trace delegation chain

## DNS Resolver Configuration

The server uses the following public DNS resolvers:
- Google DNS: 8.8.8.8, 8.8.4.4
- Cloudflare DNS: 1.1.1.1

Timeout: 5 seconds
Lifetime: 10 seconds

## Response Format

All tools return structured JSON responses with:
- `success`: Boolean indicating if query succeeded
- `domain`/`ip_address`: The queried domain or IP
- `record_type`: Type of DNS record
- `records`: Array of record data with TTL information
- `nameserver`: The nameserver that provided the response
- `error`: Error message if query failed

### Example Response

```json
{
  "domain": "example.com",
  "record_type": "A",
  "records": [
    {
      "data": "93.184.216.34",
      "ttl": 86400,
      "type": "A"
    }
  ],
  "nameserver": "8.8.8.8",
  "success": true
}
```

## Use Cases

- **Domain Investigation** - Research domain DNS configuration
- **Email Configuration** - Check MX and SPF/DKIM/DMARC records
- **Security Analysis** - Verify DNSSEC, CAA records
- **Network Troubleshooting** - Reverse lookups, delegation tracing
- **Domain Monitoring** - Track DNS changes and availability
- **Migration Planning** - Document current DNS setup

## Error Handling

The server gracefully handles DNS query failures and returns structured error responses:

```json
{
  "domain": "nonexistent.example",
  "record_type": "A",
  "error": "The DNS query name does not exist: nonexistent.example.",
  "success": false
}
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
