"""
DNS MCP Server - Comprehensive DNS query tools for domain information
Provides tools to query all DNS record types and perform DNS lookups
"""

import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.rdatatype
import socket
from typing import Optional, List, Dict, Any
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("DNS Query Server")

# Configure DNS resolver with common public DNS servers
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Google DNS and Cloudflare
resolver.timeout = 5
resolver.lifetime = 10


def format_dns_response(answers) -> List[Dict[str, Any]]:
    """Format DNS response into structured data"""
    results = []
    for rdata in answers:
        results.append({
            "data": str(rdata),
            "ttl": answers.rrset.ttl,
            "type": dns.rdatatype.to_text(answers.rdtype)
        })
    return results


@mcp.tool()
def query_a_record(domain: str) -> Dict[str, Any]:
    """
    Query A records (IPv4 addresses) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing IPv4 addresses and TTL information
    """
    try:
        answers = resolver.resolve(domain, 'A')
        return {
            "domain": domain,
            "record_type": "A",
            "records": format_dns_response(answers),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "A",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_aaaa_record(domain: str) -> Dict[str, Any]:
    """
    Query AAAA records (IPv6 addresses) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing IPv6 addresses and TTL information
    """
    try:
        answers = resolver.resolve(domain, 'AAAA')
        return {
            "domain": domain,
            "record_type": "AAAA",
            "records": format_dns_response(answers),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "AAAA",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_mx_record(domain: str) -> Dict[str, Any]:
    """
    Query MX records (mail exchange servers) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing mail server information with priority and TTL
    """
    try:
        answers = resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            records.append({
                "priority": rdata.preference,
                "mail_server": str(rdata.exchange),
                "ttl": answers.rrset.ttl
            })
        return {
            "domain": domain,
            "record_type": "MX",
            "records": sorted(records, key=lambda x: x['priority']),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "MX",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_txt_record(domain: str) -> Dict[str, Any]:
    """
    Query TXT records for a domain (includes SPF, DKIM, DMARC, verification records)
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing TXT records and TTL information
    """
    try:
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            # TXT records can have multiple strings
            txt_data = b''.join(rdata.strings).decode('utf-8')
            records.append({
                "data": txt_data,
                "ttl": answers.rrset.ttl
            })
        return {
            "domain": domain,
            "record_type": "TXT",
            "records": records,
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "TXT",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_ns_record(domain: str) -> Dict[str, Any]:
    """
    Query NS records (nameservers) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing authoritative nameserver information
    """
    try:
        answers = resolver.resolve(domain, 'NS')
        return {
            "domain": domain,
            "record_type": "NS",
            "records": format_dns_response(answers),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "NS",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_cname_record(domain: str) -> Dict[str, Any]:
    """
    Query CNAME records (canonical name/alias) for a domain
    
    Args:
        domain: The domain name to query (e.g., www.example.com)
    
    Returns:
        Dictionary containing CNAME alias information
    """
    try:
        answers = resolver.resolve(domain, 'CNAME')
        return {
            "domain": domain,
            "record_type": "CNAME",
            "records": format_dns_response(answers),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "CNAME",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_soa_record(domain: str) -> Dict[str, Any]:
    """
    Query SOA record (Start of Authority) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing SOA information including primary nameserver, 
        responsible party, serial number, and timing parameters
    """
    try:
        answers = resolver.resolve(domain, 'SOA')
        soa_data = answers[0]
        return {
            "domain": domain,
            "record_type": "SOA",
            "records": [{
                "primary_ns": str(soa_data.mname),
                "responsible_party": str(soa_data.rname),
                "serial": soa_data.serial,
                "refresh": soa_data.refresh,
                "retry": soa_data.retry,
                "expire": soa_data.expire,
                "minimum_ttl": soa_data.minimum,
                "ttl": answers.rrset.ttl
            }],
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "SOA",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_ptr_record(ip_address: str) -> Dict[str, Any]:
    """
    Query PTR record (reverse DNS lookup) for an IP address
    
    Args:
        ip_address: The IP address to reverse lookup (e.g., 8.8.8.8)
    
    Returns:
        Dictionary containing hostname(s) associated with the IP address
    """
    try:
        addr = dns.reversename.from_address(ip_address)
        answers = resolver.resolve(addr, 'PTR')
        return {
            "ip_address": ip_address,
            "record_type": "PTR",
            "records": format_dns_response(answers),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "ip_address": ip_address,
            "record_type": "PTR",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_srv_record(service: str, protocol: str, domain: str) -> Dict[str, Any]:
    """
    Query SRV records (service location) for a domain
    
    Args:
        service: The service name (e.g., 'sip', 'xmpp', 'ldap')
        protocol: The protocol (e.g., 'tcp', 'udp')
        domain: The domain name (e.g., example.com)
    
    Returns:
        Dictionary containing service location information with priority, weight, port, and target
    """
    try:
        srv_query = f"_{service}._{protocol}.{domain}"
        answers = resolver.resolve(srv_query, 'SRV')
        records = []
        for rdata in answers:
            records.append({
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
                "target": str(rdata.target),
                "ttl": answers.rrset.ttl
            })
        return {
            "query": srv_query,
            "record_type": "SRV",
            "records": sorted(records, key=lambda x: (x['priority'], -x['weight'])),
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "query": f"_{service}._{protocol}.{domain}",
            "record_type": "SRV",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_caa_record(domain: str) -> Dict[str, Any]:
    """
    Query CAA records (Certificate Authority Authorization) for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing CAA policy information
    """
    try:
        answers = resolver.resolve(domain, 'CAA')
        records = []
        for rdata in answers:
            records.append({
                "flags": rdata.flags,
                "tag": rdata.tag.decode('utf-8') if isinstance(rdata.tag, bytes) else rdata.tag,
                "value": rdata.value.decode('utf-8') if isinstance(rdata.value, bytes) else rdata.value,
                "ttl": answers.rrset.ttl
            })
        return {
            "domain": domain,
            "record_type": "CAA",
            "records": records,
            "nameserver": answers.nameserver,
            "success": True
        }
    except Exception as e:
        return {
            "domain": domain,
            "record_type": "CAA",
            "error": str(e),
            "success": False
        }


@mcp.tool()
def query_all_records(domain: str) -> Dict[str, Any]:
    """
    Query all common DNS record types for a domain
    
    Args:
        domain: The domain name to query (e.g., example.com)
    
    Returns:
        Dictionary containing all available DNS records for the domain
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
    results = {
        "domain": domain,
        "records": {}
    }
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            if record_type == 'MX':
                records = []
                for rdata in answers:
                    records.append({
                        "priority": rdata.preference,
                        "mail_server": str(rdata.exchange),
                        "ttl": answers.rrset.ttl
                    })
                results["records"][record_type] = sorted(records, key=lambda x: x['priority'])
            elif record_type == 'SOA':
                soa_data = answers[0]
                results["records"][record_type] = [{
                    "primary_ns": str(soa_data.mname),
                    "responsible_party": str(soa_data.rname),
                    "serial": soa_data.serial,
                    "refresh": soa_data.refresh,
                    "retry": soa_data.retry,
                    "expire": soa_data.expire,
                    "minimum_ttl": soa_data.minimum,
                    "ttl": answers.rrset.ttl
                }]
            elif record_type == 'TXT':
                records = []
                for rdata in answers:
                    txt_data = b''.join(rdata.strings).decode('utf-8')
                    records.append({
                        "data": txt_data,
                        "ttl": answers.rrset.ttl
                    })
                results["records"][record_type] = records
            elif record_type == 'CAA':
                records = []
                for rdata in answers:
                    records.append({
                        "flags": rdata.flags,
                        "tag": rdata.tag.decode('utf-8') if isinstance(rdata.tag, bytes) else rdata.tag,
                        "value": rdata.value.decode('utf-8') if isinstance(rdata.value, bytes) else rdata.value,
                        "ttl": answers.rrset.ttl
                    })
                results["records"][record_type] = records
            else:
                results["records"][record_type] = format_dns_response(answers)
        except Exception as e:
            results["records"][record_type] = {"error": str(e)}
    
    # Try CNAME separately as it may not exist for apex domains
    try:
        answers = resolver.resolve(domain, 'CNAME')
        results["records"]["CNAME"] = format_dns_response(answers)
    except:
        pass
    
    return results


@mcp.tool()
def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Check if DNSSEC is enabled for a domain
    
    Args:
        domain: The domain name to check (e.g., example.com)
    
    Returns:
        Dictionary containing DNSSEC status and DS/DNSKEY records if available
    """
    results = {
        "domain": domain,
        "dnssec_enabled": False,
        "ds_records": [],
        "dnskey_records": []
    }
    
    try:
        # Check for DS records
        answers = resolver.resolve(domain, 'DS')
        results["dnssec_enabled"] = True
        for rdata in answers:
            results["ds_records"].append({
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
                "digest": rdata.digest.hex(),
                "ttl": answers.rrset.ttl
            })
    except:
        pass
    
    try:
        # Check for DNSKEY records
        answers = resolver.resolve(domain, 'DNSKEY')
        results["dnssec_enabled"] = True
        for rdata in answers:
            results["dnskey_records"].append({
                "flags": rdata.flags,
                "protocol": rdata.protocol,
                "algorithm": rdata.algorithm,
                "ttl": answers.rrset.ttl
            })
    except:
        pass
    
    return results


@mcp.tool()
def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Perform a basic WHOIS-style lookup using DNS information
    
    Args:
        domain: The domain name to lookup (e.g., example.com)
    
    Returns:
        Dictionary containing comprehensive domain information from DNS
    """
    results = {
        "domain": domain,
        "nameservers": [],
        "mail_servers": [],
        "ip_addresses": {"ipv4": [], "ipv6": []},
        "soa_info": None
    }
    
    # Get nameservers
    try:
        answers = resolver.resolve(domain, 'NS')
        results["nameservers"] = [str(rdata) for rdata in answers]
    except:
        pass
    
    # Get mail servers
    try:
        answers = resolver.resolve(domain, 'MX')
        results["mail_servers"] = [
            {"priority": rdata.preference, "server": str(rdata.exchange)}
            for rdata in sorted(answers, key=lambda x: x.preference)
        ]
    except:
        pass
    
    # Get IP addresses
    try:
        answers = resolver.resolve(domain, 'A')
        results["ip_addresses"]["ipv4"] = [str(rdata) for rdata in answers]
    except:
        pass
    
    try:
        answers = resolver.resolve(domain, 'AAAA')
        results["ip_addresses"]["ipv6"] = [str(rdata) for rdata in answers]
    except:
        pass
    
    # Get SOA info
    try:
        answers = resolver.resolve(domain, 'SOA')
        soa_data = answers[0]
        results["soa_info"] = {
            "primary_ns": str(soa_data.mname),
            "responsible_party": str(soa_data.rname),
            "serial": soa_data.serial,
            "refresh": soa_data.refresh,
            "retry": soa_data.retry,
            "expire": soa_data.expire
        }
    except:
        pass
    
    return results


@mcp.tool()
def check_domain_availability(domain: str) -> Dict[str, Any]:
    """
    Check if a domain has DNS records configured (basic availability check)
    
    Args:
        domain: The domain name to check (e.g., example.com)
    
    Returns:
        Dictionary indicating if domain has DNS records and what types exist
    """
    results = {
        "domain": domain,
        "has_dns_records": False,
        "configured_record_types": []
    }
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            resolver.resolve(domain, record_type)
            results["has_dns_records"] = True
            results["configured_record_types"].append(record_type)
        except:
            pass
    
    return results


@mcp.tool()
def trace_dns_delegation(domain: str) -> Dict[str, Any]:
    """
    Trace DNS delegation chain from root to authoritative nameservers
    
    Args:
        domain: The domain name to trace (e.g., example.com)
    
    Returns:
        Dictionary showing the delegation chain and authoritative nameservers
    """
    results = {
        "domain": domain,
        "delegation_chain": [],
        "authoritative_nameservers": []
    }
    
    try:
        # Get authoritative nameservers
        answers = resolver.resolve(domain, 'NS')
        results["authoritative_nameservers"] = [str(rdata) for rdata in answers]
        
        # Build delegation chain
        parts = domain.split('.')
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])
            try:
                ns_answers = resolver.resolve(subdomain, 'NS')
                results["delegation_chain"].append({
                    "zone": subdomain,
                    "nameservers": [str(rdata) for rdata in ns_answers]
                })
            except:
                pass
    except Exception as e:
        results["error"] = str(e)
    
    return results


if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
