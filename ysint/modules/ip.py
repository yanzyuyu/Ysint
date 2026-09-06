import ipaddress
import json
import socket
from typing import Dict, Any, Optional, List
from ysint.utils import make_request

def lookup_reverse_dns(ip_str: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None

def lookup_reverse_ip_domains(ip_str: str, timeout: float = 5.0) -> List[str]:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_str}"
    status, _, body = make_request(url, timeout=timeout)
    if status == 200 and body:
        text = body.decode("utf-8", errors="replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines and not any("No DNS" in line or "error" in line.lower() for line in lines):
            return lines[:20]
    return []

def scan_ip(ip_str: str, timeout: float = 5.0) -> Dict[str, Any]:
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return {
            "query": clean_ip,
            "status": "error",
            "message": "Invalid IP address format"
        }

    is_special = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    if is_special:
        scope = "Loopback" if ip_obj.is_loopback else ("Private" if ip_obj.is_private else "Reserved")
        return {
            "query": clean_ip,
            "status": "special",
            "is_private": True,
            "scope": scope,
            "reverse_dns": lookup_reverse_dns(clean_ip)
        }

    api_url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    status_code, _, body = make_request(api_url, timeout=timeout)
    reverse_dns = lookup_reverse_dns(clean_ip)
    co_hosted = lookup_reverse_ip_domains(clean_ip, timeout=timeout)

    threat_pivots = {
        "shodan": f"https://www.shodan.io/host/{clean_ip}",
        "censys": f"https://search.censys.io/hosts/{clean_ip}",
        "abuseipdb": f"https://www.abuseipdb.com/check/{clean_ip}",
        "greynoise": f"https://viz.greynoise.io/ip/{clean_ip}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{clean_ip}",
        "bgp_he": f"https://bgp.he.net/ip/{clean_ip}"
    }

    if status_code == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            if data.get("status") == "success":
                return {
                    "query": clean_ip,
                    "status": "success",
                    "is_private": False,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "postal": data.get("zip"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as"),
                    "reverse_dns": reverse_dns,
                    "co_hosted_domains": co_hosted,
                    "threat_pivots": threat_pivots
                }
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    return {
        "query": clean_ip,
        "status": "partial",
        "is_private": False,
        "reverse_dns": reverse_dns,
        "co_hosted_domains": co_hosted,
        "threat_pivots": threat_pivots
    }
