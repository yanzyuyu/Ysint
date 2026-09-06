import json
import socket
import ssl
from typing import Dict, List, Any, Optional
from ysint.utils import make_request, build_ssl_context
from ysint.modules.ip import scan_ip

DNS_TYPES = ["MX", "TXT", "NS", "CNAME", "SOA"]
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

def resolve_dns_records(domain: str, timeout: float = 5.0) -> Dict[str, List[str]]:
    records = {}
    for record_type in DNS_TYPES:
        url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        status, _, body = make_request(url, timeout=timeout)
        records[record_type] = []
        if status == 200 and body:
            try:
                data = json.loads(body.decode("utf-8", errors="replace"))
                answers = data.get("Answer", [])
                for ans in answers:
                    val = ans.get("data")
                    if val:
                        records[record_type].append(val)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
    return records

def check_security_headers(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    url = f"https://{domain}"
    status, headers, _ = make_request(url, timeout=timeout)
    if status == 0:
        url = f"http://{domain}"
        status, headers, _ = make_request(url, timeout=timeout)

    detected = {}
    missing = []
    server = headers.get("server")
    for sec_header in SECURITY_HEADERS:
        if sec_header in headers:
            detected[sec_header] = headers[sec_header]
        else:
            missing.append(sec_header)

    return {
        "status_code": status,
        "server": server,
        "headers_present": detected,
        "headers_missing": missing
    }

def inspect_ssl_tls(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    ctx = build_ssl_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "enabled": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher and len(cipher) > 2 else None
                }
    except Exception:
        return {
            "enabled": False,
            "version": None,
            "cipher": None,
            "bits": None
        }

def lookup_domain_rdap(domain: str, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    url = f"https://rdap.org/domain/{domain}"
    status, _, body = make_request(url, timeout=timeout)
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if e.get("eventAction")}
            registrar = None
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = ent.get("vcardArray", [[]])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn" and len(field) > 3:
                                registrar = field[3]
                                break
                if registrar:
                    break
            return {
                "registrar": registrar,
                "created": events.get("registration"),
                "expires": events.get("expiration"),
                "updated": events.get("last changed")
            }
        except Exception:
            pass
    return None

def scan_domain(domain_str: str, timeout: float = 5.0) -> Dict[str, Any]:
    clean_domain = domain_str.strip().lower()
    if clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    elif clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    ipv4_addrs = []
    ipv6_addrs = []
    try:
        addr_info = socket.getaddrinfo(clean_domain, 80, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            family, _, _, _, sockaddr = item
            ip_val = sockaddr[0]
            if family == socket.AF_INET and ip_val not in ipv4_addrs:
                ipv4_addrs.append(ip_val)
            elif family == socket.AF_INET6 and ip_val not in ipv6_addrs:
                ipv6_addrs.append(ip_val)
    except (socket.gaierror, OSError):
        pass

    geo_ip = scan_ip(ipv4_addrs[0], timeout=timeout) if ipv4_addrs else None
    dns_records = resolve_dns_records(clean_domain, timeout=timeout)
    sec_headers = check_security_headers(clean_domain, timeout=timeout)
    ssl_info = inspect_ssl_tls(clean_domain, timeout=timeout)
    rdap_info = lookup_domain_rdap(clean_domain, timeout=timeout)

    return {
        "domain": clean_domain,
        "ipv4": ipv4_addrs,
        "ipv6": ipv6_addrs,
        "primary_geo": geo_ip,
        "rdap": rdap_info,
        "dns": dns_records,
        "ssl": ssl_info,
        "security_headers": sec_headers,
        "osint_pivots": {
            "crt_sh": f"https://crt.sh/?q=%.{clean_domain}",
            "urlscan": f"https://urlscan.io/domain/{clean_domain}",
            "virustotal": f"https://www.virustotal.com/gui/domain/{clean_domain}",
            "shodan": f"https://www.shodan.io/search?query=hostname%3A{clean_domain}",
            "archive_org": f"https://web.archive.org/web/*/{clean_domain}",
            "otx_alienvault": f"https://otx.alienvault.com/indicator/domain/{clean_domain}"
        }
    }
