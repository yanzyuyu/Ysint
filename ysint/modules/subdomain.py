import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "app", "cdn", "mx", "email", "cloud", "support", "shop",
    "beta", "login", "auth", "status", "git", "gitlab", "jenkins", "jira",
    "docs", "dashboard", "monitor", "intranet", "internal", "direct", "corp",
    "gw", "db", "stage", "mobile", "static", "assets", "media", "preview",
    "demo", "m", "connect", "gateway", "sso", "id", "hub", "edge"
]

def resolve_target(subdomain: str, base_domain: str) -> Dict[str, Any]:
    fqdn = f"{subdomain}.{base_domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ip": ip,
            "alive": True
        }
    except (socket.gaierror, OSError):
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ip": None,
            "alive": False
        }

def scan_subdomains(domain_str: str, wordlist: List[str] = None, max_workers: int = 20) -> Dict[str, Any]:
    clean_domain = domain_str.strip().lower()
    if clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    elif clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    targets = wordlist or DEFAULT_WORDLIST
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(resolve_target, sub, clean_domain) for sub in targets]
        for future in as_completed(futures):
            res = future.result()
            if res["alive"]:
                found.append(res)

    found.sort(key=lambda x: x["fqdn"])
    return {
        "domain": clean_domain,
        "total_probed": len(targets),
        "total_found": len(found),
        "subdomains": found
    }
