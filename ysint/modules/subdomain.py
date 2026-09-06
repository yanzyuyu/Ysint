import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
from ysint.utils import make_request

DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "app", "cdn", "mx", "email", "cloud", "support", "shop",
    "beta", "login", "auth", "status", "git", "gitlab", "jenkins", "jira",
    "docs", "dashboard", "monitor", "intranet", "internal", "direct", "corp",
    "gw", "db", "stage", "mobile", "static", "assets", "media", "preview",
    "demo", "m", "connect", "gateway", "sso", "id", "hub", "edge",
    "grafana", "kibana", "prometheus", "s3", "storage", "files", "download",
    "upload", "billing", "pay", "payment", "checkout", "store", "news",
    "forum", "community", "help", "kb", "wiki", "ws", "socket", "realtime",
    "track", "analytics", "stats", "metric", "metrics", "log", "logs",
    "ci", "cd", "build", "deploy", "release", "repo", "registry",
    "docker", "k8s", "cluster", "node", "proxy", "lb", "waf", "router",
    "firewall", "cpanel", "whm", "webdisk", "autodiscover", "sip", "voip",
    "chat", "meet", "conf", "video", "stream", "live", "relay", "vps"
]

def resolve_target(subdomain: str, base_domain: str, source: str = "DNS Wordlist") -> Dict[str, Any]:
    fqdn = f"{subdomain}.{base_domain}" if subdomain else base_domain
    try:
        ip = socket.gethostbyname(fqdn)
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ip": ip,
            "alive": True,
            "source": source
        }
    except (socket.gaierror, OSError):
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ip": None,
            "alive": False,
            "source": source
        }

def query_hackertarget_subdomains(domain: str, timeout: float = 6.0) -> List[Dict[str, Any]]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, _, body = make_request(url, timeout=timeout)
    found = []
    if status == 200 and body:
        text = body.decode("utf-8", errors="replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        for line in lines:
            if "," in line:
                host, ip = line.split(",", 1)
                host = host.strip().lower()
                ip = ip.strip()
                if host.endswith(f".{domain}") or host == domain:
                    sub_part = host[:-(len(domain) + 1)] if host.endswith(f".{domain}") else ""
                    found.append({
                        "subdomain": sub_part,
                        "fqdn": host,
                        "ip": ip if ip and ip != "No IP" else None,
                        "alive": bool(ip and ip != "No IP"),
                        "source": "HackerTarget Database"
                    })
    return found

def query_crtsh_subdomains(domain: str, timeout: float = 4.0) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    status, _, body = make_request(url, timeout=timeout)
    names = set()
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            for item in data[:100]:
                name_val = item.get("name_value", "")
                for sub in name_val.splitlines():
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub.endswith(f".{domain}") and sub != domain:
                        names.add(sub)
        except Exception:
            pass
    return list(names)

def scan_subdomains(domain_str: str, wordlist: List[str] = None, max_workers: int = 20) -> Dict[str, Any]:
    clean_domain = domain_str.strip().lower()
    if clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    elif clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    known_fqdns = {}

    ht_results = query_hackertarget_subdomains(clean_domain)
    for r in ht_results:
        known_fqdns[r["fqdn"]] = r

    crt_names = query_crtsh_subdomains(clean_domain)
    unresolved_crt = []
    for name in crt_names:
        if name not in known_fqdns:
            sub_part = name[:-(len(clean_domain) + 1)]
            unresolved_crt.append((sub_part, name))

    targets = wordlist or DEFAULT_WORDLIST
    unresolved_words = []
    for sub in targets:
        fqdn = f"{sub}.{clean_domain}"
        if fqdn not in known_fqdns:
            unresolved_words.append(sub)

    to_resolve = []
    for sub_part, name in unresolved_crt:
        to_resolve.append((sub_part, clean_domain, "Certificate Transparency Log"))
    for sub in unresolved_words:
        to_resolve.append((sub, clean_domain, "DNS Wordlist"))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(resolve_target, sub, dom, src) for sub, dom, src in to_resolve]
        for future in as_completed(futures):
            res = future.result()
            if res["alive"]:
                known_fqdns[res["fqdn"]] = res

    alive_subdomains = [item for item in known_fqdns.values() if item.get("alive")]
    alive_subdomains.sort(key=lambda x: x["fqdn"])

    return {
        "domain": clean_domain,
        "total_probed": len(targets) + len(unresolved_crt) + len(ht_results),
        "total_found": len(alive_subdomains),
        "subdomains": alive_subdomains
    }
