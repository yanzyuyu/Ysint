import ipaddress
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple, Dict, Any, List

def build_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.load_default_certs()
        return ctx
    except Exception:
        return ssl._create_unverified_context()

def make_request(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    data: Optional[bytes] = None,
    method: Optional[str] = None
) -> Tuple[int, Dict[str, str], bytes]:
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "*/*"
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, resp_headers, body
    except Exception:
        return 0, {}, b""

def query_public_search(query_str: str, timeout: float = 6.0) -> List[Dict[str, str]]:
    url = "https://lite.duckduckgo.com/lite/"
    post_data = urllib.parse.urlencode({"q": query_str}).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    status, _, body = make_request(url, headers=headers, timeout=timeout, data=post_data)
    if status != 200 or not body:
        return []

    html_text = body.decode("utf-8", errors="replace")
    links = re.findall(r"<a[^>]+class=['\"]result-link['\"][^>]*href=['\"]([^'\"]+)['\"][^>]*>(.*?)</a>", html_text, re.DOTALL)
    if not links:
        links = re.findall(r"<a[^>]+href=['\"]([^'\"]+)['\"][^>]*class=['\"]result-link['\"][^>]*>(.*?)</a>", html_text, re.DOTALL)
    snippets = re.findall(r"<td class=['\"]result-snippet['\"][^>]*>(.*?)</td>", html_text, re.DOTALL)

    results = []
    for i in range(min(len(links), len(snippets))):
        raw_url, raw_title = links[i]
        raw_snip = snippets[i]
        clean_title = re.sub(r"<[^>]+>", "", raw_title).strip()
        clean_title = re.sub(r"\s+", " ", clean_title)
        clean_snip = re.sub(r"<[^>]+>", "", raw_snip).strip()
        clean_snip = re.sub(r"\s+", " ", clean_snip)
        if clean_snip and not any(r["url"] == raw_url for r in results):
            results.append({
                "title": clean_title,
                "url": raw_url,
                "snippet": clean_snip
            })
    return results

def write_safe(text: str) -> None:
    encoding = sys.stdout.encoding or "utf-8"
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        sys.stdout.write(text.encode(encoding, errors="replace").decode(encoding))
    sys.stdout.flush()

def is_ipv4(target: str) -> bool:
    try:
        ipaddress.IPv4Address(target.strip())
        return True
    except ValueError:
        return False

def is_domain(target: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, target.strip()))

def is_email(target: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, target.strip()))

def is_phone_number(target: str) -> bool:
    clean = target.strip()
    if any(c.isalpha() for c in clean):
        return False
    digits = re.sub(r"\D", "", clean)
    if len(digits) < 7 or len(digits) > 15:
        return False
    if clean.startswith("+"):
        return True
    if clean.startswith("08") and 10 <= len(digits) <= 13:
        return True
    if any(c in clean for c in "-. ()"):
        return True
    if clean.startswith("0") and 9 <= len(digits) <= 14:
        return True
    return 10 <= len(digits) <= 15
