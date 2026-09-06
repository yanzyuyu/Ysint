import ipaddress
import re
import ssl
import sys
import urllib.error
import urllib.request
from typing import Optional, Tuple, Dict, Any

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
