import hashlib
import json
import urllib.parse
from typing import Dict, Any, List, Optional
from ysint.utils import is_email, make_request, query_public_search

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "temp-mail.org", "fakeinbox.com", "dispostable.com", "getairmail.com",
    "trashmail.com", "burnermail.io", "maildrop.cc", "crazymailing.com",
    "mohmal.com", "nada.ltd", "temp-mail.io", "fakemailgenerator.com",
    "inboxkitten.com", "emailondeck.com", "generator.email", "tempail.com",
    "dropmail.me", "fakemail.net", "getnada.com", "inboxbear.com",
    "mytemp.email", "owlymail.com", "privaterelay.appleid.com", "receivemail.org",
    "trash-mail.com", "trashmail.net", "zetmail.com", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.net", "guerrillamail.org", "spam4.me",
    "grr.la", "pokemail.net", "tempmailaddress.com", "mailcatch.com",
    "disposablemail.com", "mailfake.com", "burneremail.net", "tempmail.net"
}

def check_mx_records(domain: str, timeout: float = 5.0) -> List[str]:
    url = f"https://dns.google/resolve?name={domain}&type=MX"
    status, _, body = make_request(url, timeout=timeout)
    mx_list = []
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            answers = data.get("Answer", [])
            for ans in answers:
                val = ans.get("data")
                if val:
                    mx_list.append(val.strip().rstrip("."))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return mx_list

def check_pgp_keyserver(email: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
    encoded = urllib.parse.quote(email)
    url = f"https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search={encoded}"
    status, _, body = make_request(url, timeout=timeout)
    keys = []
    if status == 200 and body:
        text = body.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("pub:"):
                parts = line.split(":")
                if len(parts) >= 5:
                    key_id = parts[1]
                    bits = parts[3]
                    created = parts[4]
                    keys.append({
                        "key_id": key_id,
                        "bits": bits,
                        "created_timestamp": created,
                        "view_url": f"https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{key_id}"
                    })
    return keys

def check_gravatar(email: str, timeout: float = 4.0) -> Dict[str, Any]:
    clean = email.lower().strip()
    md5_hash = hashlib.md5(clean.encode("utf-8")).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
    status, _, _ = make_request(avatar_url, timeout=timeout)
    return {
        "registered": status == 200,
        "avatar_url": avatar_url if status == 200 else None,
        "hash": md5_hash
    }

def check_xposedornot_breaches(email: str, timeout: float = 6.0) -> List[str]:
    encoded = urllib.parse.quote(email)
    url = f"https://api.xposedornot.com/v1/check-email/{encoded}"
    status, _, body = make_request(url, timeout=timeout)
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            breaches = data.get("breaches", [])
            if breaches and isinstance(breaches, list):
                if isinstance(breaches[0], list):
                    return breaches[0]
                return breaches
        except Exception:
            pass
    return []

def check_hudsonrock_stealer(email: str, timeout: float = 6.0) -> Dict[str, Any]:
    encoded = urllib.parse.quote(email)
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={encoded}"
    status, _, body = make_request(url, timeout=timeout)
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            stealers = data.get("stealers", [])
            if stealers:
                first = stealers[0]
                return {
                    "compromised": True,
                    "total_services": data.get("total_user_services", 0) + data.get("total_corporate_services", 0),
                    "date_compromised": first.get("date_compromised"),
                    "os": first.get("operating_system"),
                    "malware_path": first.get("malware_path"),
                    "antiviruses": first.get("antiviruses", [])
                }
        except Exception:
            pass
    return {
        "compromised": False,
        "total_services": 0,
        "date_compromised": None,
        "os": None,
        "malware_path": None,
        "antiviruses": []
    }

def search_email_leak_footprint(email: str, timeout: float = 6.0) -> List[Dict[str, str]]:
    query_str = f'"{email}" (site:pastebin.com OR site:github.com OR filetype:sql OR filetype:csv)'
    return query_public_search(query_str, timeout=timeout)

def scan_email(email_str: str, timeout: float = 5.0) -> Dict[str, Any]:
    clean_email = email_str.strip()
    if not is_email(clean_email):
        return {
            "email": clean_email,
            "valid_syntax": False,
            "message": "Invalid email address format"
        }

    user_part, domain_part = clean_email.split("@", 1)
    domain_part = domain_part.lower()
    is_disposable = domain_part in DISPOSABLE_DOMAINS
    mx_records = check_mx_records(domain_part, timeout=timeout)
    can_receive_mail = len(mx_records) > 0

    pgp_keys = check_pgp_keyserver(clean_email, timeout=timeout)
    gravatar_info = check_gravatar(clean_email, timeout=timeout)
    breaches = check_xposedornot_breaches(clean_email, timeout=timeout)
    stealer_info = check_hudsonrock_stealer(clean_email, timeout=timeout)
    leak_mentions = search_email_leak_footprint(clean_email, timeout=timeout)

    return {
        "email": clean_email,
        "valid_syntax": True,
        "username": user_part,
        "domain": domain_part,
        "is_disposable": is_disposable,
        "mx_found": can_receive_mail,
        "mx_records": mx_records,
        "deliverable": can_receive_mail and not is_disposable,
        "pgp_keys": pgp_keys,
        "gravatar": gravatar_info,
        "breaches": breaches,
        "infostealer": stealer_info,
        "leak_footprint": leak_mentions,
        "osint_pivots": {
            "haveibeenpwned": f"https://haveibeenpwned.com/account/{clean_email}",
            "intelx": f"https://intelx.io/?s={clean_email}",
            "dehashed": f"https://www.dehashed.com/search?query={clean_email}",
            "google_leaks": f'"{clean_email}" (site:pastebin.com OR filetype:sql OR filetype:csv)'
        }
    }
