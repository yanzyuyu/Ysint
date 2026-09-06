import json
from typing import Dict, Any, List
from ysint.utils import is_email, make_request

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "temp-mail.org", "fakeinbox.com", "dispostable.com", "getairmail.com",
    "trashmail.com", "burnermail.io", "maildrop.cc", "crazymailing.com",
    "mohmal.com", "nada.ltd", "temp-mail.io", "fakemailgenerator.com",
    "inboxkitten.com", "emailondeck.com", "generator.email"
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

    return {
        "email": clean_email,
        "valid_syntax": True,
        "username": user_part,
        "domain": domain_part,
        "is_disposable": is_disposable,
        "mx_found": can_receive_mail,
        "mx_records": mx_records,
        "deliverable": can_receive_mail and not is_disposable
    }
