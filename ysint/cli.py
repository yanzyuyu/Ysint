import argparse
import json
import sys
from typing import Dict, Any, List
from ysint.utils import is_ipv4, is_domain, is_email, is_phone_number, write_safe
from ysint.modules.username import scan_username
from ysint.modules.ip import scan_ip
from ysint.modules.domain import scan_domain
from ysint.modules.email import scan_email
from ysint.modules.subdomain import scan_subdomains
from ysint.modules.phone import scan_phone

CLR_CYAN = "\033[96m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_RED = "\033[91m"
CLR_BOLD = "\033[1m"
CLR_RESET = "\033[0m"

BANNER = fr"""{CLR_CYAN}{CLR_BOLD}
 __     ______  _       _   
 \ \   / / ___|(_)_ __ | |_ 
  \ \ / /\___ \| | '_ \| __|
   \ V /  ___) | | | | | |_ 
    \_/  |____/|_|_| |_|\__|
{CLR_RESET}{CLR_YELLOW} OSINT Reconnaissance Engine v1.0.0{CLR_RESET}
"""

def print_badge(badge_type: str, message: str) -> None:
    if badge_type == "ok":
        prefix = f"{CLR_GREEN}[+]{CLR_RESET}"
    elif badge_type == "fail":
        prefix = f"{CLR_RED}[-]{CLR_RESET}"
    elif badge_type == "warn":
        prefix = f"{CLR_YELLOW}[!]{CLR_RESET}"
    else:
        prefix = f"{CLR_CYAN}[*]{CLR_RESET}"
    write_safe(f"{prefix} {message}\n")

def print_header(title: str) -> None:
    write_safe(f"\n{CLR_BOLD}--- {title} ---{CLR_RESET}\n")

def format_user_report(data: Dict[str, Any]) -> None:
    print_header(f"Username Recon: {data['target']}")
    write_safe(f"Probed: {data['total_probed']} platforms | Found: {data['total_found']} active accounts\n\n")
    for profile in data["profiles"]:
        if profile["found"]:
            write_safe(f"  {CLR_GREEN}[FOUND]{CLR_RESET} {profile['platform']:<14} : {profile['url']}\n")
        else:
            write_safe(f"  {CLR_RED}[NOT FOUND]{CLR_RESET} {profile['platform']:<14}\n")

    pivots = data.get("osint_pivots", {})
    if pivots:
        print_header("Identity & Footprint Pivots")
        for pk, pv in pivots.items():
            label = pk.replace("_", " ").title()
            write_safe(f"  {label:<18}: {pv}\n")

def format_ip_report(data: Dict[str, Any]) -> None:
    print_header(f"IP Intelligence: {data.get('query')}")
    if data.get("is_private"):
        print_badge("warn", f"Target is a {data.get('scope')} IP address.")
        if data.get("reverse_dns"):
            write_safe(f"  Reverse DNS : {data.get('reverse_dns')}\n")
        return

    if data.get("status") == "success":
        write_safe(f"  Country     : {data.get('country')} ({data.get('country_code')})\n")
        write_safe(f"  Region/City : {data.get('region')}, {data.get('city')} (ZIP: {data.get('postal')})\n")
        write_safe(f"  Coordinates : {data.get('latitude')}, {data.get('longitude')}\n")
        write_safe(f"  Timezone    : {data.get('timezone')}\n")
        write_safe(f"  ISP         : {data.get('isp')}\n")
        write_safe(f"  Org         : {data.get('organization')}\n")
        write_safe(f"  ASN         : {data.get('asn')}\n")
        if data.get("reverse_dns"):
            write_safe(f"  Reverse DNS : {data.get('reverse_dns')}\n")
    else:
        print_badge("fail", f"Could not retrieve geolocation: {data.get('message', 'Unknown error')}")

    co_hosted = data.get("co_hosted_domains", [])
    if co_hosted:
        print_header(f"Co-Hosted Public Domains Database ({len(co_hosted)})")
        for ch in co_hosted[:12]:
            write_safe(f"  - {ch}\n")

    threats = data.get("threat_pivots", {})
    if threats:
        print_header("Threat Intelligence & Scanner Pivots")
        for tk, tv in threats.items():
            write_safe(f"  {tk.upper():<14}: {tv}\n")

def format_domain_report(data: Dict[str, Any]) -> None:
    print_header(f"Domain Recon: {data['domain']}")
    if data["ipv4"]:
        write_safe(f"  IPv4 Addresses: {', '.join(data['ipv4'])}\n")
    if data["ipv6"]:
        write_safe(f"  IPv6 Addresses: {', '.join(data['ipv6'])}\n")

    geo = data.get("primary_geo")
    if geo and geo.get("status") == "success":
        write_safe(f"  Server Location: {geo.get('city')}, {geo.get('country')} ({geo.get('isp')})\n")

    rdap = data.get("rdap")
    if rdap:
        print_header("Public RDAP Registry Metadata")
        if rdap.get("registrar"):
            write_safe(f"  Registrar   : {rdap.get('registrar')}\n")
        if rdap.get("created"):
            write_safe(f"  Registered  : {rdap.get('created')}\n")
        if rdap.get("expires"):
            write_safe(f"  Expires     : {rdap.get('expires')}\n")

    ssl_info = data.get("ssl", {})
    if ssl_info.get("enabled"):
        write_safe(f"  SSL/TLS: {ssl_info.get('version')} ({ssl_info.get('cipher')}, {ssl_info.get('bits')} bits)\n")
    else:
        write_safe(f"  SSL/TLS: Not configured or unreachable\n")

    dns = data.get("dns", {})
    print_header("DNS Records")
    for rtype, rvals in dns.items():
        if rvals:
            write_safe(f"  [{rtype}]\n")
            for val in rvals:
                write_safe(f"    - {val}\n")

    sec = data.get("security_headers", {})
    print_header("Security Headers Analysis")
    if sec.get("server"):
        write_safe(f"  Server Header: {sec.get('server')}\n")
    present = sec.get("headers_present", {})
    missing = sec.get("headers_missing", [])
    if present:
        write_safe(f"  {CLR_GREEN}Configured Headers:{CLR_RESET}\n")
        for hk, hv in present.items():
            write_safe(f"    {CLR_GREEN}+{CLR_RESET} {hk}: {hv[:80]}\n")
    if missing:
        write_safe(f"  {CLR_YELLOW}Missing Headers:{CLR_RESET}\n")
        for hk in missing:
            write_safe(f"    {CLR_YELLOW}-{CLR_RESET} {hk}\n")

    pivots = data.get("osint_pivots", {})
    if pivots:
        print_header("OSINT Pivots & Threat Intelligence")
        for pk, pv in pivots.items():
            label = pk.replace("_", " ").upper()
            write_safe(f"  {label:<16}: {pv}\n")

def format_email_report(data: Dict[str, Any]) -> None:
    print_header(f"Email Intelligence: {data.get('email')}")
    if not data.get("valid_syntax"):
        print_badge("fail", "Invalid email syntax format.")
        return

    write_safe(f"  Username    : {data.get('username')}\n")
    write_safe(f"  Domain      : {data.get('domain')}\n")
    disp_flag = f"{CLR_RED}YES (Temporary/Disposable){CLR_RESET}" if data.get("is_disposable") else f"{CLR_GREEN}NO (Legitimate Domain){CLR_RESET}"
    write_safe(f"  Disposable  : {disp_flag}\n")

    deliv_flag = f"{CLR_GREEN}VALID (Mail servers active){CLR_RESET}" if data.get("deliverable") else f"{CLR_RED}UNRELIABLE{CLR_RESET}"
    write_safe(f"  Deliverable : {deliv_flag}\n")

    mx_records = data.get("mx_records", [])
    if mx_records:
        write_safe(f"  MX Servers  :\n")
        for mx in mx_records:
            write_safe(f"    - {mx}\n")
    else:
        print_badge("warn", "No MX records found for domain.")

    pgp_keys = data.get("pgp_keys", [])
    if pgp_keys:
        print_header(f"Ubuntu OpenPGP Public Keyring ({len(pgp_keys)} keys found)")
        for k in pgp_keys[:5]:
            write_safe(f"  {CLR_GREEN}[+]{CLR_RESET} Key ID: 0x{k.get('key_id')} ({k.get('bits')} bits) -> {k.get('view_url')}\n")

    gravatar = data.get("gravatar", {})
    if gravatar.get("registered"):
        print_header("Gravatar Public Identity Database")
        write_safe(f"  {CLR_GREEN}[+]{CLR_RESET} Registered Profile Avatar: {gravatar.get('avatar_url')}\n")

    breaches = data.get("breaches", [])
    if breaches:
        print_header(f"Data Breach Exposures ({len(breaches)} incidents detected)")
        write_safe(f"  {CLR_RED}[!] Target email found in {len(breaches)} public data breaches:{CLR_RESET}\n")
        chunk = ", ".join(breaches[:15])
        write_safe(f"  {chunk}\n")
        if len(breaches) > 15:
            write_safe(f"  ... and {len(breaches) - 15} more breaches.\n")
    else:
        print_header("Data Breach Exposure")
        write_safe(f"  {CLR_GREEN}[+] No known public database breaches recorded for this email.{CLR_RESET}\n")

    stealer = data.get("infostealer", {})
    if stealer.get("compromised"):
        print_header("Infostealer Malware Intelligence (Hudson Rock)")
        write_safe(f"  {CLR_RED}[!] COMPROMISED: Associated computer was infected by info-stealer malware.{CLR_RESET}\n")
        if stealer.get("date_compromised"):
            write_safe(f"  Date Compromised    : {stealer.get('date_compromised')}\n")
        if stealer.get("os"):
            write_safe(f"  Victim Operating Sys: {stealer.get('os')}\n")
        if stealer.get("total_services"):
            write_safe(f"  Total Accounts Lost : {stealer.get('total_services')} credentials\n")
        if stealer.get("malware_path"):
            write_safe(f"  Malware Execution   : {stealer.get('malware_path')}\n")

    leaks = data.get("leak_footprint", [])
    if leaks:
        print_header("Public Leaks & Pastebin Footprint")
        write_safe(f"  {CLR_GREEN}[+] Found {len(leaks)} public leak / paste records:{CLR_RESET}\n")
        for idx, lk in enumerate(leaks, 1):
            write_safe(f"    [{idx}] {lk.get('title')}\n")
            write_safe(f"        URL    : {lk.get('url')}\n")
            write_safe(f"        Details: {lk.get('snippet')}\n")

    pivots = data.get("osint_pivots", {})
    if pivots:
        print_header("Breach & Leak Directory Pivots")
        for pk, pv in pivots.items():
            label = pk.replace("_", " ").title()
            write_safe(f"  {label:<18}: {pv}\n")

def format_subdomains_report(data: Dict[str, Any]) -> None:
    print_header(f"Subdomain Discovery: {data['domain']}")
    write_safe(f"Scanned: {data['total_probed']} targets | Discovered: {data['total_found']} active subdomains\n\n")
    for sub in data["subdomains"]:
        src = f"[{sub.get('source', 'DNS')}]"
        write_safe(f"  {CLR_GREEN}[LIVE]{CLR_RESET} {sub['fqdn']:<35} -> {str(sub.get('ip')):<16} {src}\n")

def run_auto_scan(target: str, timeout: float, quiet: bool = False) -> Dict[str, Any]:
    clean = target.strip()
    if is_ipv4(clean):
        if not quiet:
            print_badge("info", f"Target detected as IPv4 Address: {clean}")
        return {"mode": "ip", "result": scan_ip(clean, timeout=timeout)}
    elif is_email(clean):
        if not quiet:
            print_badge("info", f"Target detected as Email Address: {clean}")
        return {"mode": "email", "result": scan_email(clean, timeout=timeout)}
    elif is_phone_number(clean):
        if not quiet:
            print_badge("info", f"Target detected as Phone Number: {clean}")
        return {"mode": "phone", "result": scan_phone(clean)}
    elif is_domain(clean):
        if not quiet:
            print_badge("info", f"Target detected as Domain: {clean}")
        domain_res = scan_domain(clean, timeout=timeout)
        subdomain_res = scan_subdomains(clean)
        return {"mode": "domain", "result": domain_res, "subdomains": subdomain_res}
    else:
        if not quiet:
            print_badge("info", f"Target detected as Username/Handle: {clean}")
        return {"mode": "user", "result": scan_username(clean, timeout=timeout)}

def format_phone_report(data: Dict[str, Any]) -> None:
    print_header(f"Phone Intelligence: {data.get('query')}")
    if not data.get("valid"):
        print_badge("fail", data.get("message", "Invalid telephone number format."))
        return

    write_safe(f"  International : {data.get('e164')}\n")
    write_safe(f"  National      : {data.get('national_format')}\n")
    write_safe(f"  Country       : {data.get('country')} ({data.get('country_code')})\n")
    write_safe(f"  Calling Code  : {data.get('calling_code')}\n")
    write_safe(f"  Region        : {data.get('region')}\n")
    write_safe(f"  Timezone      : {data.get('timezone')}\n")
    write_safe(f"  Carrier       : {data.get('carrier')}\n")
    write_safe(f"  Line Type     : {data.get('line_type')}\n")

    live = data.get("live_hlr")
    if live:
        print_header("Live HLR Telecom Query")
        write_safe(f"  Status        : {'Active / Valid' if live.get('valid') else 'Inactive'}\n")
        write_safe(f"  Network       : {live.get('carrier')}\n")
        write_safe(f"  Location      : {live.get('location')}\n")

    footprints = data.get("database_footprint", [])
    print_header("Public Database & Leak Footprint")
    if footprints:
        write_safe(f"  {CLR_GREEN}[+] Found {len(footprints)} public database / caller records:{CLR_RESET}\n")
        for idx, fp in enumerate(footprints, 1):
            if isinstance(fp, dict):
                write_safe(f"    [{idx}] {fp.get('title')}\n")
                write_safe(f"        URL    : {fp.get('url')}\n")
                write_safe(f"        Details: {fp.get('snippet')}\n")
            else:
                write_safe(f"    [{idx}] {fp}\n")
    else:
        write_safe(f"  {CLR_YELLOW}[-] No public indexed mentions / leak records found on the open web.{CLR_RESET}\n")

    pivots = data.get("osint_pivots", {})
    if pivots:
        print_header("OSINT Pivots & Identity Databases")
        for pk, pv in pivots.items():
            label = pk.replace("_", " ").title()
            write_safe(f"  {label:<18}: {pv}\n")

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ysint",
        description="Ysint: Modular OSINT Reconnaissance Toolkit"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    scan_parser = subparsers.add_parser("scan", help="Auto-detect target type and run reconnaissance")
    scan_parser.add_argument("target", help="Target string (IP, Domain, Email, or Username)")

    user_parser = subparsers.add_parser("user", help="Search username across multiple platforms")
    user_parser.add_argument("username", help="Username to search")

    ip_parser = subparsers.add_parser("ip", help="Investigate IP address geolocation and ASN")
    ip_parser.add_argument("address", help="IPv4 address to inspect")

    domain_parser = subparsers.add_parser("domain", help="Comprehensive domain reconnaissance")
    domain_parser.add_argument("name", help="Domain name to scan")

    email_parser = subparsers.add_parser("email", help="Verify email syntax, MX records, and disposable status")
    email_parser.add_argument("address", help="Email address to verify")

    sub_parser = subparsers.add_parser("subdomains", help="Enumerate active subdomains")
    sub_parser.add_argument("domain", help="Base domain to enumerate")

    phone_parser = subparsers.add_parser("phone", help="Investigate phone number carrier, country, and OSINT pivots")
    phone_parser.add_argument("number", help="Phone number to inspect")

    for p in [scan_parser, user_parser, ip_parser, domain_parser, email_parser, sub_parser, phone_parser]:
        p.add_argument("--json", action="store_true", help="Output raw JSON data")
        p.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0)")
        p.add_argument("-o", "--output", help="Save result to a file")

    args = parser.parse_args()

    if not args.command:
        write_safe(BANNER)
        parser.print_help()
        sys.exit(1)

    is_json_mode = getattr(args, "json", False)
    if not is_json_mode:
        write_safe(BANNER)

    result_data = None
    output_text = ""

    if args.command == "scan":
        data = run_auto_scan(args.target, args.timeout, quiet=is_json_mode)
        result_data = data
        if not is_json_mode:
            mode = data["mode"]
            if mode == "ip":
                format_ip_report(data["result"])
            elif mode == "email":
                format_email_report(data["result"])
            elif mode == "phone":
                format_phone_report(data["result"])
            elif mode == "domain":
                format_domain_report(data["result"])
                format_subdomains_report(data["subdomains"])
            elif mode == "user":
                format_user_report(data["result"])

    elif args.command == "user":
        if not is_json_mode:
            print_badge("info", f"Hunting username '{args.username}'...")
        res = scan_username(args.username, timeout=args.timeout)
        result_data = res
        if not is_json_mode:
            format_user_report(res)

    elif args.command == "ip":
        if not is_json_mode:
            print_badge("info", f"Inspecting IP address '{args.address}'...")
        res = scan_ip(args.address, timeout=args.timeout)
        result_data = res
        if not is_json_mode:
            format_ip_report(res)

    elif args.command == "domain":
        if not is_json_mode:
            print_badge("info", f"Analyzing domain '{args.name}'...")
        res = scan_domain(args.name, timeout=args.timeout)
        result_data = res
        if not is_json_mode:
            format_domain_report(res)

    elif args.command == "email":
        if not is_json_mode:
            print_badge("info", f"Inspecting email '{args.address}'...")
        res = scan_email(args.address, timeout=args.timeout)
        result_data = res
        if not is_json_mode:
            format_email_report(res)

    elif args.command == "subdomains":
        if not is_json_mode:
            print_badge("info", f"Discovering subdomains for '{args.domain}'...")
        res = scan_subdomains(args.domain)
        result_data = res
        if not is_json_mode:
            format_subdomains_report(res)

    elif args.command == "phone":
        if not is_json_mode:
            print_badge("info", f"Inspecting phone number '{args.number}'...")
        res = scan_phone(args.number)
        result_data = res
        if not is_json_mode:
            format_phone_report(res)

    if is_json_mode and result_data:
        json_output = json.dumps(result_data, indent=2)
        write_safe(json_output + "\n")
        output_text = json_output
    elif result_data:
        output_text = json.dumps(result_data, indent=2)

    if args.output and output_text:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text)
            print_badge("ok", f"Results successfully saved to {args.output}")
        except Exception as exc:
            print_badge("fail", f"Failed to save output: {exc}")

if __name__ == "__main__":
    main()
