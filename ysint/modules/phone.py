import json
import os
import re
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List
from ysint.utils import make_request, query_public_search

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier as p_carrier, timezone as p_timezone
    HAS_LIBPHONENUMBER = True
except ImportError:
    HAS_LIBPHONENUMBER = False

COUNTRY_CODES = {
    "1": {"country": "United States / Canada", "code": "US/CA", "region": "North America", "tz": "UTC-4 to UTC-10"},
    "7": {"country": "Russia / Kazakhstan", "code": "RU/KZ", "region": "Eurasia", "tz": "UTC+2 to UTC+12"},
    "20": {"country": "Egypt", "code": "EG", "region": "Africa", "tz": "UTC+2"},
    "27": {"country": "South Africa", "code": "ZA", "region": "Africa", "tz": "UTC+2"},
    "30": {"country": "Greece", "code": "GR", "region": "Europe", "tz": "UTC+2"},
    "31": {"country": "Netherlands", "code": "NL", "region": "Europe", "tz": "UTC+1"},
    "32": {"country": "Belgium", "code": "BE", "region": "Europe", "tz": "UTC+1"},
    "33": {"country": "France", "code": "FR", "region": "Europe", "tz": "UTC+1"},
    "34": {"country": "Spain", "code": "ES", "region": "Europe", "tz": "UTC+1"},
    "39": {"country": "Italy", "code": "IT", "region": "Europe", "tz": "UTC+1"},
    "40": {"country": "Romania", "code": "RO", "region": "Europe", "tz": "UTC+2"},
    "41": {"country": "Switzerland", "code": "CH", "region": "Europe", "tz": "UTC+1"},
    "43": {"country": "Austria", "code": "AT", "region": "Europe", "tz": "UTC+1"},
    "44": {"country": "United Kingdom", "code": "GB", "region": "Europe", "tz": "UTC+0"},
    "45": {"country": "Denmark", "code": "DK", "region": "Europe", "tz": "UTC+1"},
    "46": {"country": "Sweden", "code": "SE", "region": "Europe", "tz": "UTC+1"},
    "47": {"country": "Norway", "code": "NO", "region": "Europe", "tz": "UTC+1"},
    "48": {"country": "Poland", "code": "PL", "region": "Europe", "tz": "UTC+1"},
    "49": {"country": "Germany", "code": "DE", "region": "Europe", "tz": "UTC+1"},
    "52": {"country": "Mexico", "code": "MX", "region": "North America", "tz": "UTC-6"},
    "55": {"country": "Brazil", "code": "BR", "region": "South America", "tz": "UTC-3"},
    "60": {"country": "Malaysia", "code": "MY", "region": "Southeast Asia", "tz": "UTC+8"},
    "61": {"country": "Australia", "code": "AU", "region": "Oceania", "tz": "UTC+8 to UTC+11"},
    "62": {"country": "Indonesia", "code": "ID", "region": "Southeast Asia", "tz": "UTC+7 to UTC+9"},
    "63": {"country": "Philippines", "code": "PH", "region": "Southeast Asia", "tz": "UTC+8"},
    "64": {"country": "New Zealand", "code": "NZ", "region": "Oceania", "tz": "UTC+12"},
    "65": {"country": "Singapore", "code": "SG", "region": "Southeast Asia", "tz": "UTC+8"},
    "66": {"country": "Thailand", "code": "TH", "region": "Southeast Asia", "tz": "UTC+7"},
    "81": {"country": "Japan", "code": "JP", "region": "East Asia", "tz": "UTC+9"},
    "82": {"country": "South Korea", "code": "KR", "region": "East Asia", "tz": "UTC+9"},
    "84": {"country": "Vietnam", "code": "VN", "region": "Southeast Asia", "tz": "UTC+7"},
    "86": {"country": "China", "code": "CN", "region": "East Asia", "tz": "UTC+8"},
    "90": {"country": "Turkey", "code": "TR", "region": "Middle East / Europe", "tz": "UTC+3"},
    "91": {"country": "India", "code": "IN", "region": "South Asia", "tz": "UTC+5:30"},
    "92": {"country": "Pakistan", "code": "PK", "region": "South Asia", "tz": "UTC+5"},
    "94": {"country": "Sri Lanka", "code": "LK", "region": "South Asia", "tz": "UTC+5:30"},
    "98": {"country": "Iran", "code": "IR", "region": "Middle East", "tz": "UTC+3:30"},
    "212": {"country": "Morocco", "code": "MA", "region": "North Africa", "tz": "UTC+1"},
    "234": {"country": "Nigeria", "code": "NG", "region": "West Africa", "tz": "UTC+1"},
    "351": {"country": "Portugal", "code": "PT", "region": "Europe", "tz": "UTC+0"},
    "353": {"country": "Ireland", "code": "IE", "region": "Europe", "tz": "UTC+0"},
    "380": {"country": "Ukraine", "code": "UA", "region": "Europe", "tz": "UTC+2"},
    "852": {"country": "Hong Kong", "code": "HK", "region": "East Asia", "tz": "UTC+8"},
    "886": {"country": "Taiwan", "code": "TW", "region": "East Asia", "tz": "UTC+8"},
    "966": {"country": "Saudi Arabia", "code": "SA", "region": "Middle East", "tz": "UTC+3"},
    "971": {"country": "United Arab Emirates", "code": "AE", "region": "Middle East", "tz": "UTC+4"}
}

ID_CARRIERS = [
    (r"^(811|812|813|821|822|823|851|852|853)", "Telkomsel (Halo / simPATI / AS / By.U)", "Mobile"),
    (r"^(814|815|816|855|856|857|858)", "Indosat Ooredoo Hutchison (IM3)", "Mobile"),
    (r"^(817|818|819|859|877|878)", "XL Axiata", "Mobile"),
    (r"^(831|832|833|838)", "Axis (XL Axiata)", "Mobile"),
    (r"^(895|896|897|898|899)", "Tri / 3 (Indosat Ooredoo)", "Mobile"),
    (r"^(881|882|883|884|885|886|887|888|889)", "Smartfren", "Mobile"),
    (r"^(21)", "Telkom Indonesia (Jakarta / Bodetabek)", "Fixed Line"),
    (r"^(22)", "Telkom Indonesia (Bandung / Cimahi)", "Fixed Line"),
    (r"^(24)", "Telkom Indonesia (Semarang)", "Fixed Line"),
    (r"^(274)", "Telkom Indonesia (Yogyakarta)", "Fixed Line"),
    (r"^(31)", "Telkom Indonesia (Surabaya / Sidoarjo)", "Fixed Line"),
    (r"^(361)", "Telkom Indonesia (Denpasar / Bali)", "Fixed Line"),
    (r"^(61)", "Telkom Indonesia (Medan)", "Fixed Line"),
    (r"^(411)", "Telkom Indonesia (Makassar)", "Fixed Line")
]

US_AREA_CODES = {
    "800": ("Toll-Free Service", "Toll-Free"),
    "888": ("Toll-Free Service", "Toll-Free"),
    "877": ("Toll-Free Service", "Toll-Free"),
    "866": ("Toll-Free Service", "Toll-Free"),
    "855": ("Toll-Free Service", "Toll-Free"),
    "844": ("Toll-Free Service", "Toll-Free"),
    "833": ("Toll-Free Service", "Toll-Free"),
    "212": ("New York, NY", "Fixed/Mobile"),
    "646": ("New York, NY", "Fixed/Mobile"),
    "310": ("Los Angeles, CA", "Fixed/Mobile"),
    "424": ("Los Angeles, CA", "Fixed/Mobile"),
    "415": ("San Francisco, CA", "Fixed/Mobile"),
    "628": ("San Francisco, CA", "Fixed/Mobile"),
    "202": ("Washington, DC", "Fixed/Mobile"),
    "312": ("Chicago, IL", "Fixed/Mobile"),
    "713": ("Houston, TX", "Fixed/Mobile"),
    "214": ("Dallas, TX", "Fixed/Mobile"),
    "206": ("Seattle, WA", "Fixed/Mobile"),
    "305": ("Miami, FL", "Fixed/Mobile"),
    "617": ("Boston, MA", "Fixed/Mobile"),
    "416": ("Toronto, ON (Canada)", "Fixed/Mobile"),
    "604": ("Vancouver, BC (Canada)", "Fixed/Mobile")
}

def search_public_footprint(e164: str, national: str, timeout: float = 6.0) -> List[Dict[str, str]]:
    general_query = f'"{e164}" OR "{national}"'
    results = query_public_search(general_query, timeout=timeout)
    if len(results) < 3:
        spam_query = f'"{e164}" OR "{national}" site:kredibel.co.id OR site:tellows.com OR site:shouldianswer.com OR site:whocallsme.com'
        spam_results = query_public_search(spam_query, timeout=timeout)
        for sr in spam_results:
            if not any(r["url"] == sr["url"] for r in results):
                results.append(sr)
    return results

def check_live_hlr_api(e164: str, api_key: Optional[str] = None, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    key = api_key or os.environ.get("NUMVERIFY_API_KEY")
    if not key:
        return None

    clean_digits = re.sub(r"\D", "", e164)
    url = f"http://apilayer.net/api/validate?access_key={key}&number={clean_digits}"
    status, _, body = make_request(url, timeout=timeout)
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            if data.get("valid") is not None:
                return {
                    "source": "Numverify Live HLR",
                    "valid": data.get("valid"),
                    "carrier": data.get("carrier") or "N/A",
                    "line_type": data.get("line_type") or "N/A",
                    "location": data.get("location") or "N/A"
                }
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return None

def parse_phone_number(raw_input: str) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, str]]]:
    clean = raw_input.strip()
    digits = re.sub(r"\D", "", clean)

    if clean.startswith("08") or clean.startswith("02") or clean.startswith("03") or clean.startswith("06") or clean.startswith("04"):
        country_code = "62"
        national_num = digits.lstrip("0")
        return country_code, national_num, COUNTRY_CODES.get("62")

    if clean.startswith("+"):
        for length in [3, 2, 1]:
            cand = digits[:length]
            if cand in COUNTRY_CODES:
                return cand, digits[length:], COUNTRY_CODES[cand]

    if digits.startswith("00"):
        stripped = digits[2:]
        for length in [3, 2, 1]:
            cand = stripped[:length]
            if cand in COUNTRY_CODES:
                return cand, stripped[length:], COUNTRY_CODES[cand]

    for length in [3, 2, 1]:
        cand = digits[:length]
        if cand in COUNTRY_CODES and len(digits[length:]) >= 6:
            return cand, digits[length:], COUNTRY_CODES[cand]

    if len(digits) >= 10 and digits.startswith("8"):
        return "62", digits, COUNTRY_CODES.get("62")

    return None, digits, None

def scan_phone(phone_input: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    clean_raw = phone_input.strip()
    digits = re.sub(r"\D", "", clean_raw)

    if len(digits) < 7 or len(digits) > 15:
        return {
            "query": clean_raw,
            "valid": False,
            "message": "Invalid telephone digit length (must be 7-15 digits per ITU-T E.164)"
        }

    country_code, national_num, country_meta = parse_phone_number(clean_raw)

    if not country_code or not country_meta:
        return {
            "query": clean_raw,
            "valid": False,
            "message": "Unknown international country calling code"
        }

    e164 = f"+{country_code}{national_num}"
    e164_clean = f"{country_code}{national_num}"
    nat_formatted = f"0{national_num}" if country_code == "62" else national_num

    carrier_name = "Regional Telecom Carrier"
    line_type = "Mobile/Fixed"
    is_valid = True
    is_possible = True
    country_name = country_meta["country"]
    iso_code = country_meta["code"]
    tz_info = country_meta["tz"]
    region_name = country_meta["region"]

    if HAS_LIBPHONENUMBER:
        try:
            parsed_obj = phonenumbers.parse(e164, None)
            is_valid = phonenumbers.is_valid_number(parsed_obj)
            is_possible = phonenumbers.is_possible_number(parsed_obj)
            geo_desc = geocoder.description_for_number(parsed_obj, "en")
            if geo_desc:
                country_name = geo_desc
            c_desc = p_carrier.name_for_number(parsed_obj, "en")
            if c_desc:
                carrier_name = f"{c_desc} (Google libphonenumber)"
            tz_list = p_timezone.time_zones_for_number(parsed_obj)
            if tz_list:
                tz_info = ", ".join(tz_list)
            ntype = phonenumbers.number_type(parsed_obj)
            if ntype == 1:
                line_type = "Mobile"
            elif ntype == 0:
                line_type = "Fixed Line"
            elif ntype == 3:
                line_type = "Toll-Free"
            elif ntype == 2:
                line_type = "Fixed Line or Mobile"
        except Exception:
            pass

    if carrier_name == "Regional Telecom Carrier":
        if country_code == "62":
            for pattern, c_name, l_type in ID_CARRIERS:
                if re.match(pattern, national_num):
                    carrier_name = c_name
                    line_type = l_type
                    break
        elif country_code == "1":
            prefix3 = national_num[:3]
            if prefix3 in US_AREA_CODES:
                loc, ltype = US_AREA_CODES[prefix3]
                carrier_name = f"North American Operator ({loc})"
                line_type = ltype

    live_hlr = check_live_hlr_api(e164, api_key=api_key)
    if live_hlr and live_hlr.get("carrier") != "N/A":
        carrier_name = f"{live_hlr['carrier']} (Live HLR)"
        line_type = live_hlr.get("line_type", line_type)

    footprint_mentions = search_public_footprint(e164, nat_formatted)

    whatsapp_link = f"https://wa.me/{e164_clean}"
    telegram_link = f"https://t.me/+{e164_clean}"
    truecaller_link = f"https://www.truecaller.com/search/{country_code}/{national_num}"
    getcontact_link = f"https://www.getcontact.com/en/search?number={e164_clean}"
    syncme_link = f"https://sync.me/search/?number={e164_clean}"
    kredibel_link = f"https://www.kredibel.co.id/search/phone/{nat_formatted if country_code == '62' else e164_clean}"
    tellows_link = f"https://www.tellows.com/num/{e164_clean}"
    shouldianswer_link = f"https://www.shouldianswer.com/phone-number/{e164_clean}"
    whocallsme_link = f"https://whocallsme.com/Phone-Number.aspx/{e164_clean}"
    archive_link = f"https://web.archive.org/web/*/{e164}"
    google_dork = f'"{e164}" OR "{nat_formatted}"'
    leaks_dork = f'"{e164}" (site:pastebin.com OR site:trello.com OR site:github.com OR site:t.me)'
    doc_dork = f'"{e164}" (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:csv OR filetype:sql)'

    return {
        "query": clean_raw,
        "valid": is_valid,
        "possible": is_possible,
        "e164": e164,
        "national_format": nat_formatted,
        "rfc3966": f"tel:{e164}",
        "country": country_name,
        "country_code": iso_code,
        "calling_code": f"+{country_code}",
        "region": region_name,
        "timezone": tz_info,
        "carrier": carrier_name,
        "line_type": line_type,
        "live_hlr": live_hlr,
        "database_footprint": footprint_mentions,
        "osint_pivots": {
            "whatsapp": whatsapp_link,
            "telegram": telegram_link,
            "truecaller": truecaller_link,
            "getcontact": getcontact_link,
            "syncme": syncme_link,
            "kredibel": kredibel_link,
            "tellows": tellows_link,
            "shouldianswer": shouldianswer_link,
            "whocallsme": whocallsme_link,
            "archive_org": archive_link,
            "google_dork": google_dork,
            "leaks_dork": leaks_dork,
            "documents_dork": doc_dork
        }
    }
