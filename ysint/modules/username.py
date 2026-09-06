from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable
from ysint.utils import make_request

PLATFORM_TARGETS = [
    {
        "name": "GitHub",
        "probe": "https://api.github.com/users/{u}",
        "profile": "https://github.com/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "DockerHub",
        "probe": "https://hub.docker.com/v2/users/{u}/",
        "profile": "https://hub.docker.com/u/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Dev.to",
        "probe": "https://dev.to/api/users/by_username?url={u}",
        "profile": "https://dev.to/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "HackerNews",
        "probe": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "profile": "https://news.ycombinator.com/user?id={u}",
        "validator": lambda s, h, b: s == 200 and b.strip() != b"null"
    },
    {
        "name": "Keybase",
        "probe": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",
        "profile": "https://keybase.io/{u}",
        "validator": lambda s, h, b: s == 200 and b'"them":[null]' not in b and b'"them":[]' not in b
    },
    {
        "name": "Chess.com",
        "probe": "https://api.chess.com/pub/player/{u}",
        "profile": "https://www.chess.com/member/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Codeforces",
        "probe": "https://codeforces.com/api/user.info?handles={u}",
        "profile": "https://codeforces.com/profile/{u}",
        "validator": lambda s, h, b: s == 200 and b'"status":"OK"' in b
    },
    {
        "name": "Scratch",
        "probe": "https://api.scratch.mit.edu/users/{u}",
        "profile": "https://scratch.mit.edu/users/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Gravatar",
        "probe": "https://en.gravatar.com/{u}.json",
        "profile": "https://en.gravatar.com/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "GitLab",
        "probe": "https://gitlab.com/{u}",
        "profile": "https://gitlab.com/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Pastebin",
        "probe": "https://pastebin.com/u/{u}",
        "profile": "https://pastebin.com/u/{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Medium",
        "probe": "https://medium.com/@{u}",
        "profile": "https://medium.com/@{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Telegram",
        "probe": "https://t.me/{u}",
        "profile": "https://t.me/{u}",
        "validator": lambda s, h, b: s == 200 and b"tgme_page_action_button_new" not in b and b"extra" in b
    },
    {
        "name": "Replit",
        "probe": "https://replit.com/@{u}",
        "profile": "https://replit.com/@{u}",
        "validator": lambda s, h, b: s == 200
    },
    {
        "name": "Duolingo",
        "probe": "https://www.duolingo.com/2017-06-30/users?username={u}",
        "profile": "https://www.duolingo.com/profile/{u}",
        "validator": lambda s, h, b: s == 200 and b'"users":[]' not in b
    }
]

def check_single_platform(target: Dict[str, Any], username: str, timeout: float) -> Dict[str, Any]:
    probe_url = target["probe"].format(u=username)
    profile_url = target["profile"].format(u=username)
    status, headers, body = make_request(probe_url, timeout=timeout)
    is_found = target["validator"](status, headers, body)
    return {
        "platform": target["name"],
        "found": is_found,
        "url": profile_url if is_found else None,
        "status_code": status
    }

def scan_username(username: str, timeout: float = 5.0, max_workers: int = 10) -> Dict[str, Any]:
    clean_username = username.strip().lstrip("@")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(check_single_platform, target, clean_username, timeout)
            for target in PLATFORM_TARGETS
        ]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: (not x["found"], x["platform"]))
    found_profiles = [r for r in results if r["found"]]
    return {
        "target": clean_username,
        "total_probed": len(results),
        "total_found": len(found_profiles),
        "profiles": results
    }
