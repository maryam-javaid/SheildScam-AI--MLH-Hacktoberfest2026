"""
url_analyzer.py - URL intelligence for ScamShield AI.

Extracts URLs from a message and inspects their STRUCTURE only.
This module NEVER opens, visits or downloads anything from a URL.

All findings are warning indicators, not proof. For example, plain HTTP or an
IP-address host is suspicious in a message like "verify your bank account",
but neither one alone proves that a link is malicious.
"""

import ipaddress
import re
from typing import Dict, List
from urllib.parse import urlparse

MAX_URLS = 5

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy",
    "is.gd", "ow.ly", "buff.ly", "shorturl.at", "tiny.cc",
}

# needle -> label shown to the user
SUSPICIOUS_WORDS = {
    "verif": "verify",
    "login": "login",
    "signin": "signin",
    "account": "account",
    "secure": "secure",
    "bank": "bank",
    "password": "password",
    "wallet": "wallet",
    "update": "update",
    "confirm": "confirm",
}

# Endings that are used often in throwaway scam domains (but also by real sites).
RISKY_TLDS = {
    "xyz", "top", "click", "icu", "tk", "ml", "gq", "cf",
    "work", "loan", "rest", "buzz", "monster",
}

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`]+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|ow\.ly)/[^\s<>\"'`]+"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)


def extract_urls(message: str) -> List[str]:
    """Find URLs in the text (without visiting them). Returns unique URLs."""
    urls: List[str] = []
    for match in URL_PATTERN.finditer(message or ""):
        candidate = match.group(0).rstrip(".,;:!?)]}>\"'")
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls[:MAX_URLS]


def _finding(ftype: str, severity: str, explanation: str) -> Dict:
    return {"type": ftype, "severity": severity, "explanation": explanation}


def analyze_url(url: str) -> Dict:
    """Inspect one URL string and return its observable warning signals."""
    findings: List[Dict] = []
    score = 0

    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE))
    target = url if has_scheme else "http://" + url

    try:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {
            "url": url,
            "domain": "",
            "score": 10,
            "findings": [
                _finding(
                    "Unreadable URL",
                    "Low",
                    "This link is malformed and could not be analysed safely.",
                )
            ],
        }

    # 1) Unencrypted connection
    if has_scheme and parsed.scheme.lower() == "http":
        score += 10
        findings.append(
            _finding(
                "Unencrypted Connection",
                "Medium",
                "The link uses HTTP instead of HTTPS, so data sent to it is not "
                "encrypted. Many legitimate sites use HTTPS, so this is a warning "
                "sign, not proof of fraud.",
            )
        )

    # 2) IP address instead of a normal domain
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip = True
        score += 25
        extra = ""
        if ip_obj.is_private:
            extra = (
                " It is also a private/local network address, which a real "
                "organization would not normally send to the public."
            )
        findings.append(
            _finding(
                "IP Address URL",
                "High",
                "The link points to a numeric IP address instead of a normal "
                "website name. Real banks and shops almost always use their own "
                "domain name." + extra,
            )
        )
    except ValueError:
        pass

    # 3) URL shorteners
    if host in SHORTENERS:
        score += 15
        findings.append(
            _finding(
                "Shortened URL",
                "Medium",
                "The link is shortened, which hides the real destination. "
                "Shorteners are legitimate tools, but scammers use them to "
                "conceal where a link really goes.",
            )
        )

    # 4) Suspicious words in the host or path
    haystack = (host + (parsed.path or "") + "?" + (parsed.query or "")).lower()
    found_words = [label for needle, label in SUSPICIOUS_WORDS.items() if needle in haystack]
    if found_words:
        score += 20 if len(found_words) >= 2 else 10
        findings.append(
            _finding(
                "Suspicious URL Language",
                "Medium",
                "The link contains words often used to look official: "
                + ", ".join(found_words)
                + ". Attackers add such words to make fake pages look trustworthy.",
            )
        )

    # 5) Structure checks (only for normal domain names)
    if host and not is_ip:
        labels = host.split(".")
        if "xn--" in host:
            score += 15
            findings.append(
                _finding(
                    "Look-alike Characters (Punycode)",
                    "Medium",
                    "The domain uses an encoded international form that can be "
                    "used to imitate a familiar name with look-alike letters.",
                )
            )
        if host.count("-") >= 3:
            score += 10
            findings.append(
                _finding(
                    "Many Hyphens in Domain",
                    "Low",
                    "The domain contains several hyphens, a pattern often seen "
                    "in made-up domains that imitate brands.",
                )
            )
        if len(labels) >= 5:
            score += 10
            findings.append(
                _finding(
                    "Many Subdomains",
                    "Low",
                    "The domain has many parts. Attackers sometimes bury a "
                    "familiar name inside a long address to confuse readers.",
                )
            )
        if labels[-1] in RISKY_TLDS:
            score += 10
            findings.append(
                _finding(
                    "Frequently Abused Domain Ending",
                    "Low",
                    "The domain ends in ." + labels[-1] + ", an ending that is "
                    "cheap and commonly used in scam sites (but also by some "
                    "real ones).",
                )
            )

    # 6) '@' trick: http://trusted.com@evil.com
    if "@" in (parsed.netloc or ""):
        score += 20
        findings.append(
            _finding(
                "Embedded Credentials Trick",
                "High",
                "The link contains an '@' symbol before the real domain, a "
                "trick used to make a link look like it belongs to another site.",
            )
        )

    # 7) Very long URL
    if len(url) > 100:
        score += 5
        findings.append(
            _finding(
                "Very Long URL",
                "Low",
                "Unusually long links can hide the important part of the address.",
            )
        )

    return {
        "url": url,
        "domain": host or url,
        "score": min(100, score),
        "findings": findings,
    }


def analyze_urls(message: str) -> List[Dict]:
    """Extract and analyse every URL in the message. Returns [] if there are none."""
    return [analyze_url(u) for u in extract_urls(message)]
