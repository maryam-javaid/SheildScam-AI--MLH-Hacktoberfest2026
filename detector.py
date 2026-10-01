"""
detector.py - Rule-based security engine for ScamShield AI.

This module looks for OBSERVABLE social-engineering indicators in a message
using transparent, deterministic rules (regular expressions).

IMPORTANT: the score produced here is a "Risk Signal Score". It is the sum of
the indicators found. It is NOT a calibrated probability that a message is a
scam, and it must never be presented as one.
"""

import re
from typing import Dict, List, Optional

# --------------------------------------------------------------------------
# Risk levels
# --------------------------------------------------------------------------
RISK_HIGH = "HIGH RISK"
RISK_SUSPICIOUS = "SUSPICIOUS"
RISK_CAUTION = "CAUTION"
RISK_NONE = "NO OBVIOUS WARNING SIGNALS"

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Maximum number of points URL findings may add to the final score.
URL_BONUS_CAP = 35


# --------------------------------------------------------------------------
# Rules. Each rule has regex patterns that run on lowercase, cleaned text.
# --------------------------------------------------------------------------
RULES = [
    {
        "id": "urgency",
        "type": "Artificial Urgency",
        "severity": "High",
        "weight": 20,
        "patterns": [
            r"\burgent(?:ly)?\b",
            r"\bimmediate(?:ly)?\b",
            r"\bact now\b",
            r"\bright now\b",
            r"\bwithin (?:the next )?\d+\s*(?:hours?|hrs?|minutes?|mins?)\b",
            r"\blimited time\b",
            r"\b(?:expires?|expiring|expired) (?:today|tonight|soon)\b",
            r"\blast chance\b",
            r"\bfinal (?:notice|warning|reminder)\b",
            r"\bas soon as possible\b",
            r"\basap\b",
            r"\bwithout delay\b",
        ],
        "explanation": (
            "The message pushes you to act very quickly. Scammers create time "
            "pressure so you panic and do not stop to think or check."
        ),
    },
    {
        "id": "fear",
        "type": "Fear / Threat",
        "severity": "High",
        "weight": 20,
        "patterns": [
            r"\b(?:account|access|card|service|number|sim|wallet)s?\b[^.!?]{0,25}"
            r"\b(?:will be|has been|have been|is being|been)\s+"
            r"(?:suspended|blocked|disabled|closed|terminated|locked|deactivated|"
            r"restricted|frozen|limited|banned)\b",
            r"\bpermanent(?:ly)?\s+(?:\w+\s+)?(?:suspension|suspended|ban|banned|"
            r"block|blocked|closure|closed|deactivation)\b",
            r"\blegal action\b",
            r"\barrest(?:ed)?\b",
            r"\bwarrant\b",
            r"\bcourt (?:case|notice|order)\b",
            r"\bfail(?:ure|ing)? to (?:comply|verify|respond|update|pay)\b",
            r"\bunauthori[sz]ed (?:login|access|transaction|activity|attempt)\b",
            r"\bsuspicious (?:login|activity|transaction)\b",
            r"\bwill be (?:reported|prosecuted|penali[sz]ed|fined)\b",
        ],
        "explanation": (
            "The message threatens a bad outcome (blocked account, legal "
            "trouble, penalties). Fear is a common way to make people skip "
            "careful thinking."
        ),
    },
    {
        "id": "reward",
        "type": "Suspicious Reward / Greed Tactic",
        "severity": "Medium",
        "weight": 15,
        "patterns": [
            r"\byou(?:'ve| have)? (?:won|been selected|are selected)\b",
            r"\blotter(?:y|ies)\b",
            r"\bcash prize\b",
            r"\bfree money\b",
            r"\bclaim (?:your |the )?(?:reward|prize|gift|bonus|winnings?)\b",
            r"\bwinner\b",
            r"\bcongratulations\b",
            r"\bjackpot\b",
            r"\bprize\b",
        ],
        "explanation": (
            "The message promises a prize or free reward. Unexpected rewards "
            "are a classic bait: you are asked to pay or share details to "
            "'claim' something that does not exist."
        ),
    },
    {
        "id": "payment",
        "type": "Payment Request",
        "severity": "High",
        "weight": 20,
        "patterns": [
            r"\b(?:registration|processing|clearance|release|handling|redelivery|"
            r"delivery|customs|advance|security|activation|admin(?:istration)?) "
            r"(?:fee|charge|deposit|payment)s?\b",
            r"\bsend (?:us )?(?:money|payment|funds|cash)\b",
            r"\btransfer (?:the |your )?(?:payment|money|funds|amount)\b",
            r"\bpay (?:immediately|now|today|urgently|"
            r"a (?:small |one-time )?(?:\w+ )?(?:fee|charge|deposit))\b",
            r"\b(?:western union|moneygram|bitcoin|crypto(?:currency)?|usdt|gift cards?)\b",
        ],
        "explanation": (
            "The message asks for money or a fee. Real prizes, jobs and "
            "deliveries rarely require you to pay a stranger first."
        ),
    },
    {
        "id": "cta",
        "type": "Suspicious Call to Action",
        "severity": "Medium",
        "weight": 10,
        "patterns": [
            r"\bclick (?:on )?(?:the |this |below |here|the link|this link)\b",
            r"\btap (?:on )?(?:the |this )?link\b",
            r"\bfollow (?:the|this) link\b",
            r"\b(?:visit|open) (?:the |this )?(?:link|below)\b",
            r"\bverify your (?:identity|account|details|information|kyc)\b",
            r"\bconfirm your (?:identity|account|details|information)\b",
            r"\bupdate your (?:account|details|information|address|kyc)\b",
            r"\bkyc\b",
        ],
        "explanation": (
            "The message tells you to click a link or 'verify/update' "
            "something. This is how many phishing attacks move you to a fake "
            "website."
        ),
    },
    {
        "id": "secrecy",
        "type": "Secrecy / Isolation Pressure",
        "severity": "High",
        "weight": 15,
        "patterns": [
            r"\b(?:do not|don't|dont) (?:tell|inform) (?:anyone|anybody|your family|others)\b",
            r"\bkeep (?:this|it) (?:a )?(?:secret|confidential|private)\b",
            r"\bconfidential offer\b",
            r"\bdo not (?:contact|call) (?:the |your )?bank\b",
        ],
        "explanation": (
            "The message asks you to keep it secret. Scammers do this so "
            "family, friends or your bank cannot warn you."
        ),
    },
    {
        "id": "toogood",
        "type": "Too-Good-To-Be-True Offer",
        "severity": "Medium",
        "weight": 15,
        "patterns": [
            r"\bwork from home\b",
            r"\bearn (?:up to )?(?:rs\.?|pkr|usd|\$)?\s?[\d,]+\s*(?:/|per |a |each )?\s?"
            r"(?:day|daily|hour|hourly|week|weekly)\b",
            r"\bno experience (?:needed|required|necessary)\b",
            r"\bguaranteed (?:income|job|salary|returns?|profit|earnings?)\b",
            r"\beasy (?:money|income|earning)\b",
            r"\bdouble your (?:money|investment)\b",
            r"\bdaily (?:income|payout|earnings?)\b",
        ],
        "explanation": (
            "The offer promises easy money or guaranteed results. Fake job "
            "and investment scams use unrealistic promises to attract victims."
        ),
    },
    {
        "id": "delivery",
        "type": "Delivery / Parcel Pretext",
        "severity": "Medium",
        "weight": 10,
        "patterns": [
            r"\b(?:parcel|package|shipment|delivery|order|courier)\b[^.!?]{0,60}"
            r"\b(?:on hold|held|failed|could not be delivered|couldn't be delivered|"
            r"undeliverable|returned|pending|incomplete|unable to deliver)\b",
            r"\b(?:update|confirm|complete) (?:your )?(?:delivery )?address\b",
            r"\bre-?delivery\b",
        ],
        "explanation": (
            "The message claims a package problem. Fake delivery notices are "
            "very common and usually lead to a fake payment or login page."
        ),
    },
    {
        # Only reported if other pressure signals are present (see "requires").
        "id": "authority",
        "type": "Possible Authority / Brand Impersonation",
        "severity": "Medium",
        "weight": 10,
        "requires": ["urgency", "fear", "credential", "payment"],
        "patterns": [
            r"\b(?:bank|state bank|sbp|fia|nadra|fbr|customs|police|ptcl|pta|"
            r"easypaisa|jazzcash|hbl|ubl|meezan|alfalah|paypal|amazon|apple|"
            r"microsoft|netflix|dhl|fedex|tcs|leopards|ups|whatsapp|facebook|google)\b",
            r"\b(?:security|fraud|compliance|customer (?:care|support)|support|"
            r"verification) (?:team|department|desk|officer|alert)\b",
            r"\bdear (?:customer|user|account holder|valued customer|member)\b",
        ],
        "explanation": (
            "The message names or implies a trusted organization while also "
            "applying pressure. Scammers often pretend to be banks, couriers "
            "or government offices."
        ),
    },
]

# --- Sensitive information (handled separately, see _credential_finding) ---
CREDENTIAL_PATTERNS = [
    r"\botp\b",
    r"\bone[- ]time (?:password|pin|code|passcode)\b",
    r"\bpassword\b",
    r"\bpasscode\b",
    r"\bpin(?: code| number)?\b",
    r"\b(?:verification|security|confirmation|authentication) code\b",
    r"\bcnic\b",
    r"\b(?:credit|debit|atm) card\b",
    r"\bcard (?:number|details|information)\b",
    r"\bcvv\b",
    r"\b(?:bank|account) (?:details|information|number|credentials)\b",
    r"\blogin (?:details|credentials|info)\b",
    r"\bseed phrase\b",
    r"\bsocial security\b",
]

REQUEST_VERBS = re.compile(
    r"\b(?:enter|send|share|provide|reply|submit|confirm|give|tell|type|verify|"
    r"update|upload|forward|supply|disclose|reveal|input)\b"
)

# Legitimate warnings such as "Never share your OTP with anyone" are removed
# before checking, so we do not treat them as a request for the OTP.
NEGATED_SHARE = re.compile(
    r"\b(?:never|do not|don't|dont|should not|shouldn't|must not)\s+(?:\w+\s+){0,2}?"
    r"(?:share|disclose|give|tell|send|reveal|provide|forward)\b[^.!?\n]*"
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _normalize(message: str) -> str:
    """Lowercase, remove invisible characters, normalise quotes and spaces."""
    text = message or ""
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()


def _collect(patterns: List[str], text: str) -> List[str]:
    """Return the unique text snippets matched by any of the patterns."""
    hits: List[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            snippet = match.group(0).strip()
            if snippet and snippet not in hits:
                hits.append(snippet)
    return hits


def _make_finding(rule: Dict, hits: List[str]) -> Dict:
    return {
        "type": rule["type"],
        "severity": rule["severity"],
        "explanation": rule["explanation"],
        "evidence": hits[:3],
    }


def _credential_finding(text: str) -> Optional[Dict]:
    """Detect requests for OTPs, passwords, CNIC, card details, etc."""
    stripped = NEGATED_SHARE.sub(" ", text)
    hits = _collect(CREDENTIAL_PATTERNS, stripped)

    if hits and REQUEST_VERBS.search(stripped):
        return {
            "critical": True,
            "weight": 30,
            "finding": {
                "type": "Critical Credential Request",
                "severity": "Critical",
                "explanation": (
                    "The message asks for sensitive information such as an "
                    "OTP, password, PIN, CNIC or card details. Legitimate "
                    "banks and services do not ask for these in a message."
                ),
                "evidence": hits[:3],
            },
        }

    mentions = _collect(CREDENTIAL_PATTERNS, text)
    if mentions:
        return {
            "critical": False,
            "weight": 5,
            "finding": {
                "type": "Sensitive Information Mentioned",
                "severity": "Low",
                "explanation": (
                    "The message mentions sensitive information (like OTPs or "
                    "passwords) without clearly asking for it. This can be a "
                    "normal security warning, but stay careful."
                ),
                "evidence": mentions[:3],
            },
        }
    return None


def risk_from_score(score: int) -> str:
    """Convert a Risk Signal Score into a human-readable risk level."""
    if score >= 70:
        return RISK_HIGH
    if score >= 40:
        return RISK_SUSPICIOUS
    if score >= 15:
        return RISK_CAUTION
    return RISK_NONE


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def analyze_message(message: str) -> Dict:
    """
    Analyze the message text with deterministic rules.

    Returns:
        {
            "score": int,        # Risk Signal Score (0-100), NOT a probability
            "text_score": int,   # same as score until URL signals are applied
            "url_points": int,   # points added by URL findings (0 for now)
            "risk": str,         # HIGH RISK / SUSPICIOUS / CAUTION / NO OBVIOUS...
            "findings": [{"type", "severity", "explanation", "evidence"}],
        }
    """
    text = _normalize(message)
    if not text:
        return {
            "score": 0,
            "text_score": 0,
            "url_points": 0,
            "risk": RISK_NONE,
            "findings": [],
        }

    findings: List[Dict] = []
    fired = set()
    score = 0

    # 1) Sensitive information / credential request
    credential = _credential_finding(text)
    if credential:
        findings.append(credential["finding"])
        score += credential["weight"]
        if credential["critical"]:
            fired.add("credential")

    # 2) Standard rules (rules with "requires" are handled in the next pass)
    for rule in RULES:
        if rule.get("requires"):
            continue
        hits = _collect(rule["patterns"], text)
        if hits:
            findings.append(_make_finding(rule, hits))
            score += rule["weight"]
            fired.add(rule["id"])

    # 3) Context-dependent rules
    for rule in RULES:
        required = rule.get("requires")
        if not required or not (fired & set(required)):
            continue
        hits = _collect(rule["patterns"], text)
        if hits:
            findings.append(_make_finding(rule, hits))
            score += rule["weight"]
            fired.add(rule["id"])

    # 4) Dangerous combination: pressure + request for secrets
    if "credential" in fired and ("urgency" in fired or "fear" in fired):
        findings.append(
            {
                "type": "Pressure + Secret Request Combination",
                "severity": "Critical",
                "explanation": (
                    "Time pressure or threats combined with a request for "
                    "secret codes is the classic pattern of phishing attacks."
                ),
                "evidence": [],
            }
        )
        score += 10

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    score = min(100, score)

    return {
        "score": score,
        "text_score": score,
        "url_points": 0,
        "risk": risk_from_score(score),
        "findings": findings,
    }


def apply_url_signals(result: Dict, url_results: List[Dict]) -> Dict:
    """
    Add URL warning signals to the message result and recompute the risk level.
    Returns a new dict; the input is not modified.
    """
    updated = dict(result)
    highest = max([u.get("score", 0) for u in url_results], default=0)
    bonus = min(URL_BONUS_CAP, highest)
    total = min(100, result.get("text_score", result.get("score", 0)) + bonus)
    updated["url_points"] = bonus
    updated["score"] = total
    updated["risk"] = risk_from_score(total)
    return updated
