"""
Global phishing detection rules — apply worldwide.
Each rule is a dict with: id, name, weight, severity, region, desc, pattern (regex str).
"""

GLOBAL_RULES = [
    {
        "id": "url_shortener",
        "name": "Shortened URLs",
        "weight": 25,
        "severity": "high",
        "region": "global",
        "category": "URL",
        "desc": "bit.ly, tinyurl, ow.ly, etc.",
        "pattern": r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.gy|rb\.gy|cutt\.ly|is\.gd|tiny\.cc)",
    },
    {
        "id": "urgency",
        "name": "Urgency / pressure language",
        "weight": 18,
        "severity": "high",
        "region": "global",
        "category": "Social engineering",
        "desc": "act now, expires, suspended, limited time",
        "pattern": (
            r"(?:urgent|immediately|act now|expire[sd]?|limited time"
            r"|24 hours?|48 hours?|respond now|verify now|click now"
            r"|last chance|account (?:will be |is )?suspended|locked out)"
        ),
    },
    {
        "id": "prize_generic",
        "name": "Generic prize / reward lure",
        "weight": 18,
        "severity": "high",
        "region": "global",
        "category": "Prize scam",
        "desc": "lottery, lucky winner, claim now",
        "pattern": (
            r"(?:you.ve? (?:won|been selected)|lottery|lucky winner"
            r"|claim (?:your|now)|free (?:iphone|ipad|gift|cash))"
        ),
    },
    {
        "id": "credential_request",
        "name": "Credential harvesting",
        "weight": 28,
        "severity": "high",
        "region": "global",
        "category": "Credential theft",
        "desc": "verify account, OTP, enter password",
        "pattern": (
            r"(?:verify (?:your )?account|confirm (?:your )?(?:details|identity|info)"
            r"|enter (?:your )?(?:password|pin|otp|code)"
            r"|update (?:your )?(?:payment|billing|card)"
            r"|provide (?:your )?details)"
        ),
    },
    {
        "id": "suspicious_url",
        "name": "Suspicious domain patterns",
        "weight": 28,
        "severity": "high",
        "region": "global",
        "category": "URL",
        "desc": "IP-based URLs, lookalike secure/login domains",
        "pattern": (
            r"(?:https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|https?://[^\s]*[-](?:secure|login|verify|update|account|bank)[^\s]*)"
        ),
    },
    {
        "id": "grammar",
        "name": "Poor grammar / spelling",
        "weight": 10,
        "severity": "med",
        "region": "global",
        "category": "Spelling",
        "desc": "Common misspellings seen in phishing SMS",
        "pattern": (
            r"(?:recieve|acount|pasword|informaton|verfiy|suspened|clcik|immidiately|plz )"
        ),
    },
    {
        "id": "personal_info_request",
        "name": "Personal info request",
        "weight": 22,
        "severity": "high",
        "region": "global",
        "category": "Credential theft",
        "desc": "SSN, card number, date of birth",
        "pattern": (
            r"(?:social security|ssn|date of birth|dob"
            r"|card number|cvv|account number|sort code|mother.s maiden)"
        ),
    },
]
