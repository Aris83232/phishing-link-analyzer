# keeping the constants here

import os

VT_API_KEY = os.environ.get("VT_API_KEY", "")

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_REPORT_URL = "https://www.virustotal.com/api/v3/urls/{id}"

# Virus total takes time scan, so we wait
VT_POLL_DELAY = 3

# list of suspicious tld
SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".club",
    ".online",
    ".site",
    ".website",
    ".info",
    ".biz",
    ".pw",
    ".cc",
    ".ws",
    ".ru",
    ".cn",
    ".zip",
    ".mov",
    ".work",
    ".link",
    ".click",
    ".review",
    ".loan",
    ".download",
    ".stream",
]

# COMMON url shortners
URL_SHORTNERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "is.gd",
    "cutt.ly",
    "short.io",
    "shorte.st",
    "adf.ly",
    "bc.vc",
    "mcaf.ee",
    "tiny.cc",
    "lnkd.in",
    "dlvr.it",
    "budurl.com",
    "snip.ly",
]

# List of known Domain Names
TRUSTED_DOMAINS = [
    "google",
    "facebook",
    "apple",
    "microsoft",
    "amazon",
    "paypal",
    "netflix",
    "instagram",
    "twitter",
    "linkedin",
    "dropbox",
    "whatsapp",
    "telegram",
    "yahoo",
    "outlook",
    "office365",
    "onedrive",
    "icloud",
    "ebay",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "hsbc",
    "dhl",
    "fedex",
    "ups",
    "usps",
    "steam",
    "discord",
]

# Score Weights
SCORE_IP_ADDRESS = 30
SCORE_SUSPICIOUS_TLD = 20
SCORE_TYPOSQUATTING = 30
SCORE_URL_SHORTENER = 15
SCORE_LONG_URL = 10
SCORE_MANY_SUBDOMAINS = 10
SCORE_SPECIAL_CHARS = 5
SCORE_HYPHEN_DOMAIN = 10

MAX_URL_LENGTH = 75  # anything over this is suspicious imo
MAX_SUBDOMAINS = 3

# verdicts
SCORE_SAFE_MAX = 20
SCORE_SUSPICIOUS_MAX = 50

# if 3+ VT engines flag it as malicious, that's good enough
VT_MALICIOUS_THRESHOLD = 3
VT_SUSPICIOUS_THRESHOLD = 1

RESULTS_FILE = "last_scan.txt"

APP_TITLE = "Phishing URL Detector"
APP_WIDTH = 750
APP_HEIGHT = 620
