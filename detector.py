#this contains the heuristic checks, these can be performed offline

import re
from utils import extract_domain, extract_tld, levenshtein_distance
from config import SUSPICIOUS_TLDS, URL_SHORTENERS, TRUSTED_DOMAINS, MAX_URL_LENGTH, MAX_SUBDOMAINS

#Checking for ip addresses
def check_ip_address(url):
    domain = extract_domain(url)
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(ip_pattern.match(domain))

#Checking for suspicious tlds
def check_suspicious_tld(url):
    domain = extract_domain(url)
    tld = extract_tld(domain)
    return tld in SUSPICIOUS_TLDS


#Number of Subdomain checks
def check_subdomains(url):
    domain = extract_domain(url)
    parts = domain.split(".")
    subdomain_count = len(parts) - 2
    return subdomain_count > MAX_SUBDOMAINS

#Checking length of url
def check_url_length(url):
    return len(url) > MAX_URL_LENGTH


#Checking for special characters in the url
def check_special_characters(url):
    suspicious = [
        r"@",
        r"%[0-9a-fA-F]{2}",
        r"//.*//",
    ]
    for pattern in suspicious:
        if re.search(pattern, url):
            return True
    return False

#Checking for hyphen(-) in the url
def check_hyphenated_domain(url):
    domain = extract_domain(url)
    parts = domain.split(".")
    if len(parts) >= 2:
        main_domain = parts[-2]
        return "-" in main_domain
    return False

#Typosquatting check
def detect_typosquatting(url):
    domain = extract_domain(url)

    #this is to ingnore subdomains
    parts = domain.split(".")
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
    else:
        root = domain

    #To check for exact match if it is in list.
    for trusted in TRUSTED_DOMAINS:
        if root == trusted:
            continue  

        dist = levenshtein_distance(root, trusted)
        if 1 <= dist <= 2:
            return True, trusted

    return False, ""

# runs everything and returns one big dict
def run_all_checks(url):
    typosquat, matched_brand = detect_typosquatting(url)

    return {
        "ip_address":        check_ip_address(url),
        "suspicious_tld":    check_suspicious_tld(url),
        "many_subdomains":   check_subdomains(url),
        "long_url":          check_url_length(url),
        "special_chars":     check_special_characters(url),
        "hyphenated_domain": check_hyphenated_domain(url),
        "url_shortener":     check_shortener(url),
        "typosquatting":     typosquat,
        "typosquat_match":   matched_brand,
    }
