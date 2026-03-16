# putting the helper functions here

import re
import base64
from urllib.parse import urlparse


def is_valid_url(url):
    if not url or not url.strip():
        return False

    # checking http(s) for url parse
    lowered = url.strip().lower()
    if not lowered.startswith(("http://", "https://")):
        return False

    try:
        parsed = urlparse(url.strip())
        return bool(parsed.netloc)
    except Exception:
        return False


def extract_domain(url):
    try:
        parsed = urlparse(url)
        # strip port if there is one (e.g. example.com:8080)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""


def extract_tld(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""


def normalize_url(url):
    return url.strip().lower()


def url_to_base64_id(url):
    # VT v3 API needs the URL base64-encoded
    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return encoded


def save_result_to_file(content, filepath):
    try:
        with open(filepath, "w") as f:
            f.write(content)
    except Exception as e:
        # not critical if this fails, just print it
        print(f"Couldn't save result to file: {e}")


def levenshtein_distance(s1, s2):
    # standard edit distance - used for typosquatting detection
    # e.g. "paypa1.com" vs "paypal.com" = distance of 1
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)

    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]
