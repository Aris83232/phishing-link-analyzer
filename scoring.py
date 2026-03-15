#results into a score and a final verdict

from config import (
    SCORE_IP_ADDRESS, SCORE_SUSPICIOUS_TLD, SCORE_TYPOSQUATTING,
    SCORE_URL_SHORTENER, SCORE_LONG_URL, SCORE_MANY_SUBDOMAINS,
    SCORE_SPECIAL_CHARS, SCORE_HYPHEN_DOMAIN,
    SCORE_SAFE_MAX, SCORE_SUSPICIOUS_MAX,
    VT_MALICIOUS_THRESHOLD, VT_SUSPICIOUS_THRESHOLD
)

# go through each check result & add up the score
def calculate_local_score(checks):
    score = 0
    indicators = []

    if checks.get("ip_address"):
        score += SCORE_IP_ADDRESS
        indicators.append("IP address used instead of a domain name")

    if checks.get("suspicious_tld"):
        score += SCORE_SUSPICIOUS_TLD
        indicators.append("Suspicious TLD detected (.tk, .ml, .xyz, etc.)")

    if checks.get("typosquatting"):
        score += SCORE_TYPOSQUATTING
        match = checks.get("typosquat_match", "a known brand")
        indicators.append(f"Typosquatting detected - looks like '{match}'")

    if checks.get("url_shortener"):
        score += SCORE_URL_SHORTENER
        indicators.append("URL shortener service detected")

    if checks.get("long_url"):
        score += SCORE_LONG_URL
        indicators.append("Unusually long URL")

    if checks.get("many_subdomains"):
        score += SCORE_MANY_SUBDOMAINS
        indicators.append("Too many subdomains")

    if checks.get("special_chars"):
        score += SCORE_SPECIAL_CHARS
        indicators.append("Suspicious special characters found (@, %, //, etc.)")

    if checks.get("hyphenated_domain"):
        score += SCORE_HYPHEN_DOMAIN
        indicators.append("Hyphen in domain name (possible brand impersonation)")

    return score, indicators


def get_local_verdict(score):
    if score <= SCORE_SAFE_MAX:
        return "SAFE"
    elif score <= SCORE_SUSPICIOUS_MAX:
        return "SUSPICIOUS"
    else:
        return "PHISHING"

# combine the local score with whatever VT says
def get_final_verdict(local_score, vt_results):
    local_verdict = get_local_verdict(local_score)

    if vt_results and vt_results.get("available"):
        malicious  = vt_results.get("malicious", 0)
        suspicious = vt_results.get("suspicious", 0)

        # if enough engines agree it's malicious, just go with phishing
        if malicious >= VT_MALICIOUS_THRESHOLD:
            return "PHISHING"

        if local_verdict == "PHISHING":
            return "PHISHING"

        if suspicious >= VT_SUSPICIOUS_THRESHOLD or local_verdict == "SUSPICIOUS":
            return "SUSPICIOUS"

        return "SAFE"

    #if no VT data, fall back to local score only
    # TODO: show a warning in the UI when this happens
    return local_verdict


def format_results(url, indicators, local_score, vt_results, final_verdict):
    lines = []
    lines.append("=" * 55)
    lines.append("           URL ANALYSIS REPORT")
    lines.append("=" * 55)
    lines.append(f"\nURL: {url}\n")

    lines.append("-" * 55)
    lines.append("LOCAL INDICATORS:")
    if indicators:
        for item in indicators:
            lines.append(f"  [!] {item}")
    else:
        lines.append("  [✓] No suspicious indicators found")

    lines.append(f"\nLocal Risk Score: {local_score} / 100+")

    lines.append("\n" + "-" * 55)
    lines.append("VIRUSTOTAL RESULTS:")
    if vt_results and vt_results.get("available"):
        lines.append(f"  Malicious   : {vt_results.get('malicious', 0)}")
        lines.append(f"  Suspicious  : {vt_results.get('suspicious', 0)}")
        lines.append(f"  Harmless    : {vt_results.get('harmless', 0)}")
        lines.append(f"  Undetected  : {vt_results.get('undetected', 0)}")
    elif vt_results and vt_results.get("error"):
        lines.append(f"  Error: {vt_results['error']}")
    else:
        lines.append("  Not available (no API key or network issue)")

    lines.append("\n" + "=" * 55)
    lines.append(f"  FINAL VERDICT: {final_verdict}")
    lines.append("=" * 55)

    return "\n".join(lines)