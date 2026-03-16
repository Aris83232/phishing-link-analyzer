#handles the VT API calls
# using v3 of their API - v2 still also works

import time
import requests
from utils import url_to_base64_id
from config import VT_API_KEY, VT_SCAN_URL, VT_REPORT_URL, VT_POLL_DELAY


def scan_url_virustotal(url):
    if not VT_API_KEY:
        return {
            "available": False,
            "error": "API key not set. Add VT_API_KEY to your environment variables."
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    #submiting the URL so VT queues it for scanning
    try:
        submit_resp = requests.post(
            VT_SCAN_URL,
            headers=headers,
            data=f"url={url}",
            timeout=10
        )
    except requests.exceptions.ConnectionError:
        return {"available": False, "error": "No network connection"}
    except requests.exceptions.Timeout:
        return {"available": False, "error": "Request timed out"}

    if submit_resp.status_code == 401:
        return {"available": False, "error": "Invalid API key"}

    if submit_resp.status_code == 429:
        return {"available": False, "error": "Rate limit hit - try again in a minute"}

    if submit_resp.status_code not in (200, 201):
        return {"available": False, "error": f"Submission failed (HTTP {submit_resp.status_code})"}

    #giving VT a moment to actually scan it
    time.sleep(VT_POLL_DELAY)

    #fetches the report using the base64-encoded URL as the ID
    url_id = url_to_base64_id(url)
    report_url = VT_REPORT_URL.format(id=url_id)

    try:
        report_resp = requests.get(
            report_url,
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
    except requests.exceptions.ConnectionError:
        return {"available": False, "error": "Lost connection while fetching report"}
    except requests.exceptions.Timeout:
        return {"available": False, "error": "Timed out fetching report"}

    if report_resp.status_code == 404:
        return {"available": False, "error": "URL not found in VT database"}

    if report_resp.status_code != 200:
        return {"available": False, "error": f"Report fetch failed (HTTP {report_resp.status_code})"}

    return _parse_vt_response(report_resp.json())


def _parse_vt_response(data):
    # dig into the nested JSON to get the stats we care about
    try:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        if not stats:
            return {"available": False, "error": "Couldn't parse VT response"}

        return {
            "available":  True,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except Exception:
        return {"available": False, "error": "Unexpected response format from VT"}