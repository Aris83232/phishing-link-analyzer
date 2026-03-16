# phishing-link-analyzer

A desktop tool that checks URLs for phishing indicators using local heuristics and the VirusTotal API. Built with Python + Tkinter.

---

## Files

```
phishing_detector/
├── main.py          # run this to start the app
├── gui.py           # tkinter window and button logic
├── detector.py      # all the local url checks
├── scoring.py       # turns check results into a score + verdict
├── virustotal.py    # VT API calls
├── utils.py         # helper stuff (url parsing, levenshtein, etc)
└── config.py        # constants and score weights

```

---

## Setup

Requires Python 3.10+

```bash
pip install requests
```

### VirusTotal API key (optional but recommended)

Get a free key at https://www.virustotal.com/gui/join-us - the free tier gives you 500 requests/day which is more than enough.

```bash
# linux / mac
export VT_API_KEY="your_key_here"

# windows cmd
set VT_API_KEY=your_key_here

# windows powershell
$env:VT_API_KEY = "your_key_here"
```

The app still works without it - it just skips the VT step and uses local checks only.

### Run

```bash
python main.py
```

---

## How it works

### Local checks

These run without any internet connection and check things like:

- Is the URL using a raw IP address instead of a domain?
- Does it use a free/throwaway TLD like `.tk` or `.xyz`?
- Does the domain look like a misspelling of a known brand? (uses Levenshtein distance to catch stuff like `paypa1.com`)
- Is it a shortened URL that hides the real destination?
- Does the domain have hyphens suggesting a fake brand name? (e.g. `paypal-secure.com`)
- Is the URL suspiciously long? Does it have weird characters?

Each check adds to a risk score. Score ≤20 = safe, ≤50 = suspicious, >50 = phishing.

### VirusTotal

If an API key is set, the app submits the URL to VT, waits a few seconds, then fetches the report. It extracts how many of VT's ~70+ engine partners flagged the URL as malicious or suspicious.

If 3+ engines flag it as malicious, that overrides everything and it's marked phishing.

### Final verdict

```
VT malicious >= 3  →  PHISHING
local score > 50   →  PHISHING
VT suspicious >= 1 or local score > 20  →  SUSPICIOUS
otherwise  →  SAFE
```

---

## Limitations

- Heuristics generate false positives sometimes. Some legit sites have long URLs or hyphens. A high score is a warning, not a guarantee.
- Brand new phishing domains won't be in VT's database yet - so VT isn't foolproof either.
- The free VT key has rate limits (4 req/min, 500/day). Hitting it will show an error in the app.
- URL shorteners are only checked against a hardcoded list - new ones get through.

## Things I'd add with more time

- Pull from PhishTank or OpenPhish for a live blocklist
- Add WHOIS lookup to check domain registration age (new = suspicious)
- Maybe train a simple ML model on labeled URL data instead of hand-tuned weights
- Scan history export to CSV

---

## Test URLs

```
# should flag as phishing or suspicious
http://192.168.1.1/login
http://g00gle-secure.tk/verify
https://bit.ly/3xBogus

# should be safe
https://google.com
https://github.com
```
