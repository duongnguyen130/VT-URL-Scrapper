# URL Reputation Bench

Paste a batch of URLs, get VirusTotal's engine verdicts back. Chrome runs
headless throughout — no window is ever created.

Built for Python 3.12 and Selenium 4.44.

## Files

| File | Language | Job |
|---|---|---|
| `vt_scraper.py` | Python | Headless Chrome, CDP network capture |
| `app.py` | Python | stdlib http.server, streams results as NDJSON |
| `static/index.html` | HTML | Page structure |
| `static/style.css` | CSS | Visual design |
| `static/app.js` | JavaScript | Stream consumption, rows, expansion |
| `requirements.txt` | — | Dependencies |

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Selenium is the only third-party package — the UI is served by `http.server`
from the standard library, so there is no web framework to install or patch.

Selenium 4.44 resolves chromedriver itself through Selenium Manager, so nothing
needs to be on PATH. A Chrome or Chromium install is the only prerequisite.

## How it works

VirusTotal's GUI is a Polymer app buried in nested shadow roots, and the markup
changes often enough that CSS selectors rot within weeks. So the scraper does
not read the page. It enables Chrome performance logging, lets the page make its
own internal call to `/ui/urls/<id>`, and pulls that JSON response out of the
CDP network buffer. The payload carries `last_analysis_stats` and
`last_analysis_results` for every engine.

A shadow-DOM walker sits behind that as a fallback if the capture misses.

The browser instance stays alive across scans and writes its profile to
`~/.vt_scanner_profile`. That persists the Cloudflare clearance cookie, so only
the first lookup of a session pays the challenge cost. Headless Chrome gets
challenged more often than a headed one; the stealth shims in `STEALTH_JS`
cover the tells VirusTotal's checks actually read, but if a batch starts coming
back with "session was challenged", delete the profile directory and let it
re-clear.

## Reading the results

Each row shows the URL, an **engine strip**, and a flagged/total count. The
strip draws one tick per scanning engine, coloured by that engine's verdict and
sorted so findings sit at the left edge. A row that is mostly grey with two red
ticks looks very different from one that is half red — you can triage a batch
without reading a single number.

Click a row to expand every engine's individual verdict.

Defanged indicators pasted straight out of a ticket work as-is: `hxxps://`,
`[.]`, `(.)` and `[:]` are rewritten before lookup. Cmd/Ctrl+Enter in the
textarea starts a scan.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SCAN_DELAY` | `6` | Seconds between lookups |
| `MAX_URLS` | `60` | Batch ceiling |
| `VT_PROFILE_DIR` | `~/.vt_scanner_profile` | Chrome profile location |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `5000` | Bind port |

Keep the delay reasonable. Hammering the web UI will get the source IP
challenged, and the clearance cookie will not save you from that.
