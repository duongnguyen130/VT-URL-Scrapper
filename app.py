#!/usr/bin/env python3
"""
app.py
------
Flask front door for the scanner. Serves the UI and streams results back one
URL at a time as newline-delimited JSON, so rows appear as they finish rather
than after the whole batch.

Run:
    python app.py
    open http://127.0.0.1:5000

Chrome runs headless throughout; no window is ever created.

Environment:
    SCAN_DELAY=6                          seconds between lookups
    MAX_URLS=60                           batch ceiling
    VT_PROFILE_DIR=~/.vt_scanner_profile  keeps the clearance cookie
"""

import atexit
import json
import os
import time

from flask import Flask, Response, request, send_from_directory

import vt_scraper

app = Flask(__name__, static_folder="static", static_url_path="")

DEFAULT_DELAY = float(os.environ.get("SCAN_DELAY", "6"))
MAX_URLS = int(os.environ.get("MAX_URLS", "60"))

atexit.register(vt_scraper.shutdown)


def normalise(raw_text):
    """Split pasted text into a clean, de-duplicated URL list, order kept."""
    seen, urls = set(), []
    for line in raw_text.splitlines():
        u = line.strip().strip(",;\"'")
        if not u or u.startswith("#"):
            continue
        # Tolerate defanged indicators pasted out of a ticket or email.
        u = (u.replace("hxxp://", "http://")
               .replace("hxxps://", "https://")
               .replace("[.]", ".")
               .replace("(.)", ".")
               .replace("[:]", ":"))
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/config")
def config():
    return {"delay": DEFAULT_DELAY, "max_urls": MAX_URLS}


@app.route("/api/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    urls = normalise(payload.get("text", ""))
    delay = float(payload.get("delay", DEFAULT_DELAY))

    if not urls:
        return {"error": "No usable URLs found in that text."}, 400
    if len(urls) > MAX_URLS:
        return {"error": f"That's {len(urls)} URLs. Limit is {MAX_URLS} per batch."}, 400

    def stream():
        yield json.dumps({"event": "start", "total": len(urls)}) + "\n"
        scraper = vt_scraper.get_scraper()

        for i, url in enumerate(urls):
            yield json.dumps({"event": "progress", "index": i, "url": url}) + "\n"
            try:
                result = scraper.lookup(url)
            except Exception as exc:
                result = {"url": url, "stats": None, "vendors": {},
                          "source": None, "error": str(exc)}
            result["event"] = "result"
            result["index"] = i
            yield json.dumps(result) + "\n"

            if i < len(urls) - 1:
                time.sleep(delay)

        yield json.dumps({"event": "done"}) + "\n"

    return Response(
        stream(),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    print("Chrome runs headless — no window will open.")
    print("Listening on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
