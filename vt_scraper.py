"""
vt_scraper.py
-------------
Headless Selenium engine for pulling VirusTotal URL verdicts.
Python 3.12 / Selenium 4.44

Chrome runs under --headless=new. No window is ever created.

Why not scrape the DOM: VirusTotal's GUI is a Polymer app buried in nested
shadow roots whose markup changes often. Instead we let the page make its own
internal call to /ui/urls/<id> and capture that JSON response off the CDP
network log. That payload holds last_analysis_stats and last_analysis_results
for every engine, which is exactly what we need. A shadow-DOM walker is kept
as a fallback for when the capture misses.
"""

import base64
import json
import os
import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys

VT_HOME = "https://www.virustotal.com/gui/home/url"
VT_DETECTION = "https://www.virustotal.com/gui/url/{url_id}/detection"

# Persisting the profile keeps the Cloudflare clearance cookie between runs,
# so only the first lookup of a session pays the challenge cost.
PROFILE_DIR = os.environ.get(
    "VT_PROFILE_DIR", os.path.join(os.path.expanduser("~"), ".vt_scanner_profile")
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Injected before any page script runs. Headless Chrome leaks a handful of
# obvious tells; these are the ones VT's checks actually look at.
STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
window.chrome = window.chrome || {runtime: {}};
const origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (p) =>
    p.name === 'notifications'
        ? Promise.resolve({state: Notification.permission})
        : origQuery(p);
"""

# Walks nested shadow roots looking for a selector. Used by the fallback path.
DEEP_QUERY_JS = """
function deepQuery(sel, root) {
    root = root || document;
    const hit = root.querySelector(sel);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) {
            const f = deepQuery(sel, el.shadowRoot);
            if (f) return f;
        }
    }
    return null;
}
return deepQuery(arguments[0]);
"""


def vt_url_id(url: str) -> str:
    """VirusTotal identifies a URL as base64url(url) with padding stripped."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


class VirusTotalScraper:
    """
    One long-lived headless browser, reused across scans. Selenium 4.44 resolves
    chromedriver itself through Selenium Manager, so nothing needs to be on PATH.
    """

    def __init__(self, page_timeout: int = 45) -> None:
        self.page_timeout = page_timeout
        self.driver: webdriver.Chrome | None = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------- lifecycle --

    def _options(self) -> Options:
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument(f"--user-agent={UA}")
        opts.add_argument("--window-size=1440,1000")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--lang=en-US")
        opts.add_argument(f"--user-data-dir={PROFILE_DIR}")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        # Performance logging is what gives us Network.responseReceived events.
        opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        return opts

    def start(self) -> None:
        if self.driver:
            return
        self.driver = webdriver.Chrome(options=self._options())
        self.driver.set_page_load_timeout(self.page_timeout)
        self.driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument", {"source": STEALTH_JS}
        )

    def close(self) -> None:
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    # ------------------------------------------------------ net capturing --

    def _perf_log(self):
        try:
            return self.driver.get_log("performance")
        except Exception:
            return []

    def _body(self, request_id: str, attempts: int = 3):
        for _ in range(attempts):
            try:
                res = self.driver.execute_cdp_cmd(
                    "Network.getResponseBody", {"requestId": request_id}
                )
                return res.get("body")
            except Exception:
                time.sleep(0.4)
        return None

    def _capture(self, wait_seconds: int = 25):
        """Watch for the /ui/urls/<id> response and return its attributes block."""
        deadline = time.time() + wait_seconds
        seen: set[str] = set()

        while time.time() < deadline:
            for entry in self._perf_log():
                try:
                    msg = json.loads(entry["message"])["message"]
                except (KeyError, ValueError):
                    continue
                if msg.get("method") != "Network.responseReceived":
                    continue

                params = msg.get("params", {})
                resp_url = params.get("response", {}).get("url", "")
                rid = params.get("requestId")
                if not rid or rid in seen:
                    continue

                # The object endpoint itself, not /comments, /votes, /relationships.
                if "/ui/urls/" not in resp_url:
                    continue
                tail = resp_url.split("/ui/urls/", 1)[1]
                if "/" in tail.rstrip("/"):
                    continue
                seen.add(rid)

                raw = self._body(rid)
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except ValueError:
                    continue

                attrs = payload.get("data", {}).get("attributes")
                if attrs and "last_analysis_results" in attrs:
                    return attrs

            time.sleep(0.5)
        return None

    # ------------------------------------------------------ DOM fallback ---

    def _scrape_dom(self):
        js = """
        function deepAll(sel, root, acc) {
            root = root || document; acc = acc || [];
            root.querySelectorAll(sel).forEach(e => acc.push(e));
            root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) deepAll(sel, el.shadowRoot, acc);
            });
            return acc;
        }
        return deepAll('.engine-container, vt-ui-detections-list-item')
            .map(r => (r.innerText || '').trim()).filter(Boolean);
        """
        try:
            rows = self.driver.execute_script(js)
        except Exception:
            return None
        if not rows:
            return None

        results: dict[str, dict[str, str]] = {}
        stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

        for raw in rows:
            parts = [p.strip() for p in raw.split("\n") if p.strip()]
            if len(parts) < 2:
                continue
            vendor, verdict = parts[0], parts[1]
            low = verdict.lower()
            if "suspicious" in low:
                cat = "suspicious"
            elif any(k in low for k in ("malware", "malicious", "phishing", "spam")):
                cat = "malicious"
            elif "clean" in low or "harmless" in low:
                cat = "harmless"
            else:
                cat = "undetected"
            stats[cat] += 1
            results[vendor] = {"category": cat, "result": verdict}

        return {"last_analysis_stats": stats, "last_analysis_results": results}

    # ------------------------------------------------------------ lookup ---

    def _submit_new(self, url: str) -> bool:
        """URL VT has never seen. Push it through the search box to queue a scan."""
        try:
            self.driver.get(VT_HOME)
            time.sleep(2)
            box = None
            for sel in (
                "input#urlInput",
                "input#searchInput",
                "input[type='search']",
                "input[type='text']",
            ):
                box = self.driver.execute_script(DEEP_QUERY_JS, sel)
                if box:
                    break
            if not box:
                return False
            box.clear()
            box.send_keys(url)
            box.send_keys(Keys.RETURN)
            time.sleep(3)
            return True
        except Exception:
            return False

    def lookup(self, url: str, submit_if_missing: bool = True) -> dict:
        """
        Returns {url, stats, vendors, source, error}
        where vendors maps engine name -> {category, result, method}
        """
        out = {
            "url": url,
            "stats": None,
            "vendors": {},
            "source": "indexed",
            "error": None,
        }

        with self._lock:
            try:
                self.start()
                self.driver.get(VT_DETECTION.format(url_id=vt_url_id(url)))
            except Exception as exc:
                out["error"] = f"Could not load VirusTotal: {exc}"
                return out

            attrs = self._capture(wait_seconds=20)

            if attrs is None and submit_if_missing:
                out["source"] = "submitted"
                if self._submit_new(url):
                    attrs = self._capture(wait_seconds=60)

            if attrs is None:
                attrs = self._scrape_dom()
                if attrs:
                    out["source"] = "dom"

        if attrs is None:
            out["error"] = (
                "No analysis returned. VirusTotal has not indexed this URL, or "
                "the headless session was challenged."
            )
            return out

        out["stats"] = attrs.get("last_analysis_stats", {})
        for vendor, info in (attrs.get("last_analysis_results") or {}).items():
            out["vendors"][vendor] = {
                "category": info.get("category", "undetected"),
                "result": info.get("result") or "—",
                "method": info.get("method", "—"),
            }
        return out


# Module-level singleton, shared across requests by the server.
_scraper: VirusTotalScraper | None = None


def get_scraper() -> VirusTotalScraper:
    global _scraper
    if _scraper is None:
        _scraper = VirusTotalScraper()
    return _scraper


def shutdown() -> None:
    global _scraper
    if _scraper:
        _scraper.close()
        _scraper = None
