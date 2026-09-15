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

IS_WINDOWS = os.name == "nt"

# Set CHROME_BINARY to use a specific Chrome. Worth doing on a managed
# workstation: without it Selenium Manager downloads its own Chrome for
# Testing build into %USERPROFILE%\.cache, and an unsigned binary there is
# exactly what application allowlisting and EDR block. Your installed Chrome
# is already approved; point at that instead.
CHROME_BINARY = os.environ.get("CHROME_BINARY", "")

# Checked in order when CHROME_BINARY is unset.
CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files\Chromium\Application\chrome.exe",
] if IS_WINDOWS else [
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_chrome():
    """Path to an installed Chrome, or "" to let Selenium Manager decide."""
    if CHROME_BINARY:
        return CHROME_BINARY
    for path in CHROME_CANDIDATES:
        if path and os.path.isfile(path):
            return path
    return ""

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

    def __init__(self, page_timeout: int = 45, profile_suffix: str = "") -> None:
        self.page_timeout = page_timeout
        # Each browser needs its own profile directory. Chrome refuses to
        # share one --user-data-dir between concurrent instances.
        self.profile_dir = PROFILE_DIR + profile_suffix
        self.driver: webdriver.Chrome | None = None
        self.profile_in_use = True
        self._lock = threading.Lock()

    # ---------------------------------------------------------- lifecycle --

    def _options(self, use_profile: bool = True) -> Options:
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument(f"--user-agent={UA}")
        opts.add_argument("--window-size=1440,1000")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--lang=en-US")

        # Port 0 tells Chrome to pick a free port and write it to
        # DevToolsActivePort. Without it, a port collision makes Chrome exit
        # before ChromeDriver can attach, which surfaces as the confusing
        # "DevToolsActivePort file doesn't exist" crash.
        opts.add_argument("--remote-debugging-port=0")

        # Linux-only. --no-sandbox in particular is for running as root in a
        # container; on Windows it weakens the browser for no benefit and can
        # trip endpoint protection.
        if not IS_WINDOWS:
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")

        if use_profile:
            opts.add_argument(f"--user-data-dir={self.profile_dir}")

        binary = find_chrome()
        if binary:
            opts.binary_location = binary

        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        # Performance logging is what gives us Network.responseReceived events.
        opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        return opts

    def start(self) -> None:
        if self.driver:
            return

        # A locked or corrupted profile directory is the most common cause of
        # a startup crash, so if the first attempt fails, retry once without
        # it. That costs the cached Cloudflare clearance but gets a working
        # browser, and it distinguishes a profile problem from everything else.
        try:
            self.driver = webdriver.Chrome(options=self._options(use_profile=True))
            self.profile_in_use = True
        except Exception as first_error:
            try:
                self.driver = webdriver.Chrome(options=self._options(use_profile=False))
                self.profile_in_use = False
                print(
                    "Chrome would not start with the saved profile, so this "
                    "session is running without it.\n"
                    f"  Delete {self.profile_dir} to clear the problem permanently.\n"
                    "  Check for a leftover chrome.exe holding the lock first."
                )
            except Exception as second_error:
                raise RuntimeError(self._startup_help(first_error, second_error)) from None

        self.driver.set_page_load_timeout(self.page_timeout)
        self.driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument", {"source": STEALTH_JS}
        )

    def _startup_help(self, first_error, second_error) -> str:
        """Turn a ChromeDriver stack trace into something actionable."""
        binary = find_chrome() or "(auto-downloaded by Selenium Manager)"
        blurb = str(second_error).split("Stacktrace:")[0].strip()

        lines = [
            "Chrome would not start, with or without the saved profile.",
            f"  Chrome binary: {binary}",
            f"  Driver said:   {blurb}",
            "",
            "Most likely causes, in order:",
            "  1. Endpoint protection blocked the browser. If the path above is",
            "     under .cache\\selenium, Selenium Manager downloaded its own",
            "     Chrome for Testing build and your EDR or AppLocker policy",
            "     stopped it. Set CHROME_BINARY to your installed Chrome.",
            "  2. A leftover chrome.exe or chromedriver.exe is still running.",
            "     Kill both, then try again.",
            "  3. The profile directory is unwritable or on a redirected",
            f"     network home. Set VT_PROFILE_DIR to a local path.",
        ]
        return "\n".join(lines)

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


class ScraperPool:
    """
    Several headless browsers working a shared list of URLs.

    Concurrency helps because most of a lookup is waiting on a page load, not
    waiting on a rate limit. What it cannot do is raise VirusTotal's per-IP
    ceiling: every worker here shares one source address, so the pool also
    shares one pace gate. min_interval is the floor on the gap between request
    *starts* across the whole pool, whatever the worker count.

    Roughly: serial runs at (lookup + delay) per URL. The pool runs at
    min_interval per URL until the workers themselves become the bottleneck,
    i.e. until min_interval drops below lookup_time / workers.
    """

    def __init__(self, size: int = 1, min_interval: float = 2.0) -> None:
        self.size = max(1, size)
        self.min_interval = max(0.0, min_interval)
        self._scrapers = [
            VirusTotalScraper(profile_suffix=f"-{i}" if i else "")
            for i in range(self.size)
        ]
        self._gate = threading.Lock()
        self._last_start = 0.0

    def _wait_turn(self) -> None:
        """Block until the pool is allowed to start another request."""
        with self._gate:
            gap = self._last_start + self.min_interval - time.monotonic()
            if gap > 0:
                time.sleep(gap)
            self._last_start = time.monotonic()

    def run(self, urls, on_started, on_result) -> None:
        """
        Look up every URL, calling on_started(index, url) as each begins and
        on_result(index, result) as each finishes. Both callbacks run on
        worker threads, so whatever they touch must be thread-safe.

        Results arrive in completion order, not list order. Each carries its
        index so the caller can put them back in place.

        If on_result returns False the run stops early — that is how a closed
        browser tab cancels the remaining work.
        """
        state = {"next": 0, "stop": False, "lock": threading.Lock()}
        workers = min(self.size, len(urls))

        def work(scraper):
            while True:
                with state["lock"]:
                    if state["stop"] or state["next"] >= len(urls):
                        return
                    i = state["next"]
                    state["next"] += 1

                self._wait_turn()

                with state["lock"]:
                    if state["stop"]:
                        return

                on_started(i, urls[i])
                try:
                    result = scraper.lookup(urls[i])
                except Exception as exc:
                    result = {"url": urls[i], "stats": None, "vendors": {},
                              "source": None, "error": str(exc)}

                if on_result(i, result) is False:
                    with state["lock"]:
                        state["stop"] = True
                    return

        threads = [
            threading.Thread(target=work, args=(self._scrapers[n],), daemon=True)
            for n in range(workers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def close(self) -> None:
        for scraper in self._scrapers:
            scraper.close()


# Module-level singleton, shared across requests by the server. The browsers
# stay alive between batches so the Cloudflare clearance is not re-earned.
_pool: ScraperPool | None = None


def get_pool(size: int = 1, min_interval: float = 2.0) -> ScraperPool:
    """
    Return the shared pool, rebuilding it if the worker count changed.
    min_interval is cheap to adjust and never forces a rebuild.
    """
    global _pool
    if _pool is None or _pool.size != max(1, size):
        if _pool is not None:
            _pool.close()
        _pool = ScraperPool(size=size, min_interval=min_interval)
    else:
        _pool.min_interval = max(0.0, min_interval)
    return _pool


def shutdown() -> None:
    global _pool
    if _pool:
        _pool.close()
        _pool = None
