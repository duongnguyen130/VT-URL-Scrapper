#!/usr/bin/env python3
"""
app.py
------
Front door for the scanner. Serves the UI and streams results back one URL at
a time as newline-delimited JSON, so rows appear as they finish rather than
after the whole batch.

Selenium is the only third-party package in this project, and it is imported
in vt_scraper.py, not here. Everything below is standard library: http.server
hosts the UI, json encodes the wire format, os handles paths, time paces the
lookups. No framework, nothing to pip install beyond Selenium itself.

Chrome runs headless throughout; no window is ever created.

Run:
    python app.py
    open http://127.0.0.1:5000

Environment:
    HOST=127.0.0.1                        bind address
    PORT=5000                             bind port
    HEADLESS=1                            0 shows the browser windows
    SCAN_DELAY=2                          min seconds between request starts
    WORKERS=3                             concurrent headless browsers
    MAX_URLS=500                          batch ceiling
    VT_PROFILE_DIR=~/.vt_scanner_profile  keeps the clearance cookie
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import vt_scraper

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
# Minimum gap between request starts across the whole pool, in seconds. This
# is the throughput knob: the batch runs at roughly this rate per URL.
DEFAULT_DELAY = float(os.environ.get("SCAN_DELAY", "2"))

# Concurrent headless browsers. Each costs roughly 300 MB and clears
# Cloudflare separately on first use, so more is not always faster.
WORKERS = int(os.environ.get("WORKERS", "3"))

MAX_URLS = int(os.environ.get("MAX_URLS", "500"))

# Read from vt_scraper so there is one definition of the flag.
HEADLESS = vt_scraper.HEADLESS

STATIC_DIR = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
)

# Three file types are served and no more, so a lookup table beats importing
# the mimetypes module for it.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


def normalise(raw_text):
    """Split pasted text into a clean, de-duplicated URL list, order kept."""
    seen = set()
    urls = []

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


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so the response can be chunked, which is what lets the browser
    # read rows as they arrive instead of waiting for the batch to finish.
    protocol_version = "HTTP/1.1"
    server_version = "URLBench"
    sys_version = ""

    # -------------------------------------------------------------- utils --

    def log_message(self, fmt, *args):
        # The default logs every asset request. Only report failures.
        status = str(args[1]) if len(args) > 1 else ""
        if not status.startswith("2"):
            super().log_message(fmt, *args)

    def _send_bytes(self, body, ctype, status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, obj, status=200):
        self._send_bytes(json.dumps(obj).encode("utf-8"), "application/json", status)

    def _chunk(self, text):
        """Write one chunked-encoding frame. False if the client has gone away."""
        data = text.encode("utf-8")
        try:
            self.wfile.write(b"%X\r\n" % len(data))
            self.wfile.write(data)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False

    # ---------------------------------------------------------------- GET --

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/favicon.ico":
            # No icon shipped; 204 keeps it out of the log.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/api/config":
            self._send_json({
                "delay": DEFAULT_DELAY,
                "max_urls": MAX_URLS,
                "workers": WORKERS,
                "headless": HEADLESS,
            })
            return

        self._serve_static("index.html" if path == "/" else path.lstrip("/"))

    def _serve_static(self, rel):
        # Resolve first, then confirm the result is still inside static/.
        # Catches ../ traversal, symlinks, and absolute paths alike.
        target = os.path.realpath(os.path.join(STATIC_DIR, rel))

        if not target.startswith(STATIC_DIR + os.sep) or not os.path.isfile(target):
            self._send_json({"error": "Not found"}, status=404)
            return

        ext = os.path.splitext(target)[1].lower()
        with open(target, "rb") as fh:
            body = fh.read()

        self._send_bytes(body, CONTENT_TYPES.get(ext, "application/octet-stream"))

    # --------------------------------------------------------------- POST --

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/api/scan":
            self._send_json({"error": "Not found"}, status=404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            self._send_json({"error": "Malformed request body."}, status=400)
            return

        urls = normalise(payload.get("text", ""))
        try:
            delay = float(payload.get("delay", DEFAULT_DELAY))
        except (ValueError, TypeError):
            delay = DEFAULT_DELAY
        try:
            workers = max(1, min(8, int(payload.get("workers", WORKERS))))
        except (ValueError, TypeError):
            workers = WORKERS

        if not urls:
            self._send_json({"error": "No usable URLs found in that text."}, 400)
            return
        if len(urls) > MAX_URLS:
            self._send_json(
                {"error": f"That's {len(urls)} URLs. Limit is {MAX_URLS} per batch."},
                400,
            )
            return

        self._stream_scan(urls, delay, workers)

    def _stream_scan(self, urls, delay, workers):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        # Workers emit concurrently, so every write goes through one lock.
        write_lock = threading.Lock()
        alive = [True]

        def emit(obj):
            with write_lock:
                if not alive[0]:
                    return False
                if not self._chunk(json.dumps(obj) + "\n"):
                    alive[0] = False
                    return False
                return True

        workers = min(workers, len(urls))
        if not emit({"event": "start", "total": len(urls), "workers": workers}):
            return

        pool = vt_scraper.get_pool(
            size=workers, min_interval=delay, headless=HEADLESS
        )

        pool.run(
            urls,
            on_started=lambda i, url: emit(
                {"event": "progress", "index": i, "url": url}
            ),
            on_result=lambda i, res: emit({**res, "event": "result", "index": i}),
        )

        if alive[0]:
            emit({"event": "done"})
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass


def main():
    # Threaded so asset requests are not blocked by an in-flight scan.
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True

    if HEADLESS:
        print(f"Chrome runs headless — no window will open. {WORKERS} worker(s).")
    else:
        print(f"Chrome runs visible — {WORKERS} window(s) will open.")
        if WORKERS > 1:
            print("  Set WORKERS=1 unless you actually want that many windows.")
    print(f"Listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
        vt_scraper.shutdown()


if __name__ == "__main__":
    main()
