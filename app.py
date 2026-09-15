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
    SCAN_DELAY=6                          seconds between lookups
    MAX_URLS=60                           batch ceiling
    VT_PROFILE_DIR=~/.vt_scanner_profile  keeps the clearance cookie
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import vt_scraper

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
DEFAULT_DELAY = float(os.environ.get("SCAN_DELAY", "6"))
MAX_URLS = int(os.environ.get("MAX_URLS", "60"))

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

        if path == "/api/config":
            self._send_json({"delay": DEFAULT_DELAY, "max_urls": MAX_URLS})
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

        if not urls:
            self._send_json({"error": "No usable URLs found in that text."}, 400)
            return
        if len(urls) > MAX_URLS:
            self._send_json(
                {"error": f"That's {len(urls)} URLs. Limit is {MAX_URLS} per batch."},
                400,
            )
            return

        self._stream_scan(urls, delay)

    def _stream_scan(self, urls, delay):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        if not self._chunk(json.dumps({"event": "start", "total": len(urls)}) + "\n"):
            return

        scraper = vt_scraper.get_scraper()

        for i, url in enumerate(urls):
            if not self._chunk(
                json.dumps({"event": "progress", "index": i, "url": url}) + "\n"
            ):
                return  # client closed the tab; stop scanning

            try:
                result = scraper.lookup(url)
            except Exception as exc:
                result = {"url": url, "stats": None, "vendors": {},
                          "source": None, "error": str(exc)}

            result["event"] = "result"
            result["index"] = i
            if not self._chunk(json.dumps(result) + "\n"):
                return

            if i < len(urls) - 1:
                time.sleep(delay)

        self._chunk(json.dumps({"event": "done"}) + "\n")
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    # Threaded so asset requests are not blocked by an in-flight scan.
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True

    print("Chrome runs headless — no window will open.")
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
