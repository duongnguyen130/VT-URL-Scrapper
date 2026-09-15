#!/usr/bin/env python3
"""
check_chrome.py
---------------
Preflight check. Confirms Chrome can start headless and reach VirusTotal
before you commit a whole batch to it.

    python check_chrome.py
"""

import os
import sys

import vt_scraper


def main():
    print("Chrome discovery")
    binary = vt_scraper.find_chrome()
    if binary:
        print(f"  using: {binary}")
    else:
        print("  no installed Chrome found on the usual paths.")
        print("  Selenium Manager will download Chrome for Testing into your")
        print("  user cache. On a managed workstation that download is often")
        print("  what gets blocked. Set CHROME_BINARY to your real Chrome:")
        print(r'    set CHROME_BINARY=C:\Program Files\Google\Chrome\Application\chrome.exe')

    print(f"  profile: {vt_scraper.PROFILE_DIR}")
    if os.path.isdir(vt_scraper.PROFILE_DIR):
        print("           exists")
    else:
        print("           will be created on first run")

    print("\nStarting headless Chrome")
    scraper = vt_scraper.VirusTotalScraper()
    try:
        scraper.start()
    except Exception as exc:
        print(f"\n{exc}")
        return 1

    print("  started")
    if not scraper.profile_in_use:
        print("  (running without the saved profile)")

    try:
        print(f"  chrome:  {scraper.driver.capabilities.get('browserVersion', '?')}")
        chrome = scraper.driver.capabilities.get("chrome", {})
        print(f"  driver:  {chrome.get('chromedriverVersion', '?').split(' ')[0]}")

        print("\nReaching VirusTotal")
        scraper.driver.get("https://www.virustotal.com/gui/home/url")
        title = scraper.driver.title or "(no title)"
        print(f"  page title: {title}")

        if "attention" in title.lower() or "just a moment" in title.lower():
            print("\n  That looks like a Cloudflare interstitial. The session was")
            print("  challenged. Delete the profile directory and retry; if it")
            print("  persists, the source IP is being challenged, not the browser.")
            return 1

        print("\nAll checks passed. Run: python app.py")
        return 0
    finally:
        scraper.close()


if __name__ == "__main__":
    sys.exit(main())
