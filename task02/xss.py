#!/usr/bin/env python3
"""
xss.py

PyCharm-friendly reflected XSS tester.

- If you run this script from PyCharm's Run (without configuring arguments),
  it will prompt you to enter the target URL in the Run console.
- You can still pass a target as a CLI argument if you prefer.

Requirements:
    pip install requests beautifulsoup4

IMPORTANT: Only run against systems you own or have explicit written permission to test.
"""

import argparse
import html
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

# --- Config ---
PAYLOADS = [
    '<script>alert("XSS")</script>',
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
]
HEADERS = {"User-Agent": "ReflectedXSSTester/1.0 (PyCharm)"}
REQUEST_TIMEOUT = 12  # seconds


# Let's define Helpers :
def parse_url_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(url, params):
    parsed = urlparse(url)
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def find_form_field_names(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    names = set()
    for form in soup.find_all("form"):
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                names.add(name)
    return list(names)


def inspect_response_for_payload(response_text, raw_payload):
    """
    Returns a dict describing whether payload appears unescaped in various contexts.
    """
    findings = {
        "in_raw_text": False,
        "in_script_tag": False,
        "in_attribute": False,
        "escaped_only": False,
    }

    if raw_payload in response_text:
        findings["in_raw_text"] = True

    soup = BeautifulSoup(response_text, "html.parser")

    # Check script tags
    for script in soup.find_all("script"):
        if raw_payload in script.decode_contents():
            findings["in_script_tag"] = True

    # Check attributes heuristically
    for tag in soup.find_all(True):
        for attr_value in tag.attrs.values():
            if isinstance(attr_value, list):
                attr_value = " ".join(attr_value)
            if raw_payload in str(attr_value):
                findings["in_attribute"] = True

    # Escaped only?
    if not (findings["in_raw_text"] or findings["in_script_tag"] or findings["in_attribute"]):
        if html.escape(raw_payload) in response_text or html.unescape(response_text).find(raw_payload) != -1:
            findings["escaped_only"] = True

    return findings


# Core testing routine
def test_reflected_xss(target_url: str, method: str = "GET", verify_tls: bool = True):
    session = requests.Session()
    session.headers.update(HEADERS)

    # Discover URL params from provided target
    raw_params = parse_url_params(target_url)
    # normalize to single-value strings (take first if multiple)
    url_params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in raw_params.items()}

    print(f"[+] Target: {target_url}")
    if url_params:
        print(f"[+] URL parameters detected: {list(url_params.keys())}")
    else:
        print("[+] No URL parameters detected in the provided URL.")

    # Initial GET to discover forms and baseline
    try:
        baseline = session.get(target_url, timeout=REQUEST_TIMEOUT, verify=verify_tls)
        baseline.raise_for_status()
    except requests.RequestException as e:
        print(f"[-] Failed to fetch target page: {e}")
        return []

    form_fields = find_form_field_names(baseline.text)
    if form_fields:
        print(f"[+] Form fields discovered: {form_fields}")

    # Candidate params = URL params + form field names; fallback to 'q' if none found
    candidates = set(list(url_params.keys()) + form_fields)
    if not candidates:
        print("[!] No candidates discovered; using synthetic parameter 'q' for basic testing.")
        candidates = {"q"}

    findings = []

    for candidate in sorted(candidates):
        for payload in PAYLOADS:
            test_params = dict(url_params)  # copy existing URL parameters
            test_params[candidate] = payload

            try:
                if method.upper() == "GET":
                    test_url = build_url_with_params(target_url, test_params)
                    resp = session.get(test_url, timeout=REQUEST_TIMEOUT, verify=verify_tls)
                else:
                    # POST to same path (strip query)
                    parsed = urlparse(target_url)
                    post_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
                    resp = session.post(post_url, data=test_params, timeout=REQUEST_TIMEOUT, verify=verify_tls)

                # skip error pages
                if resp.status_code >= 400:
                    print(f"[!] HTTP {resp.status_code} for param='{candidate}' -> skipping deep analysis")
                    continue

                result = inspect_response_for_payload(resp.text, payload)

                if result["in_raw_text"] or result["in_script_tag"] or result["in_attribute"]:
                    print(f"[!!] Possible reflected XSS: param='{candidate}' payload='{payload}'")
                    findings.append(
                        {
                            "parameter": candidate,
                            "payload": payload,
                            "tested_url": resp.url,
                            "details": result,
                        }
                    )
                elif result["escaped_only"]:
                    print(f"[-] Payload reflected but escaped for param='{candidate}' (likely sanitized).")
                else:
                    print(f"[ ] No reflection for param='{candidate}' with payload variant.")
            except requests.RequestException as e:
                print(f"[-] Request error testing param='{candidate}': {e}")

    # Summary
    print("\n--- Scan summary ---")
    if findings:
        print(f"[!] Potential issues found: {len(findings)}")
        for idx, f in enumerate(findings, 1):
            print(f" {idx}) param='{f['parameter']}' payload='{f['payload']}' url='{f['tested_url']}'")
    else:
        print("[+] No reflected XSS detected with the simple payloads used. (Not a proof of absence.)")

    return findings


#CLI / PyCharm friendly run
def main():
    parser = argparse.ArgumentParser(description="Reflected XSS tester (PyCharm-friendly).")
    parser.add_argument("target", nargs='?', help="Target URL (include query portion if present).")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use for injection.")
    parser.add_argument("--no-verify", action="store_true", help="Do not verify TLS certificates (useful for lab self-signed certs).")
    parser.add_argument("--output", help="Optional JSON file to write findings.")
    args = parser.parse_args()

    # If no target provided via CLI, prompt the user (suitable when running in PyCharm Run console)
    target = args.target
    if not target:
        try:
            default_example = "http://localhost:3000/#/search?q=test"
            prompt = f"Enter target URL (or press Enter to use example: {default_example}): "
            entered = input(prompt).strip()
            target = entered if entered else default_example
            print(f"[+] Using target: {target}")
        except (KeyboardInterrupt, EOFError):
            print("\n[-] No target provided; exiting.")
            return

    findings = test_reflected_xss(target, method=args.method, verify_tls=not args.no_verify)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(findings, fh, indent=2, ensure_ascii=False)
            print(f"[+] Findings written to: {args.output}")
        except OSError as e:
            print(f"[-] Could not write output file: {e}")


if __name__ == "__main__":
    main()
