#!/usr/bin/env python3

import requests
import argparse
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs



# Payload Generator (Requirement #1)

class PayloadGenerator:
    def __init__(self):
        self.random_tag = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

    def generate(self, context):
        payloads = {
            "attribute-name": f'onerror=alert("XSS_{self.random_tag}")',
            "attribute-value": f'" autofocus onfocus=alert("XSS_{self.random_tag}")"',
            "text": f'<script>alert("XSS_{self.random_tag}")</script>',
        }
        return payloads.get(context, payloads["text"])


# Scanner Class

class XSSScanner:
    def __init__(self, url, params, method, cookie):
        self.url = url
        self.params = params
        self.method = method.upper()
        self.cookie = cookie
        self.results = []

    def send_request(self, payload_params):
        headers = {"Cookie": self.cookie} if self.cookie else {}

        if self.method == "GET":
            return requests.get(self.url, params=payload_params, headers=headers)

        elif self.method == "POST":
            return requests.post(self.url, data=payload_params, headers=headers)

        else:
            raise ValueError("HTTP method must be GET or POST")

    def detect_reflection(self, payload, response_text):
        return payload in response_text

    def scan(self):
        print(f"[+] Scanning {self.url}")

        generator = PayloadGenerator()
        contexts = ["attribute-name", "attribute-value", "text"]

        for param in self.params:
            for context in contexts:
                payload = generator.generate(context)
                request_params = {param: payload}

                response = self.send_request(request_params)

                reflected = self.detect_reflection(payload, response.text)

                print(f" - {param:<15} | {context:<18} | Reflected: {reflected}")

                snippet = self.extract_snippet(response.text, payload)

                self.results.append({
                    "param": param,
                    "payload": payload,
                    "context": context,
                    "reflected": reflected,
                    "status": response.status_code,
                    "snippet": snippet
                })

        self.generate_report()
        print("[+] Scan complete. Report saved as report.html")

    def extract_snippet(self, html, payload, size=200):
        index = html.find(payload)
        if index == -1:
            return ""
        return html[max(0, index - size): index + size]

    def generate_report(self):
        html = """
        <!doctype html>
        <html>
        <head><meta charset="utf-8"><title>Reflected XSS Report</title>
        <style>
        body{font-family:Arial;padding:18px}
        table{border-collapse:collapse;width:100%}
        th,td{border:1px solid #ddd;padding:8px}
        th{background:#eee}
        code{background:#f6f6f6;padding:2px 4px;border-radius:4px}
        .yes{color:green;font-weight:bold}
        .no{color:red;font-weight:bold}
        </style></head><body>
        """

        html += f"<h1>Reflected XSS Scan Report</h1><p><b>Target:</b> {self.url}</p>"
        html += "<table><tr><th>Parameter</th><th>Payload</th><th>Context</th><th>Reflected?</th><th>Status</th><th>Snippet</th></tr>"

        for result in self.results:
            html += f"""
            <tr>
                <td>{result['param']}</td>
                <td><code>{result['payload']}</code></td>
                <td>{result['context']}</td>
                <td class="{'yes' if result['reflected'] else 'no'}">{'YES' if result['reflected'] else 'NO'}</td>
                <td>{result['status']}</td>
                <td><pre style="max-height:120px;overflow:auto">{result['snippet']}</pre></td>
            </tr>
            """

        html += "</table></body></html>"

        with open("report.html", "w") as file:
            file.write(html)


# CLI Argument Parser

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reflected XSS Scanner")

    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--params", required=True, help="Comma separated list of parameters")
    parser.add_argument("--method", default="GET", help="HTTP Method: GET/POST")
    parser.add_argument("--cookie", default=None, help="Cookie string if authentication required")

    args = parser.parse_args()

    params_list = args.params.split(",")

    scanner = XSSScanner(args.url, params_list, args.method, args.cookie)
    scanner.scan()
