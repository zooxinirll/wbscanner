#!/usr/bin/env python3

import os
import requests
import random
from alive_progress import alive_bar
from termcolor import colored
import time
import pyfiglet

# Random User-Agent pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

def random_user_agent():
    return random.choice(USER_AGENTS)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Enhanced Host Header Injection Detection (includes X-Forwarded-Host)
def check_host_header_injection(url):
    payloads = ["evil.com", "attacker.com"]
    results = []
    for payload in payloads:
        headers_list = [
            {"Host": payload},
            {"X-Forwarded-Host": payload}
        ]
        for headers_subset in headers_list:
            headers = {
                "User-Agent": random_user_agent(),
                **headers_subset
            }
            try:
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
                reflected = payload in response.headers.get('Location', '') or payload in response.text.lower()
                server_disclosure = payload in response.headers.get('Server', '').lower()
                if reflected or server_disclosure:
                    header_type = list(headers_subset.keys())[0]
                    results.append(f"[!] Host Header Injection Detected on {url} with '{header_type}: {payload}'")
            except Exception as e:
                results.append(f"[ERROR] Host Header Injection Test Failed for {url} with {headers_subset}: {e}")
    return results or [f"[OK] No Host Header Injection Vulnerability on {url}"]

# Refined CORS Misconfiguration Detection
def check_cors_misconfiguration(url):
    headers = {
        "User-Agent": random_user_agent(),
        "Origin": "https://evil.com"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower()

        if response.status_code == 200 and allow_origin in ["https://evil.com", "*"] and allow_credentials == "true":
            return f"[!] Potential CORS Misconfiguration Detected on {url}. Origin: {allow_origin}"
    except Exception as e:
        return f"[ERROR] CORS Test Failed for {url}: {e}"
    return f"[OK] No CORS Misconfiguration on {url}"

# Refined Clickjacking Detection
def check_clickjacking(url):
    headers = {"User-Agent": random_user_agent()}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            x_frame_options = response.headers.get("X-Frame-Options", "").lower()
            content_security_policy = response.headers.get("Content-Security-Policy", "").lower()
            if not x_frame_options and "frame-ancestors" not in content_security_policy:
                return f"[!] Potential Clickjacking Vulnerability Detected on {url}"
    except Exception as e:
        return f"[ERROR] Clickjacking Test Failed for {url}: {e}"
    return f"[OK] Protection Against Clickjacking Present on {url}"

# Refined HTTP Request Smuggling Detection
def check_http_request_smuggling(url):
    headers = {
        "User-Agent": random_user_agent(),
        "Content-Length": "4",
        "Transfer-Encoding": "chunked"
    }
    body = "0\r\n\r\n"
    try:
        response = requests.post(url, headers=headers, data=body, timeout=10)
        if response.status_code in {200, 201}:
            return f"[!] Potential HTTP Request Smuggling Detected on {url}"
    except Exception as e:
        return f"[ERROR] HTTP Request Smuggling Test Failed for {url}: {e}"
    return f"[OK] No HTTP Request Smuggling Vulnerability on {url}"

# HTTP Methods Detection
def check_http_methods(url):
    try:
        response = requests.options(url, headers={"User-Agent": random_user_agent()}, timeout=10)
        allowed_methods = response.headers.get("Allow", "").split(", ")
        unsafe_methods = {"PUT", "DELETE", "TRACE", "CONNECT"}
        risky_methods = [method for method in unsafe_methods if method in allowed_methods]
        if risky_methods:
            return f"[!] Unsafe HTTP Methods Detected on {url}: {', '.join(risky_methods)}"
    except Exception as e:
        return f"[ERROR] HTTP Methods Test Failed for {url}: {e}"
    return f"[OK] HTTP Methods Secure on {url}"

# Scanning URLs
def scan_urls(input_source):
    results = []
    try:
        if input_source.endswith(".txt"):
            with open(input_source, "r") as file:
                urls = [line.strip() for line in file if line.strip()]
        else:
            urls = [input_source]

        print(colored("\n== Starting Scan ==\n", "cyan"))
        with alive_bar(len(urls), title="Scanning Targets", spinner="dots") as bar:
            for url in urls:
                url_results = []
                try:
                    print(colored(f"\n[Scanning] {url}", "cyan"))
                    checks = [
                        check_host_header_injection(url),
                        [check_clickjacking(url)],
                        [check_http_request_smuggling(url)],
                        [check_cors_misconfiguration(url)],
                        [check_http_methods(url)]
                    ]
                    for check in checks:
                        for result in check:
                            url_results.append(result)
                            if "[!]" in result:
                                print(colored(result, "red"))
                            elif "[ERROR]" in result:
                                print(colored(result, "yellow"))
                            else:
                                print(colored(result, "green"))
                    results.append(f"Results for {url}:\n" + "\n".join(url_results) + "\n")
                    bar()
                except KeyboardInterrupt:
                    print(colored("\n[INFO] Scan Interrupted by User!", "yellow"))
                    return results
        print(colored("\n== Scan Complete ==\n", "green"))
    except FileNotFoundError:
        print(colored(f"File not found: {input_source}", "red"))
    except Exception as e:
        print(colored(f"Error reading input: {e}", "red"))
    return results

def save_results(results):
    save = input(colored("\nDo you want to save the results? (yes/no): ", "cyan")).strip().lower()
    if save in ["yes", "y"]:
        file_name = input(colored("Enter file name (default: scan_results.txt): ", "cyan")).strip() or "scan_results.txt"
        try:
            with open(file_name, "w") as file:
                file.write("\n".join(results))
            print(colored(f"Results saved to {file_name}", "green"))
        except Exception as e:
            print(colored(f"Error saving results: {e}", "red"))

if __name__ == "__main__":
    clear_screen()
    banner = pyfiglet.figlet_format("WB Scanner", font="slant")
    print(colored(banner, "white", attrs=["bold"]))
    print(colored("                              Author: Localhost.07", "white"))
    print("")
    target = input("Enter target URL or file (e.g., target.txt): ").strip()
    results = scan_urls(target)
    if results:
        save_results(results)
