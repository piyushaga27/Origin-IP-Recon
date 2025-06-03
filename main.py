#!/usr/bin/env python3

''' Troubleshooting the status codes'''

import subprocess
import threading
import queue
import json
import argparse
import os
from dotenv import load_dotenv

load_dotenv()
validIPs = []
invalidIPs = []
IPQueue = queue.Queue()
lock = threading.Lock()

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def virus_total(domain):
    print("[+] Gathering Information from VirusTotal...")
    #api_key = "fd386adf3978bdfca2064b643e3ffdabe15f0e19863c3d79e1ad0d5f50612385"
    api_key = os.getenv("VirusTotal_API_KEY")
    if not api_key:
        print("[!] VirusTotal API key not set in .env file (VirusTotal_API_KEY). Skipping...")
        return set()
    command = f'''curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}" | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' '''
    output = run_cmd(command)
    return set(output.splitlines())

def DNS_recon(domain):
    print("[+] Gathering Information from DNS Recon...")
    command = f'''dnsrecon -d {domain} | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' '''
    output = run_cmd(command)
    return set(output.splitlines())

def alienvault(domain):
    print("[+] Gathering Information from AlienVault...")
    command = f''' curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1" | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' '''
    output = run_cmd(command)
    return set(output.splitlines())

def urlscan(domain):
    print("[+] Gathering from URLScan.io...")
    command = f'''curl -s "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000" | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' '''
    output = run_cmd(command)
    return set(output.splitlines())

def viewdns(domain):
    print("[+] Gathering IPs from ViewDNS.info...")
    #apikey="376fef13a604a802f780d079927822646c312d9e"
    api_key = os.getenv("VIEWDNS_API_KEY")
    if not api_key:
        print("[!] ViewDNS API key not set in .env file (VIEWDNS_API_KEY). Skipping...")
        return set()
    command = f"curl -s 'https://api.viewdns.info/iphistory/?domain={domain}&apikey={api_key}&output=json' | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}'"
    output = run_cmd(command)
    return set(output.splitlines())

def check_spf(domain):
    print("[+] Fetching SPF records...")
    command = f"dig +short TXT {domain} @8.8.8.8 | grep spf | grep -Eo 'ip4:([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' | cut -d: -f2"
    output = run_cmd(command)
    return set(output.splitlines())

def security_trails(domain):
    print("[+] Gathering from SecurityTrails...")
    #api_key = "ZeFkNUAeQ4anLCmbMug1zXMTf20XekFU"
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    if not api_key:
        print("[!] Security Trails API key not set in .env file (SecurityTrails_API_KEY). Skipping...")
        return set()
    command = f"curl -s -H 'apikey: {api_key}' https://api.securitytrails.com/v1/domain/{domain}/subdomains | jq -r '.subdomains[]' | sed 's/^/{domain}\./' | xargs -I {{}} dig +short {{}} | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}'"
    output = run_cmd(command)
    return set(output.splitlines())

def verify_ip() :
    while not IPQueue.empty():
        ip = IPQueue.get()
        try:
            cmd = f"echo \"{ip}\" | httpx-toolkit -silent -json -status-code -timeout 10 -retries 1 -ports 80,443"
            result = run_cmd(cmd)
            isValid = False  # track if already added

            for line in result.splitlines():
                try:
                    data = json.loads(line)
                    code = data.get("status-code", 0)
                    if 200 <= code < 400 and not isValid:
                        with lock:
                            validIPs.append(ip)
                        isValid = True
                except json.JSONDecodeError:
                    pass

            if not isValid:
                with lock:
                    invalidIPs.append(ip)

        except Exception:
            with lock:
                invalidIPs.append(ip)
        finally:
            IPQueue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Recon Tool - OSINT IP Collector & Validator")
    parser.add_argument('--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Max concurrent threads (default 10)')
    args = parser.parse_args()
    domain = args.domain
    threads = args.threads

    total_ips = set()
    total_ips.update(virus_total(domain))
    total_ips.update(DNS_recon(domain))
    total_ips.update(alienvault(domain))
    total_ips.update(urlscan(domain))
    total_ips.update(viewdns(domain))
    total_ips.update(check_spf(domain))
    total_ips.update(security_trails(domain))


    print(f"[✓] Total unique IPs found: {len(total_ips)}")

    for ip in total_ips:
        IPQueue.put(ip)

    print(f"[✓] Starting validation threads...\n")

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=verify_ip)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    # Writing results


    with open("verified_ips.txt", "w") as vf:
        for ip in validIPs:
            vf.write(ip + "\n")

    with open("unverified_ips.txt", "w") as uvf:
        for ip in invalidIPs:
            uvf.write(ip + "\n")

    print(f"\n[+] Done! Verified: {len(validIPs)}, Unverified: {len(invalidIPs)}")
    print("[✓] Results saved to 'verified_ips.txt' and 'unverified_ips.txt'")

if __name__ == "__main__":
    main()