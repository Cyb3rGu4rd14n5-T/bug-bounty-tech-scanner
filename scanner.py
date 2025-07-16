#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import re
import os

# === Your Vulners API Key ===
VULNERS_API_KEY = 'CSXPZW0GKXR3LJDXJFRWNWYQI511EVDJER6FXE14YJBPH1F5CKEYNAAI8FJHZ6SZ'

# === Colors ===
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# === Fallback attacker actions if no CVEs ===
FALLBACK_RISKS = {
    'WordPress': [
        'Exploit outdated plugins with hidden vulnerabilities.',
        'Brute-force admin credentials.',
        'Upload malicious files to gain shell access.'
    ],
    'Apache': [
        'Use known misconfigurations to bypass directory restrictions.',
        'Run Slowloris or other DoS attacks.',
        'Exploit old modules with unpatched flaws.'
    ],
    'PHP': [
        'Trigger RCE through unsafe eval or file inclusion bugs.',
        'Use outdated functions that may allow memory leaks.',
        'Abuse poor input sanitization for XSS or SQLi.'
    ],
    'jQuery': [
        'Leverage unsafe DOM manipulation for XSS.',
        'Chain with other scripts to perform clickjacking.'
    ],
    # Add more as needed!
}

print(f"""{YELLOW}
🚩 Bug Bounty Tech & CVE Scanner 🕵️‍♂️
🔒 Created by Cyb3rGu4rd14n5-T
{RESET}""")

# === Save output to next file ===
def get_next_filename():
    base = 'results'
    ext = '.txt'
    i = 1
    while os.path.exists(f"{base}{i}{ext}"):
        i += 1
    return f"{base}{i}{ext}"

# === Extract tech + version ===
def extract_tech_versions(text):
    found = []
    pattern = r'([\w\-]+)[/ ]([\d\.]+)'
    matches = re.findall(pattern, text, re.I)
    for m in matches:
        found.append((m[0], m[1]))
    return found

# === Fingerprint site ===
def fingerprint(url):
    techs = []
    try:
        response = requests.get(url, timeout=10)
    except:
        print(f"{RED}[-] Error: Cannot reach URL.{RESET}")
        return techs

    headers = response.headers
    soup = BeautifulSoup(response.text, 'html.parser')
    combined = ''

    server = headers.get('Server')
    if server:
        combined += server + ' '

    powered = headers.get('X-Powered-By')
    if powered:
        combined += powered + ' '

    for meta in soup.find_all('meta'):
        if meta.get('name', '').lower() == 'generator':
            combined += meta.get('content', '') + ' '

    for script in soup.find_all('script'):
        src = script.get('src', '')
        combined += src + ' '

    found = extract_tech_versions(combined)
    for f in found:
        techs.append(f)

    return techs

# === Check CVEs ===
def check_cves(tech, version):
    cve_list = []
    search = f"{tech} {version}"
    print(f"{YELLOW}[~] Checking CVEs for: {search} ...{RESET}")

    url = f"https://vulners.com/api/v3/search/lucene/?query={search}&apiKey={VULNERS_API_KEY}"
    resp = requests.get(url)
    if resp.status_code != 200:
        print(f"{RED}[-] CVE API error for {search}.{RESET}")
        return cve_list

    data = resp.json()
    cves = data.get('data', {}).get('search', [])
    for cve in cves[:5]:
        if 'id' in cve and 'description' in cve:
            cve_list.append({
                'id': cve['id'],
                'title': cve.get('title', 'N/A'),
                'desc': cve['description']
            })

    return cve_list

# === Main ===
def main():
    url = input(f"{CYAN}Enter website URL: {RESET}").strip()
    save = input(f"{CYAN}Save results to file? (yes/no): {RESET}").lower() == 'yes'
    report = []
    all_cve_data = []

    techs = fingerprint(url)
    if not techs:
        report.append(f"{RED}[-] No tech stack detected!{RESET}")

    for tech, version in techs:
        cve_list = check_cves(tech, version)
        if cve_list:
            status = f"{RED}Outdated with known CVEs!{RESET}"
        else:
            status = f"{YELLOW}No known CVEs found, but version might be outdated.{RESET}"
        report.append(f"\n🔧 {tech} v{version} => {status}")
        all_cve_data.append({'tech': tech, 'version': version, 'cves': cve_list})

    if save:
        filename = get_next_filename()
        with open(filename, 'w') as f:
            f.write('\n'.join(report))
        print(f"{GREEN}\n[+] Results saved to {filename}{RESET}")

    for line in report:
        print(line)

    email = input(f"\n{CYAN}Generate detailed email report? (yes/no): {RESET}").lower()
    if email == 'yes':
        print("\n===== 📧 EMAIL TEMPLATE =====\n")
        print(f"Subject: Security Alert – Vulnerabilities Identified in Website Technologies – Urgent Action Recommended\n")
        print(f"Dear [Organization Name / Website Administrator],\n")
        print(f"My name is [Your Name], a student security researcher / bug bounty hunter. I am reaching out to inform you about several critical security issues identified on your website: {url}\n")
        print(f"After reviewing publicly accessible technologies, I discovered that some components are outdated and have known security vulnerabilities (CVEs). These could put the website, its users, and your data at risk.\n")
        print(f"Summary of Identified Vulnerabilities:\n")

        count = 1
        for item in all_cve_data:
            tech = item['tech']
            version = item['version']

            if item['cves']:
                for cve in item['cves']:
                    print(f"{count}. {tech} v{version}\n")
                    print(f"   CVE: {cve['id']} ({cve['title']})\n")
                    print(f"   Type: {cve['title']}\n")
                    print(f"   Applies to: {tech} version {version} and related versions.\n")
                    print(f"   An attacker can:\n")
                    attack_points = cve['desc'].split('. ')
                    for point in attack_points:
                        point = point.strip()
                        if point:
                            print(f"   - {point.strip('.')}.")
                    print(f"\n   Fix:\n")
                    print(f"   - Upgrade to the latest secure version.")
                    print(f"   - Apply vendor patches and sanitize inputs properly.\n")
                    count += 1
            else:
                print(f"{count}. {tech} v{version}\n")
                risks = FALLBACK_RISKS.get(tech)
                if risks:
                    print(f"   No known CVEs found, but version {version} is outdated.\n")
                    print(f"   An attacker can:")
                    for r in risks:
                        print(f"   - {r}")
                    print(f"\n   Fix:\n   - Upgrade to the latest secure version.\n   - Apply best practice configuration and patch regularly.\n")
                else:
                    print(f"   No known CVEs found. Please ensure this component is up to date.\n")
                count += 1

        print("\nRisks if Left Unfixed:\n")
        print("- Unauthorized access to user data or administrative functions.\n"
              "- Data breaches through SQL injection, XSS, or other vulnerabilities.\n"
              "- Session hijacking or malicious redirects for visitors.\n"
              "- Potential compliance issues related to data security & privacy laws.\n")

        print("Recommendation:\n")
        print("I recommend that your IT or web development team perform a full security audit and apply the necessary patches or upgrades as soon as possible to prevent potential exploitation.\n"
              "Please let me know if I can assist further or provide a more detailed technical summary.\n")

        print("Sincerely,\n")
        print("[Your Full Name]\n[Your University / Department]\n[Your Roll Number]\n[Your Contact Email or Phone Number]")

if __name__ == '__main__':
    main()
