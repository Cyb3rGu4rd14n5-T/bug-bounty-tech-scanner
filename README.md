# 🕵️‍♂️ Bug Bounty Tech & CVE Scanner

**Created by: Cyb3rGu4rd14n5-T**

---

## 📌 What is this tool?

This is a simple **bug bounty helper tool** for beginners!  
It scans any website URL for:
- Server & tech stack (like Apache, PHP, WordPress, etc.)
- Checks for known CVEs (Common Vulnerabilities & Exposures)
- Generates a clear email template to help you report responsibly.

---

## 🎓 Who is this for?

This tool is designed for:
- Students learning cybersecurity
- Beginner bug bounty hunters
- Ethical hackers wanting to practice finding outdated technologies

**Example:**  
👉 You can scan your college website, find outdated plugins, generate a report, and send it to your IT team for appreciation & acknowledgment.  
It runs on **Termux**, so you can even scan from your **Android phone!**

---

## ⚡ How to use

Clone the repo:

 git clone https://github.com/YourUsername/bugbounty-tech-cve-scanner.git

 
 cd bugbounty-tech-cve-scanner



Install requirements:


pip install -r requirements.txt
Run the tool:

python3 scanner.py
Follow the prompts:

Enter the website URL.

Choose if you want to save results.

Optionally generate a detailed email report.



⚠️ Important Note about API Key
This tool uses the free Vulners API to check for CVEs.
Your included API key may expire or reach usage limits!



👉 How to get your own:
Sign up at https://vulners.com

Get your free API key in your dashboard.

Open scanner.py and replace this line:

python

VULNERS_API_KEY = 'YOUR_NEW_API_KEY'



✅ Disclaimer
For educational & ethical use only!

Always have permission before scanning websites.

Use responsibly to help secure systems & learn.
