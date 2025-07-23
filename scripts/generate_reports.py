import json
from datetime import datetime
import os

MALSHARE_DESC = """
## Malshare Samples

These are hashes of malware samples recently discovered and catalogued by Malshare, a repository of malware binaries.

- **SHA256:** This is a unique digital fingerprint for each malware file. Security analysts use these hashes to identify and share malware samples without distributing the actual malicious files.
- **First Seen:** Indicates when the sample was first detected (if available).

**How to use this info:**  
If you have malware detection tools or threat intelligence platforms, you can use these SHA256 hashes to check if any of these malware samples have been seen on your network or systems. It helps identify infections or threats by matching known malware signatures.
"""

ABUSEIPDB_DESC = """
## AbuseIPDB Blacklisted IPs

This section lists IP addresses reported for malicious activity and flagged by AbuseIPDB, a collaborative threat intelligence platform.

- These IPs are linked to activities like scanning, hacking attempts, spamming, or distributing malware.
- The "confidence score" reflects how reliably the IP is considered abusive based on reports.

**How to use this info:**  
Network defenders can block or monitor traffic to and from these IP addresses to reduce the risk of attacks. If you see connections involving these IPs, consider investigating them promptly.
"""

URLHAUS_DESC = """
## URLHaus Malicious URLs

URLHaus tracks URLs that host malware or phishing pages.

- These URLs are known to distribute malicious payloads or trick users into giving up sensitive data.
- Attackers often use these URLs in phishing emails or drive-by-download attacks.

**How to use this info:**  
Security teams can block these URLs at the network or browser level to prevent access. Users should never click on suspicious links like these, and email gateways can be configured to flag messages containing such URLs.
"""

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'cti_data.json')
OUTPUT_MD = os.path.join(os.path.dirname(__file__), '..', 'docs', 'index.md')
OUTPUT_HTML = os.path.join(os.path.dirname(__file__), '..', 'docs', 'index.html')

def load_cti_data():
    if not os.path.exists(DATA_FILE):
        print("⚠️ No CTI data found.")
        return None
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_markdown(data):
    md_lines = [f"# Cyber Threat Intelligence Feed\n",
                f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"]

    # OTX pulses
    md_lines.append("## AlienVault OTX Pulses\n")
    for pulse in data.get('otx', []):
        md_lines.append(f"### {pulse.get('name')}")
        md_lines.append(f"- Created: {pulse.get('created')}")
        md_lines.append(f"- Author: {pulse.get('author_name')}")
        desc = pulse.get('description', '').strip()
        md_lines.append(f"\n{desc}\n")

    # Malshare samples with description
    md_lines.append(MALSHARE_DESC)
    for sample in data.get('malshare', []):
        md_lines.append(f"- SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")
    md_lines.append("")

    # AbuseIPDB blacklisted IPs with description
    md_lines.append(ABUSEIPDB_DESC)
    for ip in data.get('abuseipdb', []):
        md_lines.append(f"- IP: {ip.get('ipAddress')} | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}")
    md_lines.append("")

    # URLHaus URLs with description
    md_lines.append(URLHAUS_DESC)
    for entry in data.get('urlhaus', []):
        md_lines.append(f"- URL: {entry.get('url')}")
    md_lines.append("")

    return "\n".join(md_lines)

def generate_html(md_text):
    # Basic HTML wrapper; you can style later or use markdown->html libs
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Cyber Threat Intel Feed</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 1rem; }}
    h1, h2, h3 {{ color: #2c3e50; }}
    pre {{ background: #eee; padding: 1rem; }}
  </style>
</head>
<body>
{md_text.replace('\n', '<br>\n')}
</body>
</html>"""
    return html

def save_reports(md_text, html_text):
    os.makedirs(os.path.dirname(OUTPUT_MD), exist_ok=True)
    with open(OUTPUT_MD, 'w', encoding='utf-8') as f:
        f.write(md_text)
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html_text)
    print(f"✅ Markdown report saved to {OUTPUT_MD}")
    print(f"✅ HTML report saved to {OUTPUT_HTML}")

if __name__ == "__main__":
    data = load_cti_data()
    if not data:
        exit(1)
    md_report = generate_markdown(data)
    html_report = generate_html(md_report)
    save_reports(md_report, html_report)
