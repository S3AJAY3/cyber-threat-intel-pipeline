\import json
from datetime import datetime
import os

# Descriptions for each data type
DESCRIPTIONS = {
    "malshare": """
## Malshare Samples

These are hashes of malware samples recently discovered and catalogued by Malshare, a repository of malware binaries.

- **SHA256:** Unique fingerprint for each malware file.
- **First Seen:** When it was first detected.

Use these hashes to search your network or tools for known threats.
""",
    "abuseipdb": """
## AbuseIPDB Blacklisted IPs

IP addresses reported for malicious activity, with confidence scores.

- **Confidence Score:** Reliability of abuse reports.
- **Reports:** How many times it was reported.

Use this to block or investigate network threats.
""",
    "urlhaus": """
## URLHaus Malicious URLs

URLs distributing malware or phishing payloads.

Use this to block threats at the DNS or proxy level.
""",
    "otx": """
## AlienVault OTX Pulses

Curated threat intel shared by the security community.

Each "Pulse" is a collection of related IoCs.
"""
}

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'cti_data.json')
DOCS_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs')

def load_cti_data():
    if not os.path.exists(DATA_FILE):
        print("⚠️ No CTI data found.")
        return None
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_page(filename, title, body_lines):
    path = os.path.join(DOCS_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"---\nlayout: default\ntitle: {title}\n---\n\n")
        f.write(f"# {title}\n\n")
        f.write("\n".join(body_lines))
    print(f"✅ Saved {filename}")

def generate_all_pages(data):
    # Home/index page
    home_lines = [
        f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n",
        "This site compiles threat intel feeds into one place.\n",
        "### Sources:",
        "- [AlienVault OTX](otx.md)",
        "- [Malshare](malshare.md)",
        "- [AbuseIPDB](abuseipdb.md)",
        "- [URLHaus](urlhaus.md)",
        "",
    ]
    save_page("index.md", "Cyber Threat Intelligence Hub", home_lines)

    # OTX
    otx_lines = [DESCRIPTIONS["otx"]]
    for pulse in data.get("otx", []):
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        otx_lines.append(pulse.get("description", "").strip())
        otx_lines.append("")
    save_page("otx.md", "AlienVault OTX Pulses", otx_lines)

    # Malshare
    mal_lines = [DESCRIPTIONS["malshare"]]
    for sample in data.get("malshare", []):
        mal_lines.append(f"- SHA256: `{sample.get('sha256')}` | First Seen: {sample.get('first_seen')}")
    save_page("malshare.md", "Malshare Samples", mal_lines)

    # AbuseIPDB
    abuse_lines = [DESCRIPTIONS["abuseipdb"]]
    for ip in data.get("abuseipdb", []):
        abuse_lines.append(f"- IP: `{ip.get('ipAddress')}` | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}")
    save_page("abuseipdb.md", "AbuseIPDB Blacklisted IPs", abuse_lines)

    # URLHaus
    urlhaus_lines = [DESCRIPTIONS["urlhaus"]]
    for entry in data.get("urlhaus", []):
        urlhaus_lines.append(f"- URL: `{entry.get('url')}`")
    save_page("urlhaus.md", "URLHaus Malicious URLs", urlhaus_lines)

if __name__ == "__main__":
    data = load_cti_data()
    if not data:
        exit(1)
    generate_all_pages(data)

