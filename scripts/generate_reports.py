import json
from datetime import datetime
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'cti_data.json')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs')

DESCRIPTIONS = {
    'otx': "## Pulses contain threat indicators and context shared by researchers.",
    'malshare': "## Hashes of malware binaries recently observed in the wild.",
    'abuseipdb': "## IPs reported for abuse like scans, attacks, or spam.",
    'urlhaus': "## URLs known to host malware or phishing content."
}

def load_cti_data():
    if not os.path.exists(DATA_FILE):
        print("⚠️ No CTI data found.")
        return None
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_markdown_file(filename, title, description, content_lines):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# {title}\n")
        f.write(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n")
        f.write(f"{description}\n\n")
        f.writelines('\n'.join(content_lines))
    print(f"✅ Generated {filename}")

def generate_reports(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generate individual pages
    pages = {}

    # OTX
    otx_lines = []
    for pulse in data.get('otx', []):
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        otx_lines.append(f"- Description: {pulse.get('description', '').strip()}\n")
    write_markdown_file("otx.md", "AlienVault OTX Pulses", DESCRIPTIONS["otx"], otx_lines)

    # Malshare
    malshare_lines = []
    for sample in data.get('malshare', []):
        malshare_lines.append(f"- SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")
    write_markdown_file("malshare.md", "Malshare Samples", DESCRIPTIONS["malshare"], malshare_lines)

    # AbuseIPDB
    abuse_lines = []
    for ip in data.get('abuseipdb', []):
        abuse_lines.append(f"- IP: {ip.get('ipAddress')} | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}")
    write_markdown_file("abuseipdb.md", "AbuseIPDB IP Reports", DESCRIPTIONS["abuseipdb"], abuse_lines)

    # URLHaus
    urlhaus_lines = []
    for entry in data.get('urlhaus', []):
        urlhaus_lines.append(f"- URL: {entry.get('url')}")
    write_markdown_file("urlhaus.md", "URLHaus Malicious URLs", DESCRIPTIONS["urlhaus"], urlhaus_lines)

    # Generate index.md as homepage
    index_lines = []
        "Welcome to your CTI Hub. Click below to view threat feeds:\n",
        "- [OTX Pulses](./otx.md)",
        "- [Malshare Samples](./malshare.md)",
        "- [AbuseIPDB IPs](./abuseipdb.md)",
        "- [URLHaus URLs](./urlhaus.md)",
    ]
    write_markdown_file("index.md", "Cyber Threat Intelligence Hub", "", index_lines)

if __name__ == "__main__":
    data = load_cti_data()
    if not data:
        exit(1)
    generate_reports(data)
