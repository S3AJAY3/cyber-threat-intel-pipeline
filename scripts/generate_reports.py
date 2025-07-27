import json
from datetime import datetime
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'cti_data.json')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs')

# Add your descriptions here
DESCRIPTIONS = {
    "otx": "Hashes and pulses from AlienVault OTX feed.",
    "malshare": "Hashes of malware binaries recently observed in the wild.",
    "abuseipdb": "IP addresses reported for abusive behavior.",
    "urlhaus": "Malicious URLs reported by URLHaus."
}

def load_cti_data():
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load CTI data: {e}")
        return None

def write_markdown_file(filename, title, description, content_lines, include_description=True):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# {title}\n")
        f.write(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n")
        if include_description and description:
            f.write(f"{description}\n\n")
        f.write('\n'.join(content_lines))
        f.write('\n')
    print(f"✅ Generated {filename}")

def generate_reports(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    otx_lines = []
    for pulse in data.get('otx', []):
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        otx_lines.append(f"\n{pulse.get('description', '').strip()}\n")

    malshare_lines = []
    for sample in data.get('malshare', []):
        malshare_lines.append(f"- SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")

    abuse_lines = []
    for ip in data.get('abuseipdb', []):
        abuse_lines.append(f"- IP: {ip.get('ipAddress')} | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}")

    urlhaus_lines = []
    for entry in data.get('urlhaus', []):
        urlhaus_lines.append(f"- URL: {entry.get('url')}")

    # Write individual markdown files WITHOUT descriptions
    write_markdown_file("otx.md", "AlienVault OTX Pulses", DESCRIPTIONS["otx"], otx_lines, include_description=False)
    write_markdown_file("malshare.md", "Malshare Samples", DESCRIPTIONS["malshare"], malshare_lines, include_description=False)
    write_markdown_file("abuseipdb.md", "AbuseIPDB IP Reports", DESCRIPTIONS["abuseipdb"], abuse_lines, include_description=False)
    write_markdown_file("urlhaus.md", "URLHaus Malicious URLs", DESCRIPTIONS["urlhaus"], urlhaus_lines, include_description=False)

    # Generate index.md with descriptions in the link text
    index_lines = [
        "Welcome to your CTI Hub. Click below to view threat feeds:\n",
        f"- [OTX Pulses: {DESCRIPTIONS['otx']}](./otx.md)",
        f"- [Malshare Samples: {DESCRIPTIONS['malshare']}](./malshare.md)",
        f"- [AbuseIPDB IPs: {DESCRIPTIONS['abuseipdb']}](./abuseipdb.md)",
        f"- [URLHaus URLs: {DESCRIPTIONS['urlhaus']}](./urlhaus.md)",
    ]
    write_markdown_file("index.md", "Cyber Threat Intelligence Hub", "", index_lines, include_description=False)

if __name__ == "__main__":
    data = load_cti_data()
    if not data:
        exit(1)
    generate_reports(data)
