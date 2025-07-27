import os
from datetime import datetime

OUTPUT_DIR = "../docs"

DESCRIPTIONS = {
    "otx": "Pulses from AlienVault's OTX platform containing IOCs and context on recent threats.",
    "malshare": "Hashes of malware binaries recently observed in the wild.",
    "urlhaus": "Recently submitted URLs identified as hosting malware or phishing content.",
    "threatfox": "Real-time indicators of compromise (IOCs) from abuse.ch's ThreatFox platform."
}

def write_markdown_file(filename, title, description, content_lines, include_description=True):
    path = os.path.join(OUTPUT_DIR, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)

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

    # OTX
    otx_lines = []
    for pulse in data.get('otx', [])[:50]:
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        desc = pulse.get('description', '').strip()
        if desc:
            otx_lines.append(f"\n{desc}\n")

    # Malshare
    malshare_lines = []
    for sample in data.get('malshare', [])[:50]:
        sha256 = sample.get('sha256', 'N/A')
        first_seen = sample.get('first_seen', 'N/A')
        malshare_lines.append(f"- **SHA256:** `{sha256}` | First Seen: {first_seen}")

    # URLHaus
    urlhaus_lines = []
    for entry in data.get('urlhaus', [])[:50]:
        url = entry.get('url')
        if url:
            urlhaus_lines.append(f"- {url}")

    # ThreatFox
    threatfox_lines = []
    threatfox_data = data.get('threatfox', [])
    if threatfox_data and isinstance(threatfox_data, list):
        if len(threatfox_data) > 0 and isinstance(threatfox_data[0], dict):
            for entry in threatfox_data[:50]:
                ioc = entry.get('ioc', 'N/A')
                threat_type = entry.get('threat_type', 'N/A')
                malware = entry.get('malware', 'N/A')
                threatfox_lines.append(f"- **IOC:** `{ioc}` | Type: {threat_type} | Malware: {malware}")
        else:
            threatfox_lines.append("*Warning: ThreatFox data items are not dicts.*")
    else:
        threatfox_lines.append("*No valid ThreatFox data found.*")

    # Write pages
    write_markdown_file("otx.md", "AlienVault OTX Pulses", DESCRIPTIONS["otx"], otx_lines, include_description=False)
    write_markdown_file("malshare.md", "Malshare Samples", DESCRIPTIONS["malshare"], malshare_lines, include_description=False)
    write_markdown_file("urlhaus.md", "URLHaus Malicious URLs", DESCRIPTIONS["urlhaus"], urlhaus_lines, include_description=False)
    write_markdown_file("threatfox.md", "ThreatFox IOCs", DESCRIPTIONS["threatfox"], threatfox_lines, include_description=False)

    # Homepage in pure Markdown
    index_lines = [
        "Welcome to your Cyber Threat Intelligence Hub.\n",
        "## Sources\n",
        f"### [OTX Pulses](./otx.md)\n{DESCRIPTIONS['otx']}\n",
        f"### [Malshare Samples](./malshare.md)\n{DESCRIPTIONS['malshare']}\n",
        f"### [URLHaus Malicious URLs](./urlhaus.md)\n{DESCRIPTIONS['urlhaus']}\n",
        f"### [ThreatFox IOCs](./threatfox.md)\n{DESCRIPTIONS['threatfox']}\n"
    ]
    write_markdown_file("index.md", "Cyber Threat Intelligence Hub", "", index_lines, include_description=False)

if __name__ == "__main__":
    import json
    DATA_FILE = "../cti_data.json"

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load CTI data: {e}")
        exit(1)

    generate_reports(data)
