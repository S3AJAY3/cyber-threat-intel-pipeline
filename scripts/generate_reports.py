import os
from datetime import datetime

OUTPUT_DIR = "../docs"

# Descriptions for homepage tiles
DESCRIPTIONS = {
    "otx": "Pulses from AlienVault's OTX platform containing IOCs and context on recent threats.",
    "malshare": "Hashes of malware binaries recently observed in the wild.",
    "urlhaus": "Recently submitted URLs identified as hosting malware or phishing content."
}

def write_markdown_file(filename, title, description, content_lines, include_description=True):
    """
    Writes a nicely formatted markdown file with optional description and content lines.
    """
    path = os.path.join(OUTPUT_DIR, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)  # Ensure dir exists

    with open(path, 'w', encoding='utf-8') as f:
        # Header and timestamp
        f.write(f"# {title}\n")
        f.write(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n")
        # Description if wanted
        if include_description and description:
            f.write(f"{description}\n\n")
        # Content with spacing
        f.write('\n'.join(content_lines))
        f.write('\n')
    print(f"✅ Generated {filename}")

def generate_reports(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # AlienVault OTX Pulses (limit 50)
    otx_lines = []
    for pulse in data.get('otx', [])[:50]:
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        desc = pulse.get('description', '').strip()
        if desc:
            otx_lines.append(f"\n{desc}\n")

    # Malshare Samples (limit 50)
    malshare_lines = []
    for sample in data.get('malshare', [])[:50]:
        sha256 = sample.get('sha256', 'N/A')
        first_seen = sample.get('first_seen', 'N/A')
        malshare_lines.append(f"- **SHA256:** `{sha256}` | First Seen: {first_seen}")

    # URLHaus URLs (limit 50)
    urlhaus_lines = []
    for entry in data.get('urlhaus', [])[:50]:
        url = entry.get('url')
        if url:
            urlhaus_lines.append(f"- [URLHaus Link]({url})")

    # Write individual pages (no descriptions on pages)
    write_markdown_file("otx.md", "AlienVault OTX Pulses", DESCRIPTIONS.get("otx", ""), otx_lines, include_description=False)
    write_markdown_file("malshare.md", "Malshare Samples", DESCRIPTIONS.get("malshare", ""), malshare_lines, include_description=False)
    write_markdown_file("urlhaus.md", "URLHaus Malicious URLs", DESCRIPTIONS.get("urlhaus", ""), urlhaus_lines, include_description=False)

    # Homepage with spread-out links and descriptions (not list)
    index_lines = [
        "Welcome to your Cyber Threat Intelligence Hub.",
        "",
        "<div style='display: flex; justify-content: space-around; flex-wrap: wrap;'>",
        f"<div style='flex: 1; margin: 1rem; min-width: 250px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px;'>",
        f"### [OTX Pulses](./otx.md)",
        f"<p>{DESCRIPTIONS.get('otx', '')}</p>",
        "</div>",
        f"<div style='flex: 1; margin: 1rem; min-width: 250px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px;'>",
        f"### [Malshare Samples](./malshare.md)",
        f"<p>{DESCRIPTIONS.get('malshare', '')}</p>",
        "</div>",
        f"<div style='flex: 1; margin: 1rem; min-width: 250px; padding: 1rem; border: 1px solid #ddd; border-radius: 8px;'>",
        f"### [URLHaus URLs](./urlhaus.md)",
        f"<p>{DESCRIPTIONS.get('urlhaus', '')}</p>",
        "</div>",
        "</div>",
    ]

    # Write homepage index.md
    write_markdown_file("index.md", "Cyber Threat Intelligence Hub", "", index_lines, include_description=False)

if __name__ == "__main__":
    import json
    DATA_FILE = "../cti_data.json"

    # Load CTI data JSON
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load CTI data: {e}")
        exit(1)

    generate_reports(data)
