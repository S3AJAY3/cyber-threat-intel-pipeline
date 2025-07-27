import json
from datetime import datetime
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'cti_data.json')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs')

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

def format_with_layout(title, body_lines):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    body = '\n'.join(body_lines)
    return f"""<div class="page-wrapper">

<h1>{title}</h1>
<p class="timestamp">Generated on {timestamp}</p>

{body}

</div>

<script>
const toggleTheme = () => {{
  document.body.classList.toggle('dark-mode');
}};
</script>

<style>
body {{
  font-family: 'Segoe UI', sans-serif;
  margin: 2rem;
  color: #222;
  background: #fff;
  transition: background 0.3s, color 0.3s;
}}
.dark-mode {{
  background: #121212;
  color: #ddd;
}}
.page-wrapper {{
  max-width: 900px;
  margin: auto;
}}
.timestamp {{
  color: gray;
  font-size: 0.9em;
  margin-bottom: 1.5em;
}}
h1 {{
  font-size: 2em;
  margin-bottom: 0.3em;
}}
pre, code {{
  background-color: #f6f8fa;
  padding: 0.5em;
  display: block;
  border-radius: 6px;
  overflow-x: auto;
}}
a {{
  color: #0366d6;
  text-decoration: none;
}}
a:hover {{
  text-decoration: underline;
}}
button {{
  position: fixed;
  top: 1rem;
  right: 1rem;
  background: #0366d6;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  z-index: 1000;
}}
</style>

<button onclick="toggleTheme()">🌓 Toggle Theme</button>
"""

def write_html_markdown(filename, title, content_lines):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        html = format_with_layout(title, content_lines)
        f.write(html)
    print(f"✅ Generated {filename}")

def generate_reports(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    otx_lines = []
    for pulse in data.get('otx', []):
        otx_lines.append(f"### {pulse.get('name')}")
        otx_lines.append(f"- Created: {pulse.get('created')}")
        otx_lines.append(f"- Author: {pulse.get('author_name')}")
        otx_lines.append(f"<p>{pulse.get('description', '').strip()}</p>")

    malshare_lines = [
        f"- SHA256: {s.get('sha256', 'N/A')} | First Seen: {s.get('first_seen', 'N/A')}"
        for s in data.get('malshare', [])
    ]

    abuse_lines = [
        f"- IP: {ip.get('ipAddress')} | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}"
        for ip in data.get('abuseipdb', [])
    ]

    urlhaus_lines = [
        f"- URL: {entry.get('url')}"
        for entry in data.get('urlhaus', [])
    ]

    write_html_markdown("otx.md", "👽 AlienVault OTX Pulses", otx_lines)
    write_html_markdown("malshare.md", "🧬 Malshare Samples", malshare_lines)
    write_html_markdown("abuseipdb.md", "🚨 AbuseIPDB IP Reports", abuse_lines)
    write_html_markdown("urlhaus.md", "🌐 URLHaus Malicious URLs", urlhaus_lines)

    index_html = format_with_layout("🧠 Cyber Threat Intelligence Hub", [
        "Welcome to your personal CTI hub — your command center for monitoring fresh cyber threat intelligence from public sources.",
        "<hr>",
        "<table>",
        "  <tr>",
        "    <td><a href='./otx.md'><strong>👽 AlienVault OTX</strong><br/><em>{}</em></a></td>".format(DESCRIPTIONS['otx']),
        "    <td><a href='./malshare.md'><strong>🧬 Malshare</strong><br/><em>{}</em></a></td>".format(DESCRIPTIONS['malshare']),
        "  </tr>",
        "  <tr>",
        "    <td><a href='./abuseipdb.md'><strong>🚨 AbuseIPDB</strong><br/><em>{}</em></a></td>".format(DESCRIPTIONS['abuseipdb']),
        "    <td><a href='./urlhaus.md'><strong>🌐 URLHaus</strong><br/><em>{}</em></a></td>".format(DESCRIPTIONS['urlhaus']),
        "  </tr>",
        "</table>",
        "<hr>",
        "<p><strong>Coming soon:</strong></p>",
        "<ul>",
        "<li>📄 Blog posts & incident analysis</li>",
        "<li>💼 Resume and project portfolio</li>",
        "<li>🛠 Tools and OSINT resources</li>",
        "</ul>"
    ])
    with open(os.path.join(OUTPUT_DIR, "index.md"), 'w', encoding='utf-8') as f:
        f.write(index_html)
    print("✅ Generated index.md")

if __name__ == "__main__":
    data = load_cti_data()
    if not data:
        exit(1)
    generate_reports(data)
