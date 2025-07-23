import os
from datetime import datetime, timezone

# Paths
WEB_FEED_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'web_feed')
os.makedirs(WEB_FEED_DIR, exist_ok=True)

# Example dummy data; replace with your actual CTI data source
cti_data = [
    {
        'title': 'SharePoint Vulnerabilities (CVE-2025-53770 & CVE-2025-53771)',
        'created': '2025-07-21T22:45:34.080000',
        'author': 'AlienVault',
        'description': 'Two critical zero-day vulnerabilities, ...'
    },
    # add more items here...
]

def generate_markdown_report(data):
    md_lines = ["# Cyber Threat Intelligence Feed\n"]
    md_lines.append(f"Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n")

    for item in data:
        md_lines.append(f"## {item['title']}\n")
        md_lines.append(f"**Created:** {item['created']}\n")
        md_lines.append(f"**Author:** {item['author']}\n\n")
        md_lines.append(f"{item['description']}\n\n")
        md_lines.append("---\n\n")

    return ''.join(md_lines)

def generate_html_report(data):
    html_lines = [
        "<html><head><title>Cyber Threat Intelligence Feed</title></head><body>",
        f"<p>Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>",
        "<h1>Cyber Threat Intelligence Feed</h1>"
    ]

    for item in data:
        html_lines.append(f"<h2>{item['title']}</h2>")
        html_lines.append(f"<p><strong>Created:</strong> {item['created']}<br>")
        html_lines.append(f"<strong>Author:</strong> {item['author']}</p>")
        html_lines.append(f"<p>{item['description']}</p>")
        html_lines.append("<hr>")

    html_lines.append("</body></html>")
    return ''.join(html_lines)

def save_report(filename, content):
    path = os.path.join(WEB_FEED_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Saved report: {path}")

if __name__ == "__main__":
    md_report = generate_markdown_report(cti_data)
    html_report = generate_html_report(cti_data)

    save_report('cti_feed.md', md_report)
    save_report('cti_feed.html', html_report)
