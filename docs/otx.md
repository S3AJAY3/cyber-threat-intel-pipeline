<div class="page-wrapper">

<h1>👽 AlienVault OTX Pulses</h1>
<p class="timestamp">Generated on 2025-07-27 08:44 UTC</p>

### SharePoint Vulnerabilities (CVE-2025-53770 & CVE-2025-53771): Everything You Need to Know
- Created: 2025-07-21T22:45:34.080000
- Author: AlienVault
<p>Two critical zero-day vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are actively exploited in on-premises Microsoft SharePoint servers. These flaws enable unauthenticated remote code execution through an exploit chain dubbed ToolShell. CVE-2025-53770 is a critical RCE vulnerability caused by unsafe deserialization, while CVE-2025-53771 is a spoofing vulnerability allowing authentication bypass. The vulnerabilities affect SharePoint Server Subscription Edition, SharePoint Server 2019, and SharePoint Server 2016. Cloud-hosted self-managed SharePoint instances are also at risk. Exploitation has been observed since July 18, 2025, with attacks targeting sensitive data extraction and persistent remote access. Microsoft has released emergency patches, and organizations are urged to update immediately or implement workarounds if patching is not possible.</p>
### Active Exploitation of Microsoft SharePoint Vulnerabilities
- Created: 2025-07-22T08:31:03.346000
- Author: AlienVault
<p>Unit 42 is tracking ongoing threat activity targeting on-premises Microsoft SharePoint servers, particularly within government, schools, healthcare, and large enterprises. Multiple vulnerabilities (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) allow unauthenticated attackers to access restricted functionality and execute arbitrary commands. Active exploitation has been observed, with attackers bypassing identity controls, exfiltrating data, deploying backdoors, and stealing cryptographic keys. Affected organizations are urged to immediately disconnect vulnerable servers, apply patches, rotate cryptographic material, and engage professional incident response. The vulnerabilities impact SharePoint Enterprise Server 2016 and 2019, with some also affecting SharePoint Server Subscription Edition. Cloud-based SharePoint is not affected.</p>
### CVE-2025-53770 and CVE-2025-53771: Actively Exploited SharePoint Vulnerabilities
- Created: 2025-07-22T09:04:10.561000
- Author: AlienVault
<p>Two critical vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are affecting Microsoft SharePoint Servers, enabling attackers to upload malicious files and extract cryptographic secrets. These flaws are evolutions of previously patched vulnerabilities, CVE-2025-49704 and CVE-2025-49706, which were incompletely remediated. Exploit attempts have been observed across various industries, including finance, education, energy, and healthcare. Microsoft has released patches for SharePoint Subscription Edition and Server 2019, with a patch for Server 2016 pending. The vulnerabilities allow for unauthenticated remote code execution through advanced deserialization techniques and ViewState abuse. Active exploitation in the wild has been confirmed, compromising on-premises SharePoint environments globally.</p>
### SharePoint ToolShell | Zero-Day Exploited in-the-Wild Targets Enterprise Servers
- Created: 2025-07-22T08:34:07.711000
- Author: AlienVault
<p>A zero-day vulnerability dubbed 'ToolShell' targeting on-premises Microsoft SharePoint Servers has been actively exploited. The flaw, identified as CVE-2025-53770 with an accompanying bypass CVE-2025-53771, allows unauthenticated remote code execution. Three distinct attack clusters have been observed, each with unique tradecraft and objectives. Targets include organizations in technology consulting, manufacturing, critical infrastructure, and professional services. The exploitation enables access to SharePoint's ToolPane functionality without authentication, leading to code execution via uploaded or in-memory web components. Different webshells and techniques were employed, including a custom password-protected ASPX webshell and a reconnaissance utility targeting cryptographic material. Immediate patching and following Microsoft's recommendations are strongly advised.</p>
### Phishing Campaign Targets Indian Defense Using Credential-Stealing Malware
- Created: 2025-06-21T14:51:24.557000
- Author: AlienVault
<p>APT36, a Pakistan-based cyber espionage group, is actively targeting Indian defense personnel through sophisticated phishing campaigns. The group disseminates emails with malicious PDF attachments resembling official government documents. When opened, these PDFs display a blurred background and a button mimicking the National Informatics Centre login interface. Clicking the button redirects users to a fraudulent URL and initiates the download of a ZIP archive containing a malicious executable disguised as a legitimate application. This campaign highlights APT36's focus on credential theft and long-term infiltration of Indian defense networks, emphasizing the need for robust email security, user awareness programs, and proactive threat detection systems.</p>

</div>

<script>
const toggleTheme = () => {
  document.body.classList.toggle('dark-mode');
};
</script>

<style>
body {
  font-family: 'Segoe UI', sans-serif;
  margin: 2rem;
  color: #222;
  background: #fff;
  transition: background 0.3s, color 0.3s;
}
.dark-mode {
  background: #121212;
  color: #ddd;
}
.page-wrapper {
  max-width: 900px;
  margin: auto;
}
.timestamp {
  color: gray;
  font-size: 0.9em;
  margin-bottom: 1.5em;
}
h1 {
  font-size: 2em;
  margin-bottom: 0.3em;
}
pre, code {
  background-color: #f6f8fa;
  padding: 0.5em;
  display: block;
  border-radius: 6px;
  overflow-x: auto;
}
a {
  color: #0366d6;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
button {
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
}
</style>

<button onclick="toggleTheme()">🌓 Toggle Theme</button>
