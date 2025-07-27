# AlienVault OTX Pulses
Generated on 2025-07-27 07:43 UTC

## Pulses contain threat indicators and context shared by researchers.

### SharePoint Vulnerabilities (CVE-2025-53770 & CVE-2025-53771): Everything You Need to Know
- Created: 2025-07-21T22:45:34.080000
- Author: AlienVault
- Description: Two critical zero-day vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are actively exploited in on-premises Microsoft SharePoint servers. These flaws enable unauthenticated remote code execution through an exploit chain dubbed ToolShell. CVE-2025-53770 is a critical RCE vulnerability caused by unsafe deserialization, while CVE-2025-53771 is a spoofing vulnerability allowing authentication bypass. The vulnerabilities affect SharePoint Server Subscription Edition, SharePoint Server 2019, and SharePoint Server 2016. Cloud-hosted self-managed SharePoint instances are also at risk. Exploitation has been observed since July 18, 2025, with attacks targeting sensitive data extraction and persistent remote access. Microsoft has released emergency patches, and organizations are urged to update immediately or implement workarounds if patching is not possible.

### Active Exploitation of Microsoft SharePoint Vulnerabilities
- Created: 2025-07-22T08:31:03.346000
- Author: AlienVault
- Description: Unit 42 is tracking ongoing threat activity targeting on-premises Microsoft SharePoint servers, particularly within government, schools, healthcare, and large enterprises. Multiple vulnerabilities (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) allow unauthenticated attackers to access restricted functionality and execute arbitrary commands. Active exploitation has been observed, with attackers bypassing identity controls, exfiltrating data, deploying backdoors, and stealing cryptographic keys. Affected organizations are urged to immediately disconnect vulnerable servers, apply patches, rotate cryptographic material, and engage professional incident response. The vulnerabilities impact SharePoint Enterprise Server 2016 and 2019, with some also affecting SharePoint Server Subscription Edition. Cloud-based SharePoint is not affected.

### CVE-2025-53770 and CVE-2025-53771: Actively Exploited SharePoint Vulnerabilities
- Created: 2025-07-22T09:04:10.561000
- Author: AlienVault
- Description: Two critical vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are affecting Microsoft SharePoint Servers, enabling attackers to upload malicious files and extract cryptographic secrets. These flaws are evolutions of previously patched vulnerabilities, CVE-2025-49704 and CVE-2025-49706, which were incompletely remediated. Exploit attempts have been observed across various industries, including finance, education, energy, and healthcare. Microsoft has released patches for SharePoint Subscription Edition and Server 2019, with a patch for Server 2016 pending. The vulnerabilities allow for unauthenticated remote code execution through advanced deserialization techniques and ViewState abuse. Active exploitation in the wild has been confirmed, compromising on-premises SharePoint environments globally.

### SharePoint ToolShell | Zero-Day Exploited in-the-Wild Targets Enterprise Servers
- Created: 2025-07-22T08:34:07.711000
- Author: AlienVault
- Description: A zero-day vulnerability dubbed 'ToolShell' targeting on-premises Microsoft SharePoint Servers has been actively exploited. The flaw, identified as CVE-2025-53770 with an accompanying bypass CVE-2025-53771, allows unauthenticated remote code execution. Three distinct attack clusters have been observed, each with unique tradecraft and objectives. Targets include organizations in technology consulting, manufacturing, critical infrastructure, and professional services. The exploitation enables access to SharePoint's ToolPane functionality without authentication, leading to code execution via uploaded or in-memory web components. Different webshells and techniques were employed, including a custom password-protected ASPX webshell and a reconnaissance utility targeting cryptographic material. Immediate patching and following Microsoft's recommendations are strongly advised.

### Phishing Campaign Targets Indian Defense Using Credential-Stealing Malware
- Created: 2025-06-21T14:51:24.557000
- Author: AlienVault
- Description: APT36, a Pakistan-based cyber espionage group, is actively targeting Indian defense personnel through sophisticated phishing campaigns. The group disseminates emails with malicious PDF attachments resembling official government documents. When opened, these PDFs display a blurred background and a button mimicking the National Informatics Centre login interface. Clicking the button redirects users to a fraudulent URL and initiates the download of a ZIP archive containing a malicious executable disguised as a legitimate application. This campaign highlights APT36's focus on credential theft and long-term infiltration of Indian defense networks, emphasizing the need for robust email security, user awareness programs, and proactive threat detection systems.
