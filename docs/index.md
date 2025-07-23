# Cyber Threat Intelligence Feed

Generated on 2025-07-23 07:52 UTC


## AlienVault OTX Pulses

### SharePoint Vulnerabilities (CVE-2025-53770 & CVE-2025-53771): Everything You Need to Know
- Created: 2025-07-21T22:45:34.080000
- Author: AlienVault

Two critical zero-day vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are actively exploited in on-premises Microsoft SharePoint servers. These flaws enable unauthenticated remote code execution through an exploit chain dubbed ToolShell. CVE-2025-53770 is a critical RCE vulnerability caused by unsafe deserialization, while CVE-2025-53771 is a spoofing vulnerability allowing authentication bypass. The vulnerabilities affect SharePoint Server Subscription Edition, SharePoint Server 2019, and SharePoint Server 2016. Cloud-hosted self-managed SharePoint instances are also at risk. Exploitation has been observed since July 18, 2025, with attacks targeting sensitive data extraction and persistent remote access. Microsoft has released emergency patches, and organizations are urged to update immediately or implement workarounds if patching is not possible.

### Active Exploitation of Microsoft SharePoint Vulnerabilities
- Created: 2025-07-22T08:31:03.346000
- Author: AlienVault

Unit 42 is tracking ongoing threat activity targeting on-premises Microsoft SharePoint servers, particularly within government, schools, healthcare, and large enterprises. Multiple vulnerabilities (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) allow unauthenticated attackers to access restricted functionality and execute arbitrary commands. Active exploitation has been observed, with attackers bypassing identity controls, exfiltrating data, deploying backdoors, and stealing cryptographic keys. Affected organizations are urged to immediately disconnect vulnerable servers, apply patches, rotate cryptographic material, and engage professional incident response. The vulnerabilities impact SharePoint Enterprise Server 2016 and 2019, with some also affecting SharePoint Server Subscription Edition. Cloud-based SharePoint is not affected.

### CVE-2025-53770 and CVE-2025-53771: Actively Exploited SharePoint Vulnerabilities
- Created: 2025-07-22T09:04:10.561000
- Author: AlienVault

Two critical vulnerabilities, CVE-2025-53770 and CVE-2025-53771, are affecting Microsoft SharePoint Servers, enabling attackers to upload malicious files and extract cryptographic secrets. These flaws are evolutions of previously patched vulnerabilities, CVE-2025-49704 and CVE-2025-49706, which were incompletely remediated. Exploit attempts have been observed across various industries, including finance, education, energy, and healthcare. Microsoft has released patches for SharePoint Subscription Edition and Server 2019, with a patch for Server 2016 pending. The vulnerabilities allow for unauthenticated remote code execution through advanced deserialization techniques and ViewState abuse. Active exploitation in the wild has been confirmed, compromising on-premises SharePoint environments globally.

### SharePoint ToolShell | Zero-Day Exploited in-the-Wild Targets Enterprise Servers
- Created: 2025-07-22T08:34:07.711000
- Author: AlienVault

A zero-day vulnerability dubbed 'ToolShell' targeting on-premises Microsoft SharePoint Servers has been actively exploited. The flaw, identified as CVE-2025-53770 with an accompanying bypass CVE-2025-53771, allows unauthenticated remote code execution. Three distinct attack clusters have been observed, each with unique tradecraft and objectives. Targets include organizations in technology consulting, manufacturing, critical infrastructure, and professional services. The exploitation enables access to SharePoint's ToolPane functionality without authentication, leading to code execution via uploaded or in-memory web components. Different webshells and techniques were employed, including a custom password-protected ASPX webshell and a reconnaissance utility targeting cryptographic material. Immediate patching and following Microsoft's recommendations are strongly advised.

### Phishing Campaign Targets Indian Defense Using Credential-Stealing Malware
- Created: 2025-06-21T14:51:24.557000
- Author: AlienVault

APT36, a Pakistan-based cyber espionage group, is actively targeting Indian defense personnel through sophisticated phishing campaigns. The group disseminates emails with malicious PDF attachments resembling official government documents. When opened, these PDFs display a blurred background and a button mimicking the National Informatics Centre login interface. Clicking the button redirects users to a fraudulent URL and initiates the download of a ZIP archive containing a malicious executable disguised as a legitimate application. This campaign highlights APT36's focus on credential theft and long-term infiltration of Indian defense networks, emphasizing the need for robust email security, user awareness programs, and proactive threat detection systems.


## Malshare Samples

These are hashes of malware samples recently discovered and catalogued by Malshare, a repository of malware binaries.

- **SHA256:** This is a unique digital fingerprint for each malware file. Security analysts use these hashes to identify and share malware samples without distributing the actual malicious files.
- **First Seen:** Indicates when the sample was first detected (if available).

**How to use this info:**  
If you have malware detection tools or threat intelligence platforms, you can use these SHA256 hashes to check if any of these malware samples have been seen on your network or systems. It helps identify infections or threats by matching known malware signatures.

- SHA256: 4120c0d497c549ec197736bf193ce7d711465cf1a8fd20e7c4077b668564567b | First Seen: N/A
- SHA256: 92e41e62963fbe8c20ad7bcf78318b358b4032645a087491ae4be1e9a532338d | First Seen: N/A
- SHA256: cfad481c61b1af742ba2aec8b90ef994a40e3a899427dceafd8b931f87878931 | First Seen: N/A
- SHA256: eb1f569eea745b58219b796bf24be05a0682b1554a14e5ddc0a52c844f46f8bb | First Seen: N/A
- SHA256: bb45035bedf8608e9269810c88c32556559ff5e869f8685cd2bebb36d6ea3bd3 | First Seen: N/A


## AbuseIPDB Blacklisted IPs

This section lists IP addresses reported for malicious activity and flagged by AbuseIPDB, a collaborative threat intelligence platform.

- These IPs are linked to activities like scanning, hacking attempts, spamming, or distributing malware.
- The "confidence score" reflects how reliably the IP is considered abusive based on reports.

**How to use this info:**  
Network defenders can block or monitor traffic to and from these IP addresses to reduce the risk of attacks. If you see connections involving these IPs, consider investigating them promptly.



## URLHaus Malicious URLs

URLHaus tracks URLs that host malware or phishing pages.

- These URLs are known to distribute malicious payloads or trick users into giving up sensitive data.
- Attackers often use these URLs in phishing emails or drive-by-download attacks.

**How to use this info:**  
Security teams can block these URLs at the network or browser level to prevent access. Users should never click on suspicious links like these, and email gateways can be configured to flag messages containing such URLs.

- URL: http://94.50.255.123:60829/bin.sh
- URL: http://120.61.250.19:52990/i
- URL: http://103.188.83.28/harm5
- URL: http://103.188.83.28/toto
- URL: http://103.188.83.28/tplink.sh
