# AlienVault OTX Pulses
Generated on 2025-07-27 14:59 UTC

### Dissecting Kimsuky's Attacks on South Korea: In-Depth Analysis of GitHub-Based Malicious Infrastructure
- Created: 2025-06-26T21:22:20.376000
- Author: AlienVault

A sophisticated spearphishing campaign targeting South Korea has been uncovered, utilizing GitHub as attack infrastructure. The threat actor, linked to the North Korean group Kimsuky, created multiple private repositories to store malware, decoy files, and exfiltrated victim data. The attack leveraged GitHub Personal Access Tokens to access private repositories and distribute XenoRAT malware. The campaign also employed Dropbox for malware distribution. The attackers used tailored decoy documents and impersonated legitimate entities to increase the effectiveness of their phishing attempts. Analysis of the infrastructure and malware samples revealed connections to previous Kimsuky operations, including shared test IP addresses and similar malware build environments.

### Checking all the Boxes: LapDogs, The New ORB in Town
- Created: 2025-06-26T21:14:47.499000
- Author: AlienVault

SecurityScorecard's STRIKE team has uncovered a new China-Nexus Operational Relay Box (ORB) network called 'LapDogs', targeting primarily Linux-based SOHO devices globally. The network, active since September 2023, focuses on the United States and Southeast Asia, particularly Japan, South Korea, Hong Kong, and Taiwan. LapDogs employs a custom backdoor named 'ShortLeash', which establishes footholds on compromised devices and connects them within the network. Over 1,000 actively infected nodes have been identified, revealing geographical targeting patterns indicative of structured tasking. The research highlights the network's gradual growth, methodical operation, and distinct intrusion sets, setting it apart from opportunistic botnets. Victimology analysis reveals affected ISPs, hardware vendors, and organizations in IT, networking, real estate, and media sectors.

### Iranian Educated Manticore Targets Leading Tech Academics
- Created: 2025-06-26T21:01:42.866000
- Author: AlienVault

The Iranian threat group Educated Manticore, associated with the Islamic Revolutionary Guard Corps, has launched spear-phishing campaigns targeting Israeli journalists, cyber security experts and computer science professors. The attackers posed as fictitious assistants to technology executives or researchers, directing victims to fake Gmail login pages or Google Meet invitations. This allowed them to intercept passwords and 2FA codes, gaining unauthorized access to victims' accounts. The group used a custom phishing kit implemented as a Single Page Application built with React, supporting various Google authentication flows and enabling 2FA relay attacks. The infrastructure relied on over 130 unique domains resolving to multiple IP addresses. Despite increased exposure, Educated Manticore continues to pose a persistent threat, particularly to individuals in Israel during the Iran-Israel conflict escalation.

### Dropping Elephant APT Group Targets Turkish Defense Industry With New Campaign and Capabilities: LOLBAS, VLC Player, and Encrypted Shellcode
- Created: 2025-07-23T23:31:17.334000
- Author: AlienVault

The Arctic Wolf Labs team has uncovered a new cyber-espionage campaign by the Dropping Elephant APT group targeting Turkish defense contractors. The attack leverages a five-stage execution chain delivered via malicious LNK files disguised as conference invitations. It uses legitimate binaries like VLC Media Player for defense evasion through DLL side-loading. The campaign demonstrates an evolution in the group's capabilities, transitioning from x64 DLL variants to x86 PE executables with enhanced command structures. The timing coincides with increased Turkey-Pakistan defense cooperation amid India-Pakistan tensions, suggesting geopolitical motives. The attack chain includes social engineering, PowerShell scripting, file obfuscation, and a custom remote access trojan for intelligence gathering.

### Android Malware Posing As Indian Bank Apps
- Created: 2025-07-25T10:29:03.334000
- Author: AlienVault

This report analyzes a sophisticated Android malware targeting Indian banking apps. The malware uses a dropper and main payload structure, leveraging permissions like SMS access and silent installation to steal credentials, intercept messages, and perform unauthorized financial activities. It employs Firebase for command and control, phishing pages to mimic banking interfaces, and techniques like call forwarding abuse. The malware's modular architecture, evasion tactics, and persistence mechanisms pose significant threats to mobile banking security. Distribution methods include smishing, fake websites, and malvertising. The report provides detailed static and dynamic analysis, highlighting the malware's capabilities in data exfiltration, debit card harvesting, and remote command execution.

### Threat Actors Lure Victims Into Downloading .HTA Files Using ClickFix To Spread Epsilon Red Ransomware
- Created: 2025-07-25T10:29:02.823000
- Author: AlienVault

A new Epsilon Red ransomware campaign has been discovered targeting users globally through fake ClickFix verification pages. Active since July 2025, the threat actors employ social engineering tactics and impersonate popular platforms like Discord, Twitch, and OnlyFans to trick users into executing malicious .HTA files via ActiveX. This method leads to silent payload downloads and ransomware deployment. The campaign uses a Clickfix-themed malware delivery site, urging victims to visit a secondary page where malicious shell commands are executed. The attackers also impersonate various streaming services and use romance-themed lures. Epsilon Red, first observed in 2021, shows some similarities to REvil ransomware in its ransom note styling but appears distinct in its tactics and infrastructure.

### AI-Generated Malware in Panda Image Hides Persistent Linux Threat
- Created: 2025-07-24T19:44:45.249000
- Author: AlienVault

A sophisticated Linux malware campaign called Koske has been discovered, showing signs of AI-assisted development. The threat exploits misconfigured servers to install backdoors and download weaponized JPEG images containing malicious payloads. The malware uses polyglot file abuse to hide shellcode within images, deploys a userland rootkit, and employs various persistence techniques. It aggressively manipulates network settings to ensure command-and-control communication. The malware supports 18 different cryptocurrencies and adapts its mining strategy based on the host's capabilities. The code structure and adaptability suggest AI involvement in its creation, marking a concerning shift in malware development and posing significant challenges for cybersecurity defenses.

### Novel Use of "mount" Spotted in Hikvision Attacks
- Created: 2025-07-24T19:44:44.622000
- Author: AlienVault

Attackers are exploiting CVE-2021-36260, a command injection vulnerability in Hikvision devices, using a novel technique involving the 'mount' command as a GTFOBin. This method allows them to mount a remote NFS share and execute malicious files, bypassing common network signatures. The technique has been added to VulnCheck's go-exploit framework. The attacks originate from specific IP addresses and utilize Mirai-like payloads. Over one million potentially vulnerable internet-facing targets are still exposed, making this exploit highly viable for internal pivots or building proxy networks. Advanced threat actors like Flax Typhoon and Fancy Bear have been associated with exploiting this vulnerability.

### Pausing for a "Sanctuary Moon" marathon
- Created: 2025-07-24T19:44:43.991000
- Author: AlienVault

This newsletter discusses the debut of the 'Humans of Talos' series, which highlights the people behind Cisco Talos' research and operations. It draws parallels between sci-fi characters and cybersecurity professionals, emphasizing the importance of human creativity and insight in advanced technology. The newsletter also mentions a new ransomware-as-a-service group called Chaos, which is actively targeting organizations worldwide. It provides updates on recent security incidents, including a Microsoft SharePoint vulnerability and a crypto exchange hack. The author stresses the significance of human elements in cybersecurity, despite the increasing use of machine learning.

### Gunra Ransomware Emerges with New DLS
- Created: 2025-07-24T11:30:32.766000
- Author: AlienVault

A new ransomware group called Gunra has emerged with a Dedicated Leak Site (DLS) in April 2025. Gunra's code shows similarities to the infamous Conti ransomware, suggesting it may be leveraging Conti's leaked source code. The group employs aggressive tactics, including a time-based pressure technique that forces victims to begin negotiations within five days. Gunra ransomware encrypts files using a combination of RSA and ChaCha20 algorithms, excludes certain folders and file types from encryption, and drops a ransom note named 'R3ADM3.txt'. The ransomware also deletes volume shadow copies to hinder recovery efforts. As the threat of DLS ransomware grows, organizations are advised to implement robust security measures, including regular updates, backups, and user education.

### Infrastructure of Interest: Suspicious Domains
- Created: 2025-07-17T10:23:31.597000
- Author: AlienVault

Domains identified by an automated threat monitoring infrastructure, which leverages advanced AI-driven analysis to detect anomalous and high-risk activity.

### Defending Against ToolShell: SharePoint's Latest Critical Vulnerability
- Created: 2025-07-23T23:31:18.617000
- Author: AlienVault

A critical zero-day vulnerability named ToolShell (CVE-2025-53770) has been discovered in on-premises SharePoint Server deployments. This vulnerability allows unauthenticated remote code execution, posing a significant threat to organizations worldwide. SentinelOne has detected active exploitation and provides defensive measures. ToolShell's severity is characterized by its zero-day status, high CVSS score of 9.8, no authentication requirement, and remote code execution capability. SentinelOne's defense strategy includes early identification, out-of-the-box detection logic, IOC integration, hunting queries, and proactive detection through Singularity Vulnerability Management. Recommended mitigation steps include isolating SharePoint instances, enabling AMSI, applying patches, integrating IOCs, monitoring for suspicious behavior, and conducting retroactive threat hunting.

### A Special Mission to Nowhere
- Created: 2025-07-23T23:31:20.466000
- Author: AlienVault

A phishing campaign exploiting the aftermath of a military conflict between Israel and Iran has been identified. The scam, using a fake domain 'lineageembraer.online', offers evacuation flights from Tel Aviv to New York on an Embraer Lineage 1000E business jet. The website presents unrealistic pricing and logistical details, aiming to steal personal and financial information from individuals seeking to flee the region. The operation uses fear and urgency tactics, offering seats at $2,166 USD, significantly below market rates for similar flights. The scheme involves a PDF with instructions hosted on a Shopify CDN, raising further suspicions. The campaign demonstrates how threat actors exploit crisis situations to target vulnerable individuals.

### Active Exploitation of Microsoft SharePoint Vulnerabilities: Threat Brief
- Created: 2025-07-23T23:31:20.859000
- Author: AlienVault

Several critical vulnerabilities in Microsoft SharePoint are being actively exploited, targeting on-premises servers in government, education, healthcare, and large enterprises. The vulnerabilities allow unauthenticated attackers to bypass security controls and gain privileged access, leading to data exfiltration and backdoor deployment. Immediate actions recommended include patching, disconnecting vulnerable servers, rotating cryptographic material, and engaging professional incident response. Multiple variations of exploitation have been observed, involving command execution and web shell creation. Palo Alto Networks products offer various protections against these threats, including detection and blocking capabilities.

### Multiplatform Cryptomining Campaign Uses Fake Error Pages to Hide Payload
- Created: 2025-07-24T08:26:43.473000
- Author: AlienVault

A new iteration of a broad cryptomining campaign, dubbed Soco404, has been identified. The attackers exploit vulnerabilities in cloud environments, particularly targeting PostgreSQL misconfigurations, to deploy cryptominers on both Linux and Windows systems. They use process masquerading, achieve persistence via cron jobs and shell initialization files, and rely on compromised legitimate servers for malware hosting. The malware communicates via local sockets and embeds payloads in fake 404 HTML pages on Google Sites. The campaign is part of a larger crypto-scam infrastructure, demonstrating a versatile and opportunistic operation. The attackers use multiple ingress tools and target various entry points, showing a flexible approach to maximize reach and persistence across diverse targets.

### Operation Cargotalon: Targeting Russian Aerospace Defense Using Eaglet Implant
- Created: 2025-07-24T05:49:44.274000
- Author: AlienVault

UNG0901, a threat group targeting Russian aerospace and defense sectors, has been discovered conducting a spear-phishing campaign against the Voronezh Aircraft Production Association. The operation, dubbed 'CargoTalon', utilizes a custom DLL implant called EAGLET, which is disguised as a ZIP file containing transport documents. The infection chain involves a malicious LNK file that executes the EAGLET implant, which then establishes communication with a command-and-control server for remote access and data exfiltration. The campaign employs sophisticated tactics, including decoy documents related to Russian logistics operations, and shows similarities with another threat group known as Head Mare. The attackers' motivation appears to be espionage against Russian governmental and non-governmental entities.

### DRAT V2: Updated DRAT Emerges in Arsenal
- Created: 2025-06-23T18:23:18.071000
- Author: AlienVault

TAG-140, a threat actor group overlapping with SideCopy, has deployed an updated version of their DRAT remote access trojan, dubbed DRAT V2. This new variant, developed in Delphi, introduces enhanced command and control capabilities, including arbitrary shell command execution and improved C2 obfuscation techniques. The malware was distributed through a ClickFix-style social engineering attack, using a cloned Indian Ministry of Defence press portal. DRAT V2 demonstrates TAG-140's ongoing refinement of their tooling and their continued focus on Indian government and defense targets.

### Illusory Wishes: China-nexus APT Targets the Tibetan Community
- Created: 2025-07-23T15:42:22.517000
- Author: AlienVault

Two cyberattack campaigns, Operation GhostChat and Operation PhantomPrayers, targeted the Tibetan community in June 2025, coinciding with the Dalai Lama's 90th birthday. These attacks involved strategic web compromises, DLL sideloading, and multi-stage infection chains to deploy Ghost RAT and PhantomNet backdoors. The attackers used social engineering tactics, impersonating legitimate platforms and leveraging culturally significant events to lure victims. Both campaigns employed sophisticated evasion techniques, including code injection and API hook bypassing. The attacks are attributed to China-nexus APT groups based on victimology, malware used, and employed tactics. The campaigns highlight the ongoing cyber threats faced by the Tibetan community and the evolving tactics of state-sponsored threat actors.

### Malware Analysis Report: UMBRELLA STAND - Malware targeting Fortinet devices
- Created: 2025-06-23T11:34:33.626000
- Author: AlienVault

UMBRELLA STAND is a sophisticated malware targeting FortiGate 100D series firewalls produced by Fortinet. It contains remote shell execution functionality, configurable beacon frequency, and AES-encrypted C2 communications. The malware uses fake TLS on port 443 to beacon to its C2 server and has the ability to run shell commands. It employs various defense evasion techniques such as hidden folders, generic filenames, and string encryption. UMBRELLA STAND also has persistence mechanisms through reboot hooking and ldpreload. Associated tooling includes BusyBox, nbtscan, tcpdump, and openLDAP. The malware demonstrates operational security considerations and shares similarities with previously reported COATHANGER malware.

### NET RFQ: Request for Quote Scammers Casting Wide Net to Steal Real Goods
- Created: 2025-07-23T08:02:21.339000
- Author: AlienVault

This intelligence analysis examines a widespread Request for Quote (RFQ) scam that exploits Net financing options to steal high-value electronics and goods. The scammers pose as procurement agents for legitimate companies, using stolen information and lookalike domains to appear credible. They request quotes for specific items and inquire about Net 15/30/45-day financing. Once credit is approved, they provide shipping addresses, often using freight forwarding services or residential addresses. The scammers utilize a network of shipping services, warehouses, and money mules to facilitate their operations. Key characteristics of the scam include urgent financing requests, suspicious delivery addresses, and the use of free email accounts. Mitigation efforts included domain takedowns and intercepting fraudulent shipments.

### Back to Business: Lumma Stealer Returns with Stealthier Methods
- Created: 2025-07-23T07:57:59.897000
- Author: AlienVault

Lumma Stealer, an information-stealing malware, has resurfaced shortly after its takedown in May 2025. The cybercriminals behind it are now employing more covert tactics and expanding their reach. The malware is being distributed through discreet channels and uses stealthier evasion techniques. Lumma Stealer can steal sensitive data such as credentials and private files, and is marketed as a malware-as-a-service. Users are lured to download it through fake cracked software, deceptive websites, and social media posts. The malware's infrastructure has been diversified, with a shift towards using Russian-based cloud services. Recent campaigns include fake crack downloads, ClickFix campaigns using fake CAPTCHA pages, GitHub repository abuse, and social media promotions.

### The new SparkKitty Trojan spy in the App Store and Google Play
- Created: 2025-06-23T09:21:34.785000
- Author: AlienVault

A new spyware campaign dubbed SparkKitty has been discovered targeting both iOS and Android devices. The malware, believed to be connected to the previously identified SparkCat campaign, is distributed through official app stores and unofficial sources. It primarily steals photos from infected devices, likely searching for cryptocurrency wallet information. The campaign has been active since at least February 2024 and mainly targets users in Southeast Asia and China. The malware is embedded in various apps, including modified versions of popular applications like TikTok, and uses different techniques to evade detection. The researchers identified multiple variations of the malware, including obfuscated libraries and malicious frameworks mimicking legitimate ones.

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

### New Wave of SquidLoader Malware Targeting Financial Institutions
- Created: 2025-07-21T12:03:42.589000
- Author: AlienVault

A sophisticated malware campaign is targeting financial services in Hong Kong with SquidLoader, a highly evasive malware that deploys Cobalt Strike Beacon for remote access. The malware exhibits advanced anti-analysis, anti-sandbox, and anti-debugging techniques, achieving near-zero detection rates on VirusTotal. The attack chain is complex and poses a significant threat to targeted organizations. The analysis provides detailed technical insights into SquidLoader's features and indicators of compromise, including SHA256 hashes for samples found in Hong Kong, Singapore, China, and Australia. The campaign utilizes multiple command and control servers, primarily mimicking Kubernetes API endpoints.

### Toolshell: Large-scale exploitation of new SharePoint RCE vulnerability chain identified
- Created: 2025-07-21T10:15:02.101000
- Author: AlienVault

This pulse highlights an ongoing mass exploitation campaign targeting on-premises Microsoft SharePoint servers using a newly disclosed remote code execution (RCE) chain dubbed ToolShell. Discovered on July 18, 2025, by Eye Security, the attack chain is now tracked as CVE-2025-53770 and CVE-2025-53771, combining two previously known but unpatched vulnerabilities. The attackers exploit ToolPane.aspx via unauthenticated HTTP requests, dropping a custom ASPX webshell (spinstall0.aspx) into the SharePoint site.

### Ghost Crypt Powers PureRAT with Hypnosis
- Created: 2025-07-21T08:42:38.168000
- Author: AlienVault

In May 2025, eSentire's Threat Response Unit (TRU) uncovered a targeted attack on a U.S. accounting firm. The attackers used a newly advertised crypter service, Ghost Crypt, to sideload and obfuscate a DLL into a legitimate Windows component (csc.exe), deploying PureRAT, a Remote Access Trojan that surged in 2025

