# Phishing Triage & SIEM Detection Engineering Lab

A hands-on, end-to-end security operations lab covering threat intelligence ingestion, deep email header & attachment forensics, defense evasion discovery, and custom detection rule engineering in Wazuh SIEM.

---

## 📌 Executive Overview

Modern phishing attacks routinely bypass perimeter Secure Email Gateways (SEGs) through sophisticated evasion techniques—ranging from image-rendered lures and zero-width Unicode homoglyphs to abusing trusted cloud infrastructure (Azure, Vercel). 

This project simulates the complete real-world workflow of a **Security Operations Center (SOC) Analyst**:
1. **Threat Ingestion:** Safely harvesting live threat feeds (OpenPhish) and an active email spam corpus.
2. **Forensic Analysis:** Extracting and analyzing MIME headers, authentication mechanics (SPF/DKIM/DMARC), dynamic URL redirect hops, and weaponized attachments.
3. **Defense Evasion Discovery:** Documenting real-world bypasses (rasterized image text blinding OCR, and ZIP header padding breaking automated AV parsers).
4. **Threat Intelligence Curation:** Building a standardized, defanged Indicator of Compromise (IOC) dataset mapped to the **MITRE ATT&CK Framework**.
5. **Detection Engineering:** Operationalizing curated IOCs inside **Wazuh SIEM** using custom decoders, key-value CDB threat lists, and automated correlation rules, verified via `wazuh-logtest`.

---

## 🛠️ Lab Architecture & Detection Pipeline

```
[ Inbound Threat ] 
       │
       ▼
[ Forensic Triage ] ──► Header Analysis (SPF/DKIM/DMARC Alignment)
       │            ──► Attachment Deconstruction (qpdf, pdfimages, unzip)
       │            ──► Isolated URL Detonation (Dockerized curl)
       ▼
[ Threat Intel ]    ──► IOC Extraction & CSV Normalization (iocs.csv)
       │            ──► MITRE ATT&CK Technique Mapping
       ▼
[ Wazuh SIEM ]      ──► Ingestion of Web Proxy Logs
       │            ──► Custom XML Decoder (Extracts srcip, domain)
       │            ──► Binary CDB Threat List Lookup (phishing-iocs.cdb)
       ▼
[ Security Alert ]  ──► Rule 100200 Fired (Level 12 - Critical)
```

---

## 🔬 Key Forensic Case Studies

### 1. Sample 1000: Image-Only Lure & Azure Cloud Abuse
* **Lure:** Fake Banco do Brasil (`[BB]`) tax refund notification (`R$ 4.593,21`).
* **Authentication:** SPF `pass`, DKIM `pass`, DMARC `pass` (abuse of authentic personal Gmail infrastructure).
* **Evasion Mechanism:** Text parsers (`pdftotext`) extracted only random characters (`r6WceZWcCCv8YN`). Graphic analysis (`pdfimages`) proved the entire document was a single raster bitmap (`img1000-000.png`), completely blinding string-matching gateway filters.
* **Payload Link:** Low-level object stream analysis (`qpdf`) extracted an active `/URI` linking to Microsoft Azure Static Websites:
  `hxxps://okokoaksoa[.]z13[.]web[.]core[.]windows[.]net/`

<p align="center">
  <img src="notes/docx_images/media/imagee.png" alt="Banco do Brasil Raster Image Lure" width="280"/>
  <br>
  <em>Figure 1: Extracted full-page raster bitmap lure (img1000-000.png) with embedded yellow call-to-action button.</em>
</p>

<p align="center">
  <img src="notes/docx_images/media/imagec.png" alt="PDF Image Object and Hidden URI" width="800"/>
  <br>
  <em>Figure 2: Forensic object stream extraction revealing the hidden Azure Static Web App link.</em>
</p>

---

### 2. Sample 10017: Unicode Homoglyphs & ZIP Header Padding
* **Lure:** Kraken Security account settings alert.
* **Header Evasion:** Injected non-printable zero-width Unicode characters and Cyrillic homoglyphs (`а`, `е`) into the display name and subject line to evade regex keyword detection.
* **Payload Evasion:** Attached Word document (`Regulation Wed, July 08, 2026.docx`) contained 6 prepended junk bytes and corrupted local header offsets. Strict AV unpackers abort scanning upon offset errors, while Microsoft Word's lenient parser ignores padding and opens the file.

<p align="center">
  <img src="notes/docx_images/media/image9.png" alt="ZIP Header Offset Evasion" width="800"/>
  <br>
  <em>Figure 3: Unzip warning showing offset compensation and padding bytes used to evade automated antivirus gateways.</em>
</p>

---

### 3. Sample 1001: Microsoft Account Spoofing
* **Lure:** Urgent notice of unusual sign-in activity.
* **Header Anomaly:** Total mismatch across routing vectors:
  * Header From: `no-reply@access-accsecurity[.]com` (lookalike)
  * Return-Path: `bounce@nonkfrgr[.]co[.]uk`
  * Reply-To: `solutionteamrecognizd02@gmail[.]com` (attacker collection box)
  * Authentication: SPF `none`, DKIM `none`, DMARC `permerror`.

---

### 4. Live Threat Feed: Jimdofree Campaign Clustering
* Probing live OpenPhish URLs identified 3 separate phishing endpoints targeting French webmail/postal users (`AR24`):
  * `accueilboitear24seconnecte77.jimdofree[.]com`
  * `accueilsurlespacear24-8744.jimdofree[.]com`
  * `webmailar24.jimdofree[.]com`
* **Finding:** All 3 active endpoints resolve to the identical backend hosting IP (`185.60.251.252`), demonstrating shared infrastructure across distributed lures.

<p align="center">
  <img src="notes/docx_images/media/imagea.png" alt="Live OpenPhish URL Traces" width="800"/>
  <br>
  <em>Figure 4: Automated sandbox curl triage tracking live HTTP status codes, redirects, and resolved backend IPs.</em>
</p>

---

## 🎯 MITRE ATT&CK Matrix Mapping

| Tactic | Technique ID | Technique Name | Context in Lab |
| :--- | :--- | :--- | :--- |
| **Initial Access** | **T1566.001** | Spearphishing Attachment | Delivery of weaponized PDF and DOCX files |
| **Initial Access** | **T1566.002** | Spearphishing Link | Phishing URLs delivering credential-harvesting pages |
| **Defense Evasion**| **T1027** | Obfuscated/Encrypted Info | Zero-width Unicode homoglyphs, malformed ZIP headers, rasterized PDF text |
| **Defense Evasion**| **T1036.005** | Masquerading: Match Name | Impersonating Microsoft, Kraken Security, and Banco do Brasil |
| **Resource Dev**   | **T1583.001** | Acquire Infrastructure: Domains | Attacker-registered domains configured with valid SPF/DKIM |
| **Resource Dev**   | **T1583.006** | Acquire Infrastructure: Web Services | Exploiting Azure Static Web Apps and Vercel hosting |
| **Execution**      | **T1204.001** | User Execution: Malicious Link | Employee clicking link to malicious landing page |
| **Execution**      | **T1204.002** | User Execution: Malicious File | Employee opening document attachment |

---

## 🛡️ Wazuh SIEM Detection Engineering

### 1. Threat Intelligence CDB List (`etc/lists/phishing-iocs`)
All extracted domains are normalized and formatted for constant-time CDB hash table lookups:
```text
okokoaksoa.z13.web.core.windows.net:phishing
webmailar24.jimdofree.com:phishing
access-accsecurity.com:phishing
system-update-account-ilpro.vercel.app:phishing
```

### 2. Custom Proxy Log Decoder (`local_decoder.xml`)
Extracts the source IP and target domain from incoming web proxy events:
```xml
<decoder name="custom_proxy">
  <program_name>proxy</program_name>
  <regex>src=(\S+)\s+domain=(\S+)</regex>
  <order>srcip, domain</order>
</decoder>
```

### 3. Custom Correlation Rule (`local_rules.xml`)
Matches outbound web traffic against the threat intelligence list and tags MITRE techniques:
```xml
<group name="web,proxy,phishing,">
  <rule id="100200" level="12">
    <decoded_as>custom_proxy</decoded_as>
    <list field="domain" lookup="match_key">etc/lists/phishing-iocs</list>
    <description>Outbound connection to known phishing domain ($(domain)) detected</description>
    <mitre>
      <id>T1566.002</id>
      <id>T1204.001</id>
    </mitre>
  </rule>
</group>
```

### 4. Verification with `wazuh-logtest`

Simulating an outbound request from workstation `10.0.0.5` to a known phishing domain:
```bash
echo "Oct 23 10:15:01 proxy01 proxy: src=10.0.0.5 domain=webmailar24.jimdofree.com" | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest
```

**Engine Output:**
```text
**Phase 1: Completed pre-decoding.
	full event: 'Oct 23 10:15:01 proxy01 proxy: src=10.0.0.5 domain=webmailar24.jimdofree.com'
	timestamp: 'Oct 23 10:15:01'
	hostname: 'proxy01'
	program_name: 'proxy'

**Phase 2: Completed decoding.
	name: 'custom_proxy'
	domain: 'webmailar24.jimdofree.com'
	srcip: '10.0.0.5'

**Phase 3: Completed filtering (rules).
	id: '100200'
	level: '12'
	description: 'Outbound connection to known phishing domain (webmailar24.jimdofree.com) detected'
	groups: '['web', 'proxy', 'phishing']'
	firedtimes: '1'
	mail: 'True'
	mitre.id: '['T1566.002', 'T1204.001']'
	mitre.tactic: '['Initial Access', 'Execution']'
	mitre.technique: '['Spearphishing Link', 'Malicious Link']'

**Alert to be generated.
```

**False Positive Verification:**
Testing benign traffic (`domain=google.com`) confirmed the log decodes cleanly while **Rule 100200 does not trigger**, verifying zero false positive noise.

---

## 📂 Repository Structure

```
phish-lab/
├── README.md                      # Comprehensive project documentation (with embedded evidence)
├── .gitignore                     # Prevents accidental commit of live malware
├── notes/
│   ├── iocs.csv                   # Unified, defanged indicator of compromise table
│   └── docx_images/media/         # 14 evidence screenshots and extracted lures
├── reports/
│   ├── report-sample-1000.md      # Incident report: Banco do Brasil (PDF image lure & Azure abuse)
│   ├── report-sample-1001.md      # Incident report: Microsoft Account (header mismatch & spoofing)
│   └── report-sample-10017.md     # Incident report: Kraken Security (homoglyphs & ZIP header padding)
└── wazuh/
    ├── lists/phishing-iocs        # CDB threat intelligence lookup list
    ├── decoders/local_decoder.xml # Custom proxy log decoder
    ├── rules/local_rules.xml      # Detection rule 100200 with MITRE ATT&CK tags
    └── test_results.txt           # Captured wazuh-logtest verification logs
```

---

## 🚀 Key Takeaways for SOC Operations

1. **Authentication $\neq$ Benignity:** SPF, DKIM, and DMARC passes prove sender identity, not intent. Attackers routinely abuse legitimate email providers (Gmail, Microsoft 365 tenants) to bypass perimeter filters.
2. **Multi-Vector Defense:** Defeating modern phishing requires defense-in-depth: Secure Email Gateways for header anomalies, deep archive parsers for header padding evasion, and endpoint/proxy SIEM correlation for callback containment.
3. **Detection Engineering Lifecycle:** Developing effective SIEM detections requires curating threat intelligence, extracting specific log tokens through decoders, and testing against negative benign datasets to eliminate alert fatigue.
