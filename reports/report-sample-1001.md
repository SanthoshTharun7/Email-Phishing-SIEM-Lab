# Phishing Incident Report: Sample 1001

## 1. Executive Summary
An external email impersonating the **Microsoft Account Team** was detected with the subject *"Microsoft account unusual signin activity"*. The email attempts to deceive users into interacting with an embedded link disguised as a security response action. Technical examination indicates severe domain and routing anomalies with zero authentication, consistent with an unauthenticated credential-harvesting attempt.

---

## 2. Technical Evidence & Analysis
* **Sender Identity Manipulation:**
  * **Display Name:** `"Microsoft account team"`
  * **Header From:** `no-reply@access-accsecurity[.]com` (typosquatted / lookalike domain)
  * **Envelope Return-Path:** `bounce@nonkfrgr[.]co[.]uk`
  * **Reply-To:** `solutionteamrecognizd02@gmail[.]com` (directing user communications to a free Gmail mailbox)
* **Authentication Failures:**
  * **SPF:** `spf=none` (smtp.mailfrom=`nonkfrgr.co.uk`, origin IP: `89.144.9.87`)
  * **DKIM:** `dkim=none` (message not cryptographically signed)
  * **DMARC:** `dmarc=permerror` (lookup/record misconfiguration prevented evaluation)
* **Embedded Payload / Link:**
  * Embedded URL: `hxxp://thebandalisty[.]com/track/o39473XgziG18708448HxBA1821750yoR33736gMed176`
  * Dynamic triage inside sandbox revealed HTTP code `000` (domain expired / unreachable at test time).

---

## 3. MITRE ATT&CK Mapping
| Technique ID | Technique Name | Context in Sample |
| :--- | :--- | :--- |
| **T1566.002** | Phishing: Spearphishing Link | Delivery of an unauthenticated email carrying an external link. |
| **T1036.005** | Masquerading: Match Legitimate Name | Display name spoofing `"Microsoft account team"`. |
| **T1583.001** | Acquire Infrastructure: Domains | Registration of `access-accsecurity[.]com` and `thebandalisty[.]com`. |
| **T1598.003** | Phishing for Information: Spearphishing Link | Lure crafted to capture account credentials. |

---

## 4. Indicators of Compromise (IOCs)
* **Sender Domain:** `access-accsecurity[.]com`
* **Return-Path Domain:** `nonkfrgr[.]co[.]uk`
* **Originating IP:** `89[.]144[.]9[.]87`
* **Exfiltration / Reply Address:** `solutionteamrecognizd02@gmail[.]com`
* **Payload URL Domain:** `thebandalisty[.]com`

---

## 5. Severity Assessment & Recommended Actions
* **Severity:** **HIGH** (Brand impersonation targeting core enterprise identity / SSO).
* **Recommended Actions:**
  1. **Block & Filter:** Add `access-accsecurity[.]com` and `thebandalisty[.]com` to perimeter email and web gateway blocklists.
  2. **Quarantine:** Purge all emails originating from `89.144.9.87` or containing `solutionteamrecognizd02@gmail.com`.
  3. **User Triage & Escalation:** Query proxy/DNS logs for outbound connections to `thebandalisty[.]com`. Force password reset and revoke active sessions for any user with confirmed clicks.
