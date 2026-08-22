# Phase 5: Full Network Incident Investigation (Capstone)

## Network Traffic Analysis and Threat Detection Engineering Series

---

This is the capstone phase of the Network Traffic Analysis and Threat Detection Engineering Series, a self-directed independent research project built across five phases to develop practical SOC analyst skills from protocol fundamentals through real-world malware investigation.

Phase 5 consists of three independent incident investigations using real malicious packet captures sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net). Each investigation follows a structured analyst methodology: alert triage, host identification, DNS analysis, HTTP analysis, TLS analysis, IOC extraction, timeline construction, and remediation planning, applied to a different malware family producing different traffic signatures.

---

## Investigations

| # | Exercise | Malware Family | Date |
|---|---|---|---|
| [Investigation 1](./Investigation-1-NetSupport-RAT/) | Easy as 123 | NetSupport Manager RAT | 2026-02-28 |
| [Investigation 2](./Investigation-2-Lumma-Stealer/) | Lumma in the Room-ah | Lumma Stealer (LummaC2) | 2026-01-31 |
| [Investigation 3](./Investigation-3-FormBook/) | First to Last | FormBook (XLoader) | 2026-08-09 |

---

## What Each Investigation Covered

### Investigation 1: NetSupport Manager RAT

**Scenario:** SIEM alert for NetSupport Manager RAT activity from an internal host to a single external C2 IP over TCP port 443.

**Key findings:**
- Infected host identified as DESKTOP-TEYQ2NR, user brolf (Becka Rolf), via DHCP Option 12 and Kerberos CNameString
- NetSupport RAT communicated via plaintext HTTP POST to `/fakeurl.htm` on port 443, port evasion with no TLS present despite using the HTTPS port
- Self-identifying User-Agent `NetSupport Manager/1.3` confirmed the malware family from traffic alone
- 264 POST requests at exact 60-second intervals over 4.4 hours, textbook fixed-interval C2 keep-alive beaconing
- Zero TLS packets on the C2 connection, `ip.addr == 45.131.214.85 && tls` returned no results
- Microsoft Edge CDN domain flagged and verified as a false positive before the IOC table was finalised

**Defining evasion technique:** Port mimicry. Plaintext HTTP on port 443 to pass through firewalls that allow outbound HTTPS by default without deep packet inspection.

---

### Investigation 2: Lumma Stealer (LummaC2)

**Scenario:** SIEM alert for Lumma Stealer victim fingerprinting activity from an internal host to an external IP over TCP port 80.

**Key findings:**
- Infected host identified as DESKTOP-ES9F3ML, user gwyatt (Gabriel Wyatt), with full name confirmed via SAMR QueryUserInfo Response
- Alert domain confirmed as `whitepepper.su` resolving to 153.92.1[.]49, cross-referenced via HTTP Host header and DNS A record
- Seven malicious domains resolved across five TLDs (.su, .cc, .lat, .sbs, .cyou), domain rotation infrastructure
- 8,023-byte victim fingerprinting POST extracted via TCP stream containing hardware profile, GPU model, canvas fingerprint, installed fonts, audio profile, and WebDriver status
- Canvas fingerprinting and WebDriver: false check documented as anti-sandbox techniques. Lumma verified it was running in a real browser before proceeding
- Both Chrome and Edge browser vaults targeted separately, two independent agent registrations to the C2 panel
- Dual-channel C2 architecture: plain HTTP port 80 for fingerprinting, TLS port 443 for credential exfiltration
- Spoofed User-Agent Chrome/144 identified. That version does not exist.

**Defining evasion technique:** Dual-channel architecture with anti-sandbox validation. Fingerprint the host first to confirm it is a real machine, then exfiltrate credentials over encrypted TLS so the stolen data cannot be read in transit.

---

### Investigation 3: FormBook (XLoader)

**Scenario:** Six SIEM alerts for FormBook CnC Checkin activity firing across six different external IPs within three minutes. The multi-domain pattern is the first indicator before the PCAP is even opened.

**Key findings:**
- Infected host identified as DESKTOP-5NLV63K, user rvance (Raymond Vance), with machine account (DESKTOP-5NLV63K$) correctly distinguished from user account (rvance) in Kerberos traffic
- FormBook contacted 16 domains at the same time: 15 decoys and 1 active C2, all carrying the same session token `kbBSJ=Ep6t_fJ_` and hardcoded Firefox/39 User-Agent
- Active C2 `www.z61gqw.beer` (156.247.51[.]39) identified by HTTP 403 Forbidden response and Set-Cookie tracking header. Every decoy returned 404. Only the active C2 returned 403 with a session cookie.
- `www.taibeinan.cc` documented as a broken backend decoy, returned 500 and 502 errors before 404, suggesting a live but misconfigured server rather than a passive legitimate site
- `www.independent.ie` returned HTTP 301 Moved Permanently, a legitimate site enforcing HTTPS redirect that FormBook's client cannot handle
- 173.46.81[.]201 initially flagged as C2, confirmed as Windows Update CDN delivering a Windows Defender signature update after URI verification, removed from IOC table
- FormBook uses URI-level base64 encoding (`2kn1=` parameter) rather than TLS for payload protection. No TLS on any C2 connection.

**Defining evasion technique:** Decoy flood. Simultaneous checkins to 15 legitimate domains create noise in SOC alert queues, making the single active C2 harder to isolate from the flood of 404 responses.

---

## Three-Malware Comparison

The same core investigation methodology was applied across all three captures. What differed was how each malware family tried to stay hidden, and what that required from the analyst reading the results.

| Factor | NetSupport RAT | Lumma Stealer | FormBook |
|---|---|---|---|
| C2 domains | None, direct IP | 7 domains across 5 TLDs | 16 domains, 15 decoys + 1 active |
| C2 identification | User-Agent and URI | DNS resolution and SNI | Response code and Set-Cookie |
| TLS on C2 | None | Dual channel, port 80 and 443 | None |
| Payload protection | None, cleartext POST | TLS transport encryption | URI base64 encoding |
| User-Agent | Self-identifying | Spoofed plausible version | Hardcoded decade-old version |
| Evasion technique | Port mimicry | Anti-sandbox + domain rotation | Decoy flood |
| Key detection signal | /fakeurl.htm + NetSupport UA | /api/set_agent + Chrome/144 | 403 vs 404 + Firefox/39 UA |
| False positive encountered | Microsoft Edge CDN | None | Windows Defender update |
| Capture duration | 4.4 hours | 10.3 hours | Active session |
| Beaconing observed | 60-second fixed interval | Sustained TLS sessions | Concurrent multi-domain |

---

## Core Investigation Methodology

Every investigation followed the same structured sequence regardless of the malware family:

```
1. Read the alert context before opening the PCAP
        ↓
2. Statistics > Conversations: identify the top internal talker
        ↓
3. DHCP filter: hostname from Option 12 and Option 81
        ↓
4. kerberos.CNameString: username (user account, not machine account)
        ↓
5. SAMR QueryUserInfo: full AD display name
        ↓
6. DNS investigation: map C2 infrastructure, rule out tunneling
        ↓
7. HTTP investigation: URI patterns, User-Agent, payload extraction
        ↓
8. TLS investigation: SNI fields, presence or absence of encryption
        ↓
9. IOC extraction: verify before including, document removals
        ↓
10. Timeline, remediation, and cross-phase connections
```

Filters that stayed the same across all three investigations:

```wireshark
dhcp                                    # Hostname identification
kerberos.CNameString                    # Username identification
dns.qry.type == 16                      # TXT records: tunneling check
dns.qry.type == 10                      # NULL records: tunneling check
tls.handshake.type == 1                 # Client Hello: SNI extraction
ip.src == [victim_ip] && http.request   # HTTP traffic from victim
```

---

## Series Summary: All Five Phases

| Phase | Title | Core Skills Developed |
|---|---|---|
| [Phase 1](../Lab-1-Protocol-Identification/) | Protocol Identification | DNS, TCP, HTTP analysis and normal vs suspicious traffic baselines |
| [Phase 2](../Lab-2-TCP-Handshake-Analysis/) | TCP Handshake and Port Scan Analysis | TCP handshake analysis, port scan detection, OS fingerprinting, firewall behavior |
| [Phase 3](../Lab-3-DNS-Traffic-Deep-Dive/) | DNS Traffic Deep Dive | DNS tunneling simulation, beaconing simulation, IOC framework |
| [Phase 4](../Lab-4-HTTP-HTTPS-Analysis/) | HTTP and HTTPS Traffic Analysis | HTTP inspection, TLS handshake, SNI extraction, SSLKEYLOGFILE decryption, User-Agent analysis |
| [Phase 5](../Lab-5-Incident-Investigation/) | Full Incident Investigation | Three real malware investigations: NetSupport RAT, Lumma Stealer, FormBook |

---

## Skills Demonstrated Across the Series

**Network protocol analysis**
DNS query and response analysis across A, AAAA, MX, TXT, PTR, and NXDOMAIN record types. TCP handshake identification, port scan detection, and connection lifecycle analysis. HTTP request and response dissection. TLS handshake analysis and SNI extraction.

**Threat simulation and detection**
DNS tunneling simulation using Iodine and Python, subdomain entropy analysis and record type cycling detection. DNS beaconing simulation with configurable jitter and IO Graph pattern analysis. Suspicious User-Agent generation and detection. Port scan detection from both Windows and Kali Linux with OS fingerprint comparison.

**Incident investigation**
Alert-driven PCAP analysis from SIEM context to complete incident report across three malware families. Host identification in Windows Active Directory environments using DHCP, Kerberos, and SAMR. IOC extraction with false positive verification and explicit removal documentation. Chronological timeline construction from raw packet timestamps. Remediation planning including detection rule authoring at multiple confidence levels.

**Analyst discipline**
False positive identification and verification before IOC table inclusion, documented in all three Phase 5 investigations. Negative result interpretation: confirming the absence of DNS tunneling or TLS as a finding, not an uncertainty. Cross-investigation comparison: applying the same methodology to different malware families and correctly interpreting different results. Machine account vs user account distinction in Kerberos traffic.

---

## Tools Used Across the Series

| Tool | Purpose |
|---|---|
| Wireshark | Primary packet capture and analysis tool across all phases |
| Nmap | Port scanning from Windows (-sT) and Kali (-sS) for Phase 2 |
| Iodine | DNS tunneling simulation for Phase 3 |
| Python 3 | Custom DNS tunneling and beaconing simulation scripts |
| SSLKEYLOGFILE | Client-side TLS session key export for HTTPS decryption in Phase 4 |
| VirusTotal | IOC cross-reference for Phase 5 investigations |
| malware-traffic-analysis.net | Source of real malicious PCAPs for Phase 5 |

---

## Note on PCAP Files

Capture files from Phases 1 through 4 are included in their respective lab folders. Phase 5 PCAPs are not redistributed in this repository. They contain real malicious traffic from live infections. All three exercises are publicly available at [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) for anyone who wants to replicate the analysis.

---

*This series was completed as part of an independent cybersecurity research program building toward a remote SOC Analyst role. All lab work was self-directed on personal hardware using a home lab environment. Every constraint encountered, router firmware behavior, VM networking limitations, tool platform differences, was documented as a technical finding rather than omitted.*

