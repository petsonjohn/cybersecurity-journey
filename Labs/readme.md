# Network Traffic Analysis and Threat Detection Engineering Series

An independent research series built across five phases, starting from basic protocol identification and finishing with three real malware investigations using live infection captures. All work was done on personal hardware: a Windows laptop, a Kali Linux VM in VirtualBox, and a home router.

---

## Phases

| Phase                                       | Title                                | Focus                                                                                                            |
| ------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| [Phase 1](./Lab-1-Protocol-Identification/) | Protocol Identification              | DNS, TCP, and HTTP baselining: what normal traffic looks like before you hunt anomalies                          |
| [Phase 2](./Lab-2-TCP-Handshake-Analysis/)  | TCP Handshake and Port Scan Analysis | Port scan detection, OS fingerprinting from packet headers, firewall behavior at the packet level                |
| [Phase 3](./Lab-3-DNS-Traffic-Deep-Dive/)   | DNS Traffic Deep Dive                | DNS tunneling and beaconing simulation using Iodine and Python, subdomain entropy analysis                       |
| [Phase 4](./Lab-4-HTTP-HTTPS-Analysis/)     | HTTP and HTTPS Traffic Analysis      | HTTP stream inspection, TLS handshake dissection, SNI extraction, client-side HTTPS decryption via SSLKEYLOGFILE |
| [Phase 5](./Lab-5-Incident-Investigation/)  | Full Incident Investigation          | Three malware investigations from real captures: NetSupport RAT, Lumma Stealer, FormBook                         |

---

## What This Series Covers

Protocol analysis across DNS, TCP, HTTP, TLS, and DHCP. Threat simulation built from scratch using Python scripts and open-source tools. Port scan detection from both Windows and Linux with a documented comparison of how the same scan type looks different depending on the platform.

Phase 5 is where everything gets applied at once. Each investigation starts from a SIEM alert, works through host identification in a Windows Active Directory environment using DHCP, Kerberos, and SAMR, maps the C2 infrastructure, extracts IOCs, and finishes with a full incident report including a remediation plan and detection rules.

Three malware families, three different evasion techniques, the same core filter sequence throughout.

---

## Skills

- Network protocol baselining and anomaly identification
- DNS tunneling detection, beaconing interval analysis, IOC triage
- Port scan detection and OS fingerprinting from TCP header fields
- TLS handshake analysis and SNI extraction without decryption
- Client-side HTTPS decryption using SSLKEYLOGFILE
- Alert-driven PCAP investigation across three malware families
- Host identification in Windows AD environments
- False positive verification before IOC inclusion
- Detection rule authoring at multiple confidence levels

---

## Tools

Wireshark, Nmap, Kali Linux, Iodine, Python 3, SSLKEYLOGFILE, VirusTotal, malware-traffic-analysis.net

---

## On the Lab Environment

Real home lab environments do not behave like textbook setups. The router's admin panel firewall settings had no effect on scan results because the firmware runs stateful inspection independently of what the UI exposes. Kali VM traffic was invisible in Windows Wireshark due to how VirtualBox's bridged adapter handles packet visibility. Windows Nmap fell back from SYN scans to connect scans because of raw socket restrictions.

Every constraint like this is documented in the relevant phase as a technical finding, not omitted. That is how real environments work.

---

Built as part of an independent cybersecurity research program targeting remote SOC Analyst, Network Security Analyst, and Blue Team roles.


