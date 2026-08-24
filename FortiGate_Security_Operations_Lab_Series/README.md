# FortiGate Security Operations Lab Series

An independent, hands-on research project covering firewall policy, SSL inspection, malware and web filtering, intrusion prevention, VPN, and SIEM integration on FortiGate 7.6.6, built and documented end to end in a home lab.

## Why This Series Exists

Most FortiGate tutorials assume a fully licensed appliance and stop the moment something doesn't work as expected. This series was built on an evaluation (LENC) license instead, deliberately keeping every constraint, error, and workaround in the writeups rather than editing them out. The goal was to practice the way a real analyst actually works: something breaks, you figure out why, and you document what you learned either way.

Every lab follows the same principle: eval license and firmware limitations are documented as confirmed ceilings, not treated as failures or hidden from the writeup.

## Environment

- **FortiGate 7.6.6** VM, running in GNS3 on VMware Workstation
- **Kali Linux** (VirtualBox) as the attack and test machine
- **Windows host** bridging the hypervisors and running Splunk
- **Splunk Enterprise Free**, used in the final lab for log analysis
- Eval **LENC license** throughout, no production or paid licensing used

## Lab Index

| Lab | Topic | Key Finding |
|---|---|---|
| 03 | Firewall Policy & Explicit Proxy | Baseline policy configuration and initial logging approach |
| 04 | SSL Inspection (v1) | First confirmed LENC ceiling — cipher suite restriction breaks the handshake even when the policy accepts traffic |
| 05 | Multi-Hypervisor Lab Infrastructure | Cross-hypervisor bridging between VirtualBox, the Windows host, and GNS3/VMware |
| 06 | SSL Inspection (v2, deep dive) | Confirmed root cause: 512-bit RSA cap on dynamically generated certificates, evidenced by `MOZILLA_PKIX_ERROR_INADEQUATE_KEY_SIZE` |
| 07 | Blocking Malware / Antivirus | EICAR-based detection, correlated across Security Events; AV signatures frozen at an April 2018 snapshot |
| 08 | Web Filtering | FortiGuard cloud dependency confirmed as blocked on eval license, degrading live category lookups |
| 09 | Intrusion Prevention System (IPS) | Signature-based detection of a real exploit (Shellshock, CVE-2014-6271) despite a frozen 2018 signature database — the constraint limited *coverage*, not detection capability |
| 10 | IPsec Remote Access VPN | First clean result — IPsec is unaffected by LENC since it doesn't depend on dynamic certificate generation |
| 11 | SSL-VPN | Closed as a confirmed firmware limitation: SSL-VPN tunnel mode was permanently removed from FortiOS 7.4.4+ following CVE-2024-21762 — not a licensing issue |
| 12 | Monitoring and Splunk Bridge (flagship) | FortiGate syslog forwarded into Splunk; reproduced the Lab 09 IPS detection end to end inside a SIEM search; found a silent Windows host-firewall block that neither FortiGate nor Splunk surfaced on its own |
| — | LENC Constraint Mapping Analysis | Standalone synthesis document mapping every lab against the license's actual root causes, distinguishing true LENC ceilings from unrelated firmware or infrastructure issues |

## Methodology Notes

- **Logging approach evolved over the series.** Early labs used Explicit Proxy Policy logging to the Security Event log; from Lab 06 onward, logging shifted to standard Firewall Policy for cleaner Forward Traffic data. This shift is intentional and reflects a deliberate methodology improvement, not a correction of a mistake.
- **Every constraint is evidenced, not assumed.** Findings are backed by specific error codes, CLI return codes, or timestamped log correlation rather than general statements that "the license limited this."
- **Two categories of limitation appear across the series and are kept distinct:** true LENC eval-license ceilings (certificate generation, FortiGuard cloud dependency) versus unrelated firmware or infrastructure issues (e.g., SSL-VPN removal in Lab 11, the Windows host firewall in Lab 12). Conflating the two would misrepresent both.

## A Note on AI-Assisted Workflow

Portions of this series' documentation and troubleshooting process were supported by AI tools (Claude, Gemini), used for structuring writeups, working through error messages, and refining documentation clarity. All lab execution, configuration, and screenshots are original hands-on work.

## Author

Oluwadamilola John Petson
[LinkedIn](https://linkedin.com/in/oluwadamilola-petson) · [GitHub](https://github.com/petsonjohn)

---

*This series is complete as of August 2026. Next up: dedicated Splunk fundamentals and incident response labs.*
