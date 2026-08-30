# FortiGate Security Operations

Ten labs (03 to 12) on FortiGate 7.6.6, running in GNS3 on VMware with Kali on a
separate hypervisor as the client and attacker. The goal was not to make
every feature work. It was to understand what each security feature does,
and when it does not work, to find out exactly why.

That last part became the theme. This lab environment ran on an evaluation
licence with real constraints, and a good chunk of the value here is in
separating a licensing limit from a misconfiguration from a firmware
change. Those look identical from the user's seat and mean very different
things on a real network.

## The labs

| Lab | Focus |
|---|---|
| [03 — Firewall policy and explicit proxy](./lab-03-firewall-policy-explicit-proxy) | Policy matching, and finding out the host was routing around the firewall |
| [04 — SSL inspection v1](./lab-04-ssl-inspection-v1) | Deep inspection through the proxy path |
| [05 — Multi-hypervisor infrastructure](./lab-05-multi-hypervisor-infrastructure) | Bridging Kali on VirtualBox into GNS3 on VMware, and a TCP checksum offload bug |
| [06 — SSL inspection v2](./lab-06-ssl-inspection-v2) | Standard policy path, and confirming the 512-bit RSA licence ceiling |
| [07 — Antivirus and malware blocking](./lab-07-antivirus-malware-blocking) | EICAR detection correlated across two log sources |
| [08 — Web filtering](./lab-08-web-filtering) | FortiGuard dependency and fail-closed behaviour |
| [09 — IPS with Shellshock](./lab-09-ips-shellshock) | Confirmed detection of CVE-2014-6271, signature 39294 |
| [10 — IPsec VPN](./lab-10-ipsec-vpn) | IKEv2 negotiation, unaffected by the licence |
| [11 — SSL VPN](./lab-11-ssl-vpn) | Feature removed from firmware after CVE-2024-21762 |
| [12 — Splunk bridge](./lab-12-splunk-bridge) | FortiGate syslog into Splunk, IPS detection rebuilt in SPL |

Plus a standalone synthesis:

### [Evaluation licence constraint mapping](./lenc-constraint-mapping-analysis)
Maps all ten labs against the two actual root causes of every
constraint hit: a 512-bit RSA cap on dynamically generated certificates,
and a frozen 2018 FortiGuard signature snapshot with no live category
lookups. The point of the document is that the constraint is narrow and
specific, not a catch-all excuse. Some labs were blocked outright, some
degraded but functional, and two were completely clean because neither
dependency was in play.

## Three findings worth your time

- **Lab 12:** syslog and Splunk were both configured correctly and no logs
  arrived. Windows Defender Firewall was silently dropping the inbound UDP.
  Neither FortiGate nor Splunk surfaced it. Root-caused by elimination.
- **Lab 10:** IPsec worked where SSL inspection failed, because it uses
  pre-shared keys and never generates a certificate. That is what proves
  the licence constraint is specifically about certificate generation, not
  security features in general.
- **Lab 11:** SSL-VPN tunnel mode was not misconfigured. Fortinet removed
  it from the firmware entirely in FortiOS 7.4.4+ following CVE-2024-21762,
  confirmed at the CLI by a feature code that returns nothing.

## A Note on AI-Assisted Workflow

Portions of this series' documentation and troubleshooting process were supported by AI tools (Claude, Gemini), used for structuring writeups, working through error messages, and refining documentation clarity. All lab execution, configuration, and screenshots are original hands-on work.

## Author

Oluwadamilola John Petson
[LinkedIn](https://linkedin.com/in/oluwadamilola-petson) · [GitHub](https://github.com/petsonjohn)
