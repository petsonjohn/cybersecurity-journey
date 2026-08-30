# Cybersecurity Journey

Independent security investigation and lab work by Oluwadamilola Petson.
I document everything I build, including the parts that failed and what
caused them, because on a real SOC floor the writeup is half the job.

**Currently:** Security Management at the Nigerian Communications
Commission, Nigeria's federal telecoms regulator. Monitoring incidents in
Microsoft Defender EDR, running phishing simulations, and supporting
vulnerability assessments.

**Looking for:** remote SOC Analyst, Network Security Analyst, or
Cybersecurity Analyst roles from October 2026.

- LinkedIn: https://linkedin.com/in/oluwadamilola-petson
- Email: Johnpetson16@gmail.com
- Based in Abuja, Nigeria (UTC+1). My day overlaps US overnight shifts.

---

## Start here

Two complete series, both scoped and executed independently in a home lab.
If you only have a few minutes, read the FormBook investigation. It is the
sharpest single piece of analysis in the repo.

### [Network Traffic Analysis and Threat Detection Engineering](./network-traffic-analysis)

Five phases, from protocol baselining to three real malware
investigations. Covers DNS tunnelling detection, C2 beaconing, TLS 1.3
decryption, and full incident reports on NetSupport RAT, Lumma Stealer,
and FormBook captured from real infections.

### [FortiGate Security Operations](./fortigate-security-operations)

Ten labs (03 to 12) plus a standalone constraint analysis, built on FortiGate
7.6.6 across GNS3 and VMware. Firewall policy, SSL inspection, intrusion
prevention with a confirmed Shellshock detection, VPN, and a FortiGate to
Splunk syslog bridge. Includes the walls I hit and what actually caused
them.

---

## What this repo shows

- Packet-level traffic analysis across DNS, TCP, HTTP, and TLS
- Malware traffic investigation from raw captures, with IOC extraction and
  false-positive discipline
- Host identification in Windows environments using DHCP, Kerberos, and
  SAMR
- FortiGate firewall administration: policy, NAT, SSL inspection, IPS, web
  filtering, VPN
- SIEM work: FortiGate syslog into Splunk, detection rebuilt in SPL,
  dashboards
- Honest constraint documentation: telling a licensing limit apart from a
  misconfiguration apart from a firmware change

## Tools

Wireshark · Splunk · FortiGate / FortiOS · Kali Linux · Nmap · Nikto ·
GNS3 · VMware · VirtualBox · Python · Git · Obsidian

## Certifications

- ISC2 Certified in Cybersecurity (CC)
- Fortinet Certified Associate in Cybersecurity (FCA)
- Google Cybersecurity Certificate
- Cisco CyberOps Associate
