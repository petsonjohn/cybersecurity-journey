# Network Traffic Analysis and Threat Detection Engineering

Five phases of independent traffic analysis, built in a home lab. The
early phases establish what normal looks like and how to pull signal out
of a capture. The last phase applies all of it to three real malware
infections.

Each phase carries its own full writeup with screenshots and the packet
captures used. The short version of each is below.

## The phases

### [Phase 1 — Protocol identification](./phase-1-protocol-identification)
Baselined live traffic across DNS, TCP, and HTTP from my own machine.
While mapping normal behaviour I found two things outside the original
scope: a DNS server failure retry loop and a telemetry beaconing pattern.
Both came back as reference points in Phase 3.

### [Phase 2 — TCP handshakes and port scan detection](./phase-2-tcp-handshake-port-scan)
Compared a full connect scan against a stealth SYN scan at packet level,
fingerprinted the target OS, and documented how a host firewall changes
closed versus filtered port responses. Windows sent `Win=65535` with full
options; Kali sent `Win=1024` with options stripped.

### [Phase 3 — DNS deep dive](./phase-3-dns-deep-dive)
Built DNS tunnelling two ways, with Iodine and a custom Python encoder,
then decoded the exfiltrated payload out of the query names. Simulated C2
beaconing with jitter and measured the cadence at 5.08 seconds average.
Confirmed that a successful DNS response code does not rule out C2, since
real C2 domains resolve fine.

### [Phase 4 — HTTP and HTTPS analysis](./phase-4-http-https-analysis)
Extracted SNI from encrypted sessions, decrypted live TLS 1.3 traffic
using an exported session-key log, and profiled suspicious User-Agent
strings against the legitimate baseline captured in Phase 1. Documented
why TLS 1.3 hides the certificate that TLS 1.2 leaves in the clear.

### [Phase 5 — Malware investigations](./phase-5-malware-investigations)
Three real infection captures, investigated end to end: NetSupport RAT,
Lumma Stealer, and FormBook. Every technique from Phases 1 through 4 feeds
into these. Full incident reports with IOC tables inside.

## What carried across every phase

The same filter discipline and the same question at each step: what is
normal here, and what breaks the pattern. By Phase 5 that turned into a
repeatable investigation method that held across three different malware
families producing completely different traffic.
