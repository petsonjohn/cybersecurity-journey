
**Date completed:** 30 May 2025
**Tools used:** Wireshark, Nmap 
**Environment:** Windows laptop (192.168.1.143), Kali Linux VM (192.168.1.117), Home router (192.168.1.1)
**Capture files:**
- `lab2_part1_clean_and_failed_handshakes.pcapng`
- `lab2_part2_windows_connect_scan.pcapng`
- `lab2_part3_kali_stealth_scan_router.pcapng`
- `lab2_part5_kali_scan_windows_fw_off.pcapng`
- `lab2_part5_kali_scan_windows_fw_on.pcapng`

> **Display note:** Most screenshots use Wireshark name resolution enabled — IPs display as hostnames (e.g., 192.168.1.143 as DjSegee, 192.168.1.1 as TozedKangwei Router). For the Conversations statistics screenshot in Part 2, name resolution was disabled intentionally to show the sequential IP to port pattern that confirms scanning behavior.
---

## Lab Framework — Why the Methodology Was Adapted

Two constraints changed the original lab design. Each one produced learning a scripted lab would not have.

**Router firmware firewall:** Toggling the firewall, DMZ, or DDoS settings in the admin panel had no actual effect on the network traffic. Whether the firewall was on or off, Nmap scans consistently returned "closed" ports (RST responses) instead of "filtered" ones. This reveals a clear firmware limitation: the router fails to drop incoming packets, allowing traffic straight through to interact with the host regardless of the user configuration.

**VM packet capture limitation:** Kali's scan traffic was not visible in Windows Wireshark during Part 5 despite confirmed ICMP connectivity. After testing multiple interfaces, the issue was attributed to how VirtualBox's bridged adapter exposes traffic to the host capture interface. Capturing directly on Kali confirmed the scans ran correctly. Lesson: always validate traffic visibility at multiple capture points in a virtualized environment before concluding traffic is absent.

---

## Part 1 — Clean and Failed TCP Handshakes

**Frames analyzed:** 20297–23989 (clean handshakes), 24892–24897 (failed connections)

### Clean Handshakes — Multi-Site Analysis

**Filter used:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

SYN packets across four sites

![[handshake_multi_site_syn_filter.png]]

| Site         | Protocol | Infrastructure        | Post-Handshake Data Visible |
| ------------ | -------- | --------------------- | --------------------------- |
| neverssl.com | HTTP     | Origin server         | Yes — plain text readable   |
| google.com   | HTTPS    | CDN (142.251.150.119) | No — TLS encrypted          |
| github.com   | HTTPS    | CDN-hosted            | No — TLS encrypted          |
| udemy.com    | HTTPS    | CDN (104.16.143.237)  | No — TLS encrypted          |

### Google HTTPS Handshake

**Filter:** `ip.addr==192.168.1.143 && tcp.port==6872 && ip.addr==142.251.150.119 && tcp.port==443` **Frames:** 22094–23989

Google TCP handshake SYN SYN-ACK ACK

![[clean_handshake_google.png]]

| Step | Flag    | Details                                  |
| ---- | ------- | ---------------------------------------- |
| 1    | SYN     | Windows sends a SYN to Google            |
| 2    | SYN-ACK | Google CDN responds, connection accepted |
| 3    | ACK     | Windows confirms, handshake complete     |

After the handshake all frames show TLS Application Data, content is encrypted and unreadable without session keys. The handshake structure is identical to HTTP. Only what follows it changes.

**neverssl.com vs HTTPS:** neverssl.com delivers readable HTTP content after the handshake. HTTPS sites show the same handshake then switch immediately to encrypted TLS records. This is the clearest visual demonstration of why HTTPS exists.

### Failed Connection Attempts

**Filter:** `ip.addr == 192.168.1.1 && (tcp.port == 23 || tcp.port == 8080 || tcp.port == 9999)` **Frames:** 24892–24897

Failed connection RST response ports 23, 8080, 9999

![[failed_connection_rst.png]]

All three probed ports returned RST, ACK — closed port responses from the router.

|Port|Service|Response|Meaning|
|---|---|---|---|
|23|Telnet|RST, ACK|Closed — no Telnet service running|
|8080|HTTP-alt|RST, ACK|Closed — no alternate web service|
|9999|Unassigned|RST, ACK|Closed — port unused|

**RST vs filtered — what each tells an analyst:**

- **RST response:** Target is reachable, TCP stack responded, port is closed but not protected by a firewall
- **No response (filtered):** A firewall is dropping the probe before the OS sees it, silence is evidence of active filtering

---

## Part 2 — Windows Full Connect Scan (-sT) Against Router

**Capture:** `lab2_part2_windows_connect_scan.pcapng` **Command:** `nmap -sT 192.168.1.1` and `nmap -sT -sV 192.168.1.1`

### Why -sT on Windows

Windows restricts raw socket access for non kernel applications. Nmap cannot craft raw SYN packets so it uses the OS TCP stack to complete full connections instead. This makes the scan louder completed handshakes are logged by the target application. It is the only reliable scan type available on Windows without a kernel driver.

### Nmap Results

Nmap connect scan output

![[nmap_windows_output_1.png]]

- **Open ports:** 53 (DNS), 80 (HTTP), 443 (HTTPS)
- **Closed ports:** 997 — all returned RST
- **Router name identified** from service banners during -sV scan

### Open Port Conversation — Port 80 (Frames 568–609)

**Filter:** `ip.addr == 192.168.1.143 && tcp.port == 80`

Connect scan port 80 open port conversation

![[windows_connect_scan_port80.png]]

| Frame | Flag     | Description                       |
| ----- | -------- | --------------------------------- |
| 568   | SYN      | Windows probes port 80            |
| 583   | SYN-ACK  | Router responds — port open       |
| 586   | ACK      | Handshake completes               |
| 609   | RST, ACK | Nmap closes after confirming open |

The SYN → SYN-ACK → ACK → RST,ACK pattern is the connect scan signature for an open port. The completed handshake means the target application briefly logs the connection, this is what makes connect scans louder than SYN scans.

### Closed Port — Port 23

**Filter:** `ip.addr == 192.168.1.143 && tcp.port == 23`

Connect scan port 23 closed RST

![[windows_connect_scan_port23_closed.png]]

SYN sent → RST, ACK returned immediately. No SYN-ACK. The absence of SYN-ACK is the definitive closed port indicator across all scan types.

### Conversation Statistics — Sequential Scan Pattern

Conversation statistics sequential port order

![[windows_conversation_statistics.png]]

With name resolution off, the Conversations view shows the Windows IP (Address A) hitting the router across ports (Port B) in numerical order: 1, 3, 4, 6, 7, 9, 13, 17, 19 and continuing sequentially. The volume and ordering together confirm scanning behavior without needing to read individual packets. This is one of the fastest techniques for identifying a scan in a large capture.


---

## Part 3 — Kali Stealth SYN Scan (-sS) Against Router

**Capture:** `lab2_part3_kali_stealth_scan_router.pcapng` **Commands:** `sudo nmap -sS 192.168.1.1` and `sudo nmap -sS -sV -O 192.168.1.1`

### Why -sS on Kali

Linux grants Nmap raw socket access, allowing it to craft TCP packets directly without the OS TCP stack. Nmap sends SYN, receives SYN-ACK, then sends RST before the OS completes the handshake. The target application never sees a completed connection and logs nothing. Root privileges are required because raw socket access is a privileged operation.

### Nmap Results

Nmap stealth scan output with OS detection

![[nmap_kali_output.png]]

- **Open ports:** 53, 80, 443 — matching the Windows connect scan
- **OS detected:** Linux 4.15–5.19 (router running embedded Linux, identified via -sV and -O flags)
- **Observation:** The Windows connect scan identified the router by name from service banners. The Kali SYN scan required explicit -sV and -O flags to obtain the same detail, because SYN scans never complete handshakes, banners are not passively readable.

### Open Port — Port 80 (Frames 279–302)

**Filter:** `ip.addr == 192.168.1.143 && tcp.port == 80`

Stealth scan port 80 SYN SYN-ACK RST pattern

![[kali_stealth_scan_port80.png]]

| Frame | Flag    | Description                                   |
| ----- | ------- | --------------------------------------------- |
| 279   | SYN     | Kali probes port 80 — Win=1024, MSS=1460 only |
| 289   | SYN-ACK | Router responds — port open                   |
| 302   | RST     | Kali aborts — handshake never completes       |

No ACK follows the SYN-ACK. The handshake is deliberately left incomplete. The target OS sees a half open connection. The target application sees nothing.

### Closed Port — Port 23

**Filter:** `ip.addr == 192.168.1.143 && tcp.port == 23`

Stealth scan port 23 closed RST ACK

![[kali_stealth_scan_port23_closed.png]]

SYN sent → RST, ACK from router. Identical RST response to the connect scan for this port. The difference is no ACK follows from Kali, the half open pattern holds even for closed ports.

### Notable Finding — Pre-Scan Recon Behavior

Before scanning began, Kali sent an ARP request for the router's MAC address followed by a DNS PTR reverse lookup. The router resolved the PTR query back to the DjSegee hostname. This is Nmap's automatic host discovery and reverse DNS phase, it runs before every scan. An analyst watching the wire would see this ARP and PTR sequence immediately preceding the SYN flood and recognize it as the beginning of a scan workflow.

---

## Part 4 — Platform Comparison: Windows -sT vs Kali -sS

| Factor                    | Windows -sT                      | Kali -sS                              |
| ------------------------- | -------------------------------- | ------------------------------------- |
| Handshake                 | SYN → SYN-ACK → ACK → RST,ACK    | SYN → SYN-ACK → RST                   |
| Completes                 | Yes                              | No                                    |
| Application log on target | Created                          | Not created                           |
| Detection difficulty      | Louder, application logs created | Quieter at app layer, visible on wire |

---

## Part 5 — Firewall Impact: Kali Scan on Windows (Firewall Off vs On)

**Captures:** `lab2_part5_kali_scan_windows_fw_off.pcapng` and `lab2_part5_kali_scan_windows_fw_on.pcapng` **Command:** `sudo nmap -sS 192.168.1.143` for both scans

### Capture Limitation

Kali's scan traffic was not visible in Windows Wireshark during live capture. After testing multiple interfaces, the issue was isolated to how VirtualBox's bridged adapter handles packet visibility between VM and host not a network failure. Captures were taken directly on Kali and confirmed complete, then imported to my Windows Wireshark for analysis.

### Firewall Off

Windows firewall disabled settings

![[windows_fw_off_settings.png]]

Nmap Scan with Windows firewall disabled

![[nmap_windows_fw_off_output.png]]

**Nmap result:** 994 closed ports (RST), 6 open ports

|Open Port|Service|
|---|---|
|135|MSRPC|
|139|NetBIOS-ssn|
|445|SMB|
|5357|WSDAPI|
|8000|Splunk web interface|
|8089|Splunk management port|

**Port 445 open — filter:** `ip.addr == 192.168.1.117 && tcp.port == 445`

Firewall off port 445 open SYN SYN-ACK RST

![[fw_off_port445_open.png]]

SYN → SYN-ACK → RST — port open, Nmap aborts cleanly.

**Port 444 closed — filter:** `ip.addr == 192.168.1.117 && tcp.port == 444`

Firewall off port 444 closed RST ACK

![[fw_off_port444_closed.png]]

SYN → RST, ACK — port closed, TCP stack responds directly.

With the firewall off, Windows responds honestly to every probe. A complete picture of the machine's services is shown.

### Firewall On

Windows firewall enabled settings

![[windows_fw_on_settings.png]]

Nmap Scan with Windows firewall enabled

![[nmap_windows_fw_on_output.png]]

**Nmap result:** 996 filtered ports (no response), 4 open ports

|Port|Firewall Off|Firewall On|
|---|---|---|
|135|Open|Open|
|139|Open|Open|
|445|Open|Open|
|5357|Open|Open|
|8000 (Splunk)|Open|Filtered|
|8089 (Splunk)|Open|Filtered|
|All others|Closed — RST|Filtered — no response|

**Port 445 still open — same filter:**

Firewall on port 445 still open

![[fw_on_port445_open.png]]

Behavior identical to firewall off,  Windows Firewall is configured to allow SMB traffic.

**Port 444 now filtered — same filter:**

Firewall on port 444 filtered no response

![[fw_on_port444_filtered.png]]

SYN sent → no response. Windows Firewall drops the probe before the TCP stack sees it. The same port that returned RST with the firewall off now returns silence. Closed became filtered.

---

## Key Findings Summary

| Part  | Scan              | Platform | Target         | Open Ports                 | Notable                                                       |
| ----- | ----------------- | -------- | -------------- | -------------------------- | ------------------------------------------------------------- |
| 1     | Browsing + probes | Windows  | Sites + router | N/A                        | Multiple SYN per page load; all failed probes returned RST    |
| 2     | Connect scan -sT  | Windows  | Router         | 53, 80, 443                | Sequential ports in Conversations; DNS over TCP               |
| 3     | Stealth scan -sS  | Kali     | Router         | 53, 80, 443                | Win=1024 fingerprint; Linux OS detected; pre-scan ARP and PTR |
| 4     | Comparison        | Both     | Router         | Same                       | Win=65535 vs Win=1024; handshake completes vs half-open       |
| 5 off | Stealth scan -sS  | Kali     | Windows        | 135,139,445,5357,8000,8089 | Full port map exposed; all closed returned RST                |
| 5 on  | Stealth scan -sS  | Kali     | Windows        | 135,139,445,5357           | 996 filtered; Splunk hidden; attack surface reduced           |

---

## SOC Application

Port scan detection is one of the most common alert types in a SOC. The methodology is consistent regardless of tool or scan type: Statistics > Conversations to identify high-volume source IPs, then `tcp.flags.syn == 1 && tcp.flags.ack == 0` to isolate probes, then check responses to map open, closed, and filtered ports.

Source location changes the escalation path. An internal IP scanning internal hosts could indicate a compromised machine performing lateral movement reconnaissance, higher priority than an external scan.

The firewall comparison in Part 5 demonstrates why host based firewall state is one of the first things checked on a potentially compromised machine. The difference between what is visible with and without the firewall active reveals the true attack surface and whether defenses are working as configured.

Platform fingerprinting from TCP headers is passive intelligence. Win=1024 with no WS option is an Nmap signature. TTL of 64 is Linux. TTL of 128 is Windows. These values help attribute a scan before knowing anything else about the source.

---

## Technical Constraints and Adaptations

| Constraint                     | Attempted                                   | Result                                         | Lesson                                                                     |
| ------------------------------ | ------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------- |
| Windows raw socket restriction | nmap -sS on Windows                         | Fell back to connect scan                      | Platform dictates scan capability; Linux needed for stealth scanning       |
| Router firmware firewall       | Enabled via DMZ and DDoS settings           | Traffic went through despite enabling Firewall | Admin panel controls are a subset of actual firmware security behavior     |
| VM packet capture limitation   | Capture Kali traffic from Windows Wireshark | Traffic not visible in host capture            | Validate visibility at multiple capture points in virtualized environments |

---

## Skills Demonstrated

- TCP three-way handshake analysis across multiple site types and protocols
- Failed connection analysis — RST closed port vs filtered silence distinction
- Port scan detection using Wireshark filters and Statistics > Conversations
- Connect scan (-sT) execution and analysis from Windows
- Stealth SYN scan (-sS) execution and analysis from Kali
- Platform comparison — TCP header OS fingerprinting
- Router firmware behavior analysis and constraint documentation
- Windows Firewall packet level impact analysis before and after comparison
- VM networking troubleshooting and traffic validation