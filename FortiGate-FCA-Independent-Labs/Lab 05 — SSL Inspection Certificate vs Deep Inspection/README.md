
**Date:** 13th June, 2026
**Lab Environment:** FortiGate 7.6.6 VM, GNS3 and VMware, Windows Host

---

## Objective

Configure and compare SSL Certificate Inspection and SSL Deep Inspection on FortiGate, document what each mode reveals in traffic logs and the browser certificate chain, install FortiGate's CA certificate to fix browser trust warnings, and explain what each inspection mode means in practice for an analyst.

---

## Tools Used

- FortiGate 7.6.6 VM (GNS3 running on VMware)
- FortiGate GUI
- FortiGate CLI (used for connectivity checks)
- Windows Host Machine (physical client)
- Firefox Browser (explicit proxy client)

---

## Topology

Explicit Web Proxy setup carried over from the previous lab.

- **Port 1 (LAN):** Static IP 192.168.126.132
- **Port 2 (WAN):** DHCP via GNS3 NAT cloud
- **Proxy:** Explicit Web Proxy on port1, listening on port 8080
- **Firefox:** Manual proxy pointed to 192.168.126.132:8080

---

## How the Two Inspection Modes Work

**SSL Certificate Inspection** reads the SNI field in the TLS Client Hello. This is the part of the TLS handshake sent in plain text before encryption starts. FortiGate uses this hostname to make policy decisions but never looks inside the encrypted connection. The TLS session between client and server stays untouched.

**SSL Deep Inspection** ends that session completely. FortiGate creates two separate TLS connections: one between itself and the browser, using a certificate it generates and signs with its own CA (Fortinet_CA_SSL), and one between itself and the real server, using the real server certificate. The browser never talks directly to the destination server. FortiGate decrypts the traffic to inspect it, then re-encrypts it and sends it on.

In this lab, deep inspection was set up inside the Explicit Web Proxy rather than a standard firewall policy. This makes sense because the proxy already sits between the browser and the internet as a middleman. Firefox is already pointed at FortiGate as its proxy, so having FortiGate also handle TLS termination for deep inspection is a natural fit.

---

## Steps Taken

### Phase 1: Baseline, Real Certificate, No Inspection

Turned off the Firefox proxy temporarily (Settings > Network Settings > No Proxy). Browsed to bbc.com. Clicked the padlock, then Connection Secure, then More Information, then View Certificate.

![State A real cert chain](lab05_state_a_real_cert_chain.png)

The certificate chain showed the real certificate authority for bbc.com, not FortiGate. This is the clean baseline both inspection modes get compared against.

Turned the Firefox proxy back on (192.168.126.132:8080) before continuing.

---

### Phase 2: Reviewed the Built In SSL Inspection Profiles

Went to Security Profiles > SSL/SSH Inspection. FortiGate comes with four built in profiles: certificate-inspection, deep-inspection, no-inspection, and custom-deep-inspection.

Opened certificate-inspection in view mode. Confirmed it only checks the TLS handshake, not the encrypted content, and that the profile cannot be edited.

![Certificate inspection profile readonly](lab05_certinspect_profile_readonly.png)

---

### Phase 3: Applied Certificate Inspection to the Proxy Policy

Went to Policy & Objects > Proxy Policy. Edited Proxy-LAN-to-WAN. Set the SSL Inspection field to certificate-inspection. Saved.

![Proxy policy certificate inspection applied](lab05_proxy_policy_certinspect_applied.png)

---

### Phase 4: Tested Certificate Inspection and Checked the Logs

Browsed to bbc.com and instagram.com through Firefox with the proxy active. Went to Log & Report > Forward Traffic and opened the detail panel on an HTTPS log entry.

![Certificate inspection log entry](lab05_log_certinspect_entry.png)

**This worked on the first try.**

**Lab limitation: log fields not fully visible**

The Forward Traffic log detail panel on this trial VM does not show a dedicated url field or ssl-inspector field. The closest visible fields are Destination (domain and IP) and Security Action. With certificate inspection active, Security Action showed Accept.

This is a known limit of the trial license and local log storage, not a sign that inspection was not working. On a production FortiGate with FortiAnalyzer or cloud logging enabled, the full log schema including ssl-inspector, url, app, and utmaction would be visible.

---

### Phase 5: Configured Deep Inspection

Went to Security Profiles > SSL/SSH Inspection.

**Lab limitation: profile cloning not available on trial**

Cloning a read only SSL inspection profile is not available on this trial VM. deep-inspection is preloaded and read only with no clone option. custom-deep-inspection is the fourth built in profile and is editable by design for exactly this kind of situation.

**How this was handled:** opened custom-deep-inspection directly and configured it instead of trying to clone deep-inspection.

Configuration applied:

| Field | Value |
|---|---|
| SSL Inspection Method | Deep Inspection |
| CA Certificate | Fortinet_CA_SSL |
| HTTPS Port 443 | Enabled |
| Untrusted SSL Certificates | Block |
| Expired SSL Certificates | Block |
| Invalid SSL Certificates | Block |
| Log SSL Anomalies | Enable |

![Custom deep inspection profile config](lab05_custom_deepinspect_profile_config.png)

---

### Phase 6: Applied Deep Inspection to the Proxy Policy

Went to Policy & Objects > Proxy Policy. Edited Proxy-LAN-to-WAN. Changed the SSL Inspection field from certificate-inspection to custom-deep-inspection. Saved.

![Proxy policy deep inspection applied](lab05_proxy_policy_deepinspect_applied.png)

---

### Phase 7: Tried to Capture the Untrusted Certificate Warning

**This is where the lab hit a wall.**

Plan: browse to bbc.com before installing the CA certificate, expecting a SEC_ERROR_UNKNOWN_ISSUER warning that could be clicked into to see Fortinet_CA_SSL listed as an untrusted issuer.

**What actually happened:** the page loaded with no warning at all. No certificate error, no advanced prompt, no change in browser behavior.

**Troubleshooting steps taken to find the cause:**

1. Confirmed `network.dns.echconfig.enabled` was set to false in Firefox about:config, then restarted Firefox fully. No change.
2. Confirmed `network.http.http3.enable` was still false from earlier lab setup. No change.
3. Tried a simpler site (example.com) to rule out site specific TLS behavior like certificate pinning or QUIC. Same result, no warning.
4. Confirmed custom-deep-inspection was actually saved and active on the Proxy-LAN-to-WAN policy, not reverted back to certificate-inspection.
5. Confirmed all FortiGate certificates were valid and not expired under System > Certificates.
6. Tested in a fresh Firefox private window to rule out cached certificate exceptions from earlier tests.
7. Switched the test method entirely, moving from the explicit proxy to a standard firewall policy (LAN-to-WAN-Allow from an earlier lab) with a manual `route add` command forcing specific destination IPs through FortiGate's port1, to rule out a proxy specific quirk.
8. With deep inspection applied to the standard firewall policy instead, several HTTPS sites (including bbc.com and facebook.com) returned a **connection timed out** error in the browser, even though the Forward Traffic log showed the session as accepted at the policy level.
9. Checked FortiGate's own outbound connectivity from the CLI:
   - `execute ping 8.8.8.8` returned 0% packet loss with clean round trip times (28.5ms to 48.2ms, average 37.9ms)
   - `execute telnet 8.8.8.8 443` connected successfully, ruling out basic port 443 reachability as the problem

**Root cause found:**

Basic ping, DNS, and TCP connectivity on FortiGate's WAN interface all worked fine. That ruled out routing and reachability as the problem. The failure was happening specifically at the TLS step inside deep inspection, the moment FortiGate has to close the connection with the browser and open a new encrypted connection to the real server.

Looking into FortiGate's evaluation license settings explained why. The eval license limits FortiGate to low encryption mode only. Most modern HTTPS sites require strong encryption (TLS 1.2 or 1.3 with ciphers like AES-GCM and ECDHE) to complete a handshake. The eval license does not support these, so when FortiGate tried to open that second encrypted connection to the real server, the handshake could not finish. That produced the timeout seen in testing. This also explains why ping and basic TCP connections worked fine: those do not involve encryption at all, only the TLS specific step failed, and it failed consistently across both the proxy and firewall policy tests.

This is a licensing limit, not a setup mistake, a resource problem, or an issue caused by running FortiGate inside a virtual machine. The deep inspection feature is configured correctly and would work as expected on a fully licensed FortiGate.

**What was not tested:** installing the FortiGate CA certificate before trying deep inspection again. Since the low encryption limit stops the TLS handshake before it finishes, the browser never gets far enough to even check FortiGate's certificate. So CA trust was never actually the issue here. This step was still completed in Phase 8 for documentation, but there was no working deep inspection session to test it against.

---

### Phase 8: CA Certificate Export (Completed, Result Unconfirmed)

Even though Phase 7 never reached the warning state, the CA export step was completed anyway for documentation and because it is a required step regardless of the troubleshooting outcome.

Went to Security Profiles > SSL/SSH Inspections > custom-deep-inspection > edit. Found Fortinet_CA_SSL under CA Certificates. Selected and downloaded it as fortigate_ca.crt.

![FortiGate CA export](lab05_fortigate_ca_export.png)

Imported into Firefox: Settings > Privacy & Security > Certificates > View Certificates > Authorities tab > Import. Selected fortigate_ca.crt, checked "Trust this CA to identify websites," restarted Firefox.

![Firefox CA trusted](lab05_firefox_ca_trusted.png)

**Note:** since the low encryption license limit stops the TLS handshake from finishing during deep inspection, the warning in Phase 7 was never reachable in the first place, no matter the CA trust setting. The certificate still imported successfully and shows as trusted in Firefox's Authorities list, which confirms the import process itself works correctly. This step stays valid and needed for any future test on a fully licensed FortiGate, where the handshake would complete and CA trust would actually matter.

---

## Lab Limitations and How They Were Handled

**Limitation 1: Log field visibility limited on trial license**

The Forward Traffic log detail panel does not show ssl-inspector, url, or app fields the way production deployments with FortiAnalyzer or cloud logging would. This is a license and storage limit. The Security Action field (Accept vs Accept with UTM allowed) was used as the main way to confirm inspection was running throughout this lab.

**Limitation 2: SSL inspection profile cloning not available on trial**

deep-inspection cannot be cloned on this trial VM. custom-deep-inspection, the editable profile meant for this exact purpose, was used instead. This is the correct supported approach, not a missing feature.

**Limitation 3: Deep inspection blocked by an evaluation license encryption limit (confirmed)**

Deep inspection was set up correctly and confirmed active at the policy and log level, but TLS sessions to external HTTPS sites timed out at the decrypt and reconnect step, both through the explicit proxy and a standard firewall policy. Testing one thing at a time ruled out routing, DNS, ECH, ping, and basic port 443 reachability as causes. Checking FortiGate's evaluation license settings confirmed the real cause: the eval license only supports low encryption, which cannot complete a handshake with the strong ciphers most HTTPS sites require today. This is a confirmed license limit, not an unresolved bug, a setup mistake, or a performance issue from running FortiGate as a VM.

---

## Key Findings

**Finding 1: Certificate inspection sees the hostname but not the content**

FortiGate reads the SNI field from the TLS handshake to identify the destination hostname. No URL path, HTTP header, or response body is visible. Web filtering under certificate inspection only works at the domain category level, good enough for blocking entire domains but not for filtering specific URLs or scanning content. The TLS session between browser and server is not touched. This mode worked correctly and was fully tested in this lab.

**Finding 2: Deep inspection is built to create two separate TLS sessions, confirmed at the policy level but blocked by a license limit**

With deep inspection configured, FortiGate is meant to act as the TLS endpoint for the browser, presenting its own certificate while keeping a separate session with the real server. The log showing Accept (UTM allowed) confirms FortiGate engaged this process. The full result, including the browser actually showing FortiGate's certificate, was not seen in this lab because the evaluation license's low encryption limit stopped the handshake from completing, as explained in Limitation 3. This is a license boundary, not a flaw in how deep inspection works.

**Finding 3: Policy level acceptance and session level completion are two different things**

This was the most useful unplanned finding in the lab. A session can be accepted and processed at the policy level while still failing afterward during TLS negotiation. A log entry showing Accept (UTM allowed) confirms the policy matched and inspection was triggered, but it does not confirm the user actually got a working connection. This matters for log analysis: an analyst who only checks the Security Action field could think a session succeeded when the real user experience was a failed connection.

**Finding 4: Testing one variable at a time is more useful than getting lucky with a working config**

Ruling out routing, DNS, ECH, ping, and TCP reachability one at a time, and testing across two different policy types (explicit proxy and standard firewall policy), narrowed down an unclear failure to one specific layer. This is the same approach used in real troubleshooting and incident response, where the goal is eliminating possibilities step by step instead of guessing at one cause.

**Finding 5: The certificate chain is the clearest proof that deep inspection is working, when it completes**

Comparing State A (real certificate authority) against a hypothetical State C (Fortinet_CA_SSL as the issuer) would be the clearest visual proof of inspection happening in the middle of the connection. This lab successfully captured State A and confirmed how the mechanism is supposed to work through the setup in Phase 5, but State C was not captured because the license limit in Limitation 3 stopped the handshake before it could finish. On a fully licensed FortiGate, this screenshot would be simple to get.

**Finding 6: Telling apart a license limit from a setup mistake is its own analyst skill**

The biggest takeaway from this lab was not the technical configuration itself, it was the process of figuring out whether something is broken because of a setup error or because of a platform restriction that has nothing to do with the configuration. Ruling out routing, DNS, ECH, and basic connectivity before looking at licensing avoided two wrong conclusions: assuming a config mistake, or assuming a vague hardware problem. In a real SOC or engineering role, correctly identifying that a security control is blocked by a license rather than misconfigured changes what happens next. One path means fixing a policy. The other means a licensing or procurement conversation.

---

## What an Analyst Would Do Next

1. **Check which proxy and firewall policies have deep inspection turned on** versus certificate inspection or no inspection at all, since this lab showed that a policy can log UTM activity without the session actually completing. This means policy checks alone are not enough without also checking the session level.
2. **Investigate unexpected certificate warnings from users** by checking the issuing certificate authority first. If it matches the organization's known FortiGate CA, the cause is likely a CA distribution gap. If it is unrecognized, that is a possible sign of unauthorized man in the middle activity.
3. **Review SSL anomaly logs regularly**, since Log SSL Anomalies was turned on in this lab's profile and would catch blocked sessions from untrusted, expired, or invalid certificates in a working deployment.
4. **Check TLS layer timeouts separately from policy level logs**, the central lesson from this lab, since relying only on Accept or Accept (UTM allowed) would have hidden the fact that sessions were failing after the policy already accepted them.
5. **Check licensing and subscription status early when troubleshooting a security feature**, since this lab's root cause turned out to be an evaluation license limit, not a configuration issue. Checking license status and feature entitlements first can save a lot of troubleshooting time in both lab and production environments.

---

## Status

This lab is complete, with one confirmed limitation. The certificate inspection objective was fully achieved and tested end to end, including logs. The deep inspection objective was configured correctly at every checkable layer (profile, policy assignment, log activity) but could not complete end to end because of a confirmed evaluation license limit: low encryption mode only, which does not support the modern TLS ciphers needed for deep inspection's decrypt and reconnect process. This is a platform limit, not an open or unresolved technical problem.

---

## Skills Demonstrated

- SSL/TLS inspection configuration on FortiGate (certificate inspection and deep inspection)
- Explicit Web Proxy configuration and policy management
- Certificate chain analysis and browser trust troubleshooting
- FortiGate CA certificate export and import workflow
- Forward Traffic log analysis and Security Action interpretation
- Systematic network troubleshooting: ruling out DNS, routing, ECH, ICMP, and TCP layer issues one at a time
- CLI based connectivity testing (ping, telnet) for root cause isolation
- Identifying a licensing constraint as a root cause instead of assuming a configuration error
- Understanding the difference between policy level logging and session level completion
- SOC relevant log analysis judgment, recognizing that Accept in logs does not always mean a successful connection
