**Date:** August 23, 2026 

**Series context:** FortiGate Security Operations Lab Series (Labs 03 to 12)

**Purpose:** This document consolidates every instance across the series where the FortiGate LENC evaluation license created a confirmed technical ceiling, separate from the individual lab writeups, so the pattern is visible in one place rather than scattered across twelve documents.

---

## What the LENC Eval License Actually Restricts

Across the series, four confirmed and reproducible constraints were identified. None of them have a GUI or CLI override. They are built into how the eval license behaves, not settings that were missed during configuration.

**1. Dynamically generated certificate key size is capped at 512-bit RSA.**
Any certificate FortiGate creates on the fly, such as during SSL inspection re-signing or SSL-VPN portal certificate generation, is generated at 512-bit regardless of what the admin configures.

**2. Cipher suite offerings are restricted to legacy options.**
Modern browsers and clients reject these outright rather than negotiating down to them.

**3. FortiGuard cloud connectivity is disabled.**
No live signature updates, no real-time web category lookups, and no contract-based license validation.

**4. AV and IPS signature databases are frozen at a static April 2018 snapshot.**
Whatever protections existed in FortiGuard's database as of that date are what is available. Nothing newer is present.

The pattern across every lab below is consistent: any function that depends on FortiGate generating its own certificate or reaching FortiGuard's cloud services hits a ceiling. Anything that does not depend on those two things runs cleanly.

---

## Lab-by-Lab Mapping

| Lab | Function Tested | LENC Affected | What Happened |
|---|---|---|---|
| 04: SSL Inspection v1 | SSL deep inspection on a firewall policy | Yes | Traffic was accepted by the policy but the session itself still failed. Traced to the eval license cipher suite restriction. FortiGate could not complete a TLS handshake the client would accept. First confirmed ceiling in the series. |
| 06: SSL Inspection v2 | Full deep inspection with a UTM profile attached | Yes | Confirmed the specific mechanism from Lab 04. Firefox returned MOZILLA_PKIX_ERROR_MITM_DETECTED (expected, proof interception was working) followed by MOZILLA_PKIX_ERROR_INADEQUATE_KEY_SIZE once FortiGate's CA was trusted. The certificate creation tool only offered 512-bit RSA for new requests. Browsers require a 2048-bit minimum. No internal path around this on the eval license. |
| 07 to 08: AV and Web Filtering | Malware detection (EICAR) and category-based web filtering | Yes | AV scanning operated against the frozen April 2018 signature snapshot rather than a current database. Detections relying on signatures published after that date would not be present. Web filtering could not perform live FortiGuard category lookups since cloud connectivity is disabled on the eval license. |
| 09: IPS | Intrusion Prevention System, signature-based detection | Partially | The frozen 2018 signature snapshot meant modern nmap scan formats produced no matches, not because IPS was broken, but because the traffic shape did not match an aging signature set. A decade-old CVE (Shellshock, CVE-2014-6271) delivered as a real payload still triggered a correct immediate detection. The constraint limited coverage, not detection capability itself. |
| 10: IPsec Remote Access VPN | Dial-up IPsec tunnel, PSK authentication | No | IPsec relies on a pre-shared key, not a FortiGate-generated certificate. Phase 1 and Phase 2 negotiation succeeded cleanly. The tunnel was not fully completed end to end, but the blocker was unrelated vendor and firmware behavior (strongSwan and FortiClient compatibility), not the LENC license. First clean data point confirming the constraint is cert-generation-specific, not VPN-functionality wide. |
| 11: SSL-VPN | SSL-VPN tunnel mode | No, different constraint entirely | SSL-VPN tunnel mode is not restricted by the eval license. It does not exist in the firmware at all. Fortinet permanently removed it from FortiOS 7.4.4 and above following CVE-2024-21762, confirmed via a CLI command returning Return code -1 (feature code absent from the binary). This is a firmware and vendor decision, not a licensing ceiling. The distinction matters and is kept separate throughout the series. |
| 12: Splunk Bridge | FortiGate log export to an external SIEM | No | Syslog forwarding and Splunk data input configuration involve no certificate generation and no FortiGuard dependency. The pipeline worked cleanly once a Windows host firewall rule was added, an unrelated and non-LENC blocker. |

---

## The Pattern

Plotting the relevant labs against the two root causes makes the shape of the constraint clear.

**Certificate generation dependent functions (Labs 04, 06):** blocked outright by the 512-bit RSA ceiling. No workaround exists on the eval license.

**FortiGuard cloud dependent functions (Labs 07, 08, and partially 09):** degraded, not blocked. Detections still fire but against a static aging reference set rather than a current one.

**Functions needing neither (Labs 10, 12):** run cleanly regardless of how security-critical the function is. IPsec and centralised logging are just as core to a real SOC environment as SSL inspection, and neither one is affected by the eval license at all.

**Lab 11 is the control case that proves the boundary.** It looks like it belongs in the LENC list but does not. It is a firmware removal, entirely unrelated to licensing. Keeping this distinction explicit matters. Treating a firmware removal and an eval license ceiling as the same kind of constraint would misrepresent both.

---

## Why This Document Exists

A reader going through twelve individual lab writeups might wonder whether the eval license is being used as a catch-all explanation for anything that did not work. This document shows the opposite.

Every constraint claimed across the series traces back to one of exactly two mechanisms: RSA key generation or FortiGuard cloud dependency. Each one was confirmed independently with reproducible evidence, specific error codes, CLI return codes, or timestamped log correlation. And the labs where nothing went wrong are documented with the same attention as the ones where something did.

Knowing exactly where a constraint's boundary sits, rather than treating every unexpected result the same way, is the skill this document is meant to show.

---

*This closes the FortiGate Security Operations Lab Series (Labs 03 to 12).*
