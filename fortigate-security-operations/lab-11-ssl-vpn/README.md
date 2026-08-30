**Date:** July 2026

**Context:** Written after Lab 10 findings. Read the Lab 10 writeup first.

**Lab Status:** Not completed. SSL-VPN tunnel mode does not exist in this firmware version. Documented as a confirmed firmware finding.

---

## Clarification on What the Lab 10 Wizard Actually Created

This is worth stating clearly before anything else because there was confusion about it during the session.

The VPN Wizard in FortiGate 7.6.6 creates IPsec tunnels only. It does not label tunnels as IPsec anywhere on screen because it does not offer any other type. There is no dropdown to choose between IPsec and SSL-VPN inside the wizard. Whatever you name the tunnel, whatever settings you fill in, the wizard produces an IPsec configuration underneath.

Corp-FullTunnel was an IPsec tunnel. Corp-SSL-VPN was also an IPsec tunnel, because that is all the wizard creates. The name made no difference to what FortiGate built underneath.

This was confirmed during the session: the standard VPN Wizard is hardcoded for IPsec connections and the word IPsec is not even shown because it is implied.

So the lab was testing IPsec as planned. FortiGate built the IPsec dial-up configuration correctly. The IKEv2 Phase 1 handshake completed successfully on the FortiGate side. The problem was entirely on the client side. strongSwan on Kali failed gateway validation because it does not send the proprietary FortiClient vendor ID headers the wizard-built tunnel expects, and the Linux standalone FortiClient app does not include an IPsec stack at all.

---

## Why SSL-VPN Could Not Be Tested

After the IPsec client side failed, the next attempt was to test SSL-VPN instead since the standalone Linux FortiClient showed SSL-VPN as an available option.

VPN > SSL-VPN Settings did not exist in the FortiGate GUI. The only items visible under VPN were VPN Tunnel, VPN Wizard, and VPN Location Map.

The CLI command to unhide the SSL-VPN menu was attempted:

```
config system settings
    set gui-sslvpn enable
end
```

Result:

```
value parse error before 'enable'
Command fail. Return code -1
```

Return code -1 means the command failed because the feature code no longer exists in the firmware binary. Fortinet permanently removed SSL-VPN tunnel mode from FortiOS 7.4.4 and above, including all VM trial builds. The removal followed severe vulnerabilities in the SSL-VPN engine, including CVE-2024-21762. The menu is missing because the feature was removed from the firmware entirely, not because it is hidden or disabled.

SSL-VPN tunnel mode cannot be tested on this FortiOS version. There is no configuration path around it.

---

## What This Means for the Lab Series

Lab 11 as originally planned cannot be completed on FortiOS 7.6.6. The SSL-VPN tunnel mode binary does not exist in this firmware.

This closes the vendor ecosystem thread that started in Lab 10. IPsec worked correctly at the protocol level and the Phase 1 handshake completed. SSL-VPN does not exist in this firmware at all. Both findings are confirmed and documented. No further testing is possible on this build.

The outcome here follows the same pattern as Labs 06, 07, and 08 where the eval license was the ceiling. In Lab 11 the ceiling is the firmware version itself, not the license. Recognising and documenting that kind of boundary is part of working in a real environment where not everything can be configured away.
