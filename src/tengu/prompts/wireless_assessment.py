"""Wireless network security assessment prompts."""

from __future__ import annotations


def wireless_assessment(interface: str = "wlan0") -> str:
    """Wireless network penetration test workflow.

    Args:
        interface: Wireless interface to use (must support monitor mode).

    WARNING: Only use on networks you own or have explicit written authorization.
    """
    return f"""# Wireless Security Assessment

## LEGAL WARNING
Only test wireless networks you own or have EXPLICIT WRITTEN AUTHORIZATION to test.
Unauthorized wireless testing violates the Computer Fraud and Abuse Act (CFAA)
and equivalent laws in most jurisdictions.

## Prerequisites
- Wireless adapter that supports monitor mode (Alfa AWUS036ACH recommended)
- Root/sudo access
- Written authorization from network owner
- Check applicable laws in your jurisdiction

## Interface Setup
```bash
# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start {interface}
# Interface is now likely: {interface}mon
```

## Phase 1 — Passive Network Discovery
1. `aircrack_scan(interface="{interface}mon", scan_time=60)` — discover all nearby networks
2. Document target networks (BSSID, SSID, channel, encryption)

## Phase 2 — Network Analysis
3. Record target network traffic on specific channel:
   - `aircrack_scan(interface="{interface}mon")` — capture on authorized network
4. Analyze captured traffic for:
   - Weak encryption (WEP, WPA-TKIP)
   - WPS enabled (vulnerable to Pixie-Dust, brute-force)
   - PMKID captures

## Phase 3 — Authentication Testing (AUTHORIZED NETWORKS ONLY)
5. WPA2 password testing (captured handshake):
   - `hash_crack(hash="...", mode="hashcat", wordlist="/usr/share/wordlists/rockyou.txt")`
6. Default credentials check against common router manufacturers

## Phase 4 — Client Security
7. Check for rogue AP possibilities (Evil Twin)
8. Verify client isolation is enabled
9. Test for deauthentication attack susceptibility

## Phase 5 — Cleanup
```bash
sudo airmon-ng stop {interface}mon
sudo service NetworkManager restart
```

## Common Vulnerabilities
- WEP encryption (trivially crackable)
- WPA2-PSK with weak passphrase
- WPS PIN brute-force (Reaver/Bully)
- PMKID attack (no client needed for WPA2 cracking)
- Evil Twin / Karma attacks
- Unencrypted guest networks with access to internal resources
- No client isolation on guest networks"""
