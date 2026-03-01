"""Active Directory assessment prompts."""

from __future__ import annotations


def ad_assessment(
    target: str,
    domain: str,
    credentials: str = "none",
) -> str:
    """Active Directory penetration test workflow.

    Args:
        target: Domain Controller IP or hostname.
        domain: Active Directory domain name (e.g. corp.local).
        credentials: Authentication level — none (null session), user (low-priv user), admin (domain admin).
    """
    auth_steps = ""
    if credentials in ("user", "admin"):
        auth_steps = f"""
## Phase 3 — Authenticated Enumeration
5. `nxc_enum(target="{target}", protocol="ldap", domain="{domain}", username="...", password="...")` — LDAP enumeration
6. `impacket_kerberoast(target="{target}", domain="{domain}", username="...", password="...")` — Kerberoasting
7. `nxc_enum(target="{target}", protocol="smb", modules=["spider_plus"])` — SMB share spidering"""

    return f"""# Active Directory Assessment: {domain} ({target})

## Target: {target} | Domain: {domain} | Auth: {credentials}

## Phase 1 — Network Discovery
1. `nmap_scan(target="{target}", ports="88,135,139,389,445,464,593,636,3268,3389", scan_type="version")` — DC port scan
2. `dns_enumerate(domain="{domain}")` — DNS records, SRV records for AD services

## Phase 2 — Unauthenticated Enumeration
3. `enum4linux_scan(target="{target}")` — null session SMB enumeration (users, shares, password policy)
4. `nxc_enum(target="{target}", protocol="smb")` — SMB signing, OS version, hostname
{auth_steps}

## Phase 4 — Vulnerability Assessment
8. Check for classic AD vulnerabilities:
   - MS17-010 (EternalBlue): `nmap_scan(target="{target}", scripts="smb-vuln-ms17-010")`
   - PrintNightmare: `nmap_scan(target="{target}", scripts="smb-vuln-cve-2021-1675")`
   - ZeroLogon (CVE-2020-1472): `cve_lookup(cve_id="CVE-2020-1472")`

## Phase 5 — Credential Attacks
9. Password spraying (LOW AND SLOW — check lockout policy first!):
   `hydra_attack(target="{target}", service="smb", username_list="/tmp/users.txt", password="Password123!")`
10. Hash cracking from Kerberoasting: `hash_crack(hash="$krb5tgs$23$...", mode="hashcat", wordlist="...")`

## OPSEC Notes
- Check password lockout policy BEFORE brute force
- Kerberoasting IS logged by domain controllers (Event ID 4769)
- Use timing delays between attempts to avoid detection
- Document every credential used for the final report

## Key AD Vulnerabilities to Check
- Kerberoastable accounts (SPNs set on user accounts)
- AS-REP Roasting (accounts with pre-auth disabled)
- Password in description fields
- Unconstrained delegation
- AdminSDHolder abuse
- ACL abuse (WriteDACL, GenericAll, GenericWrite)"""
