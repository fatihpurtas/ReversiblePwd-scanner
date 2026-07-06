# Reversible Password Encryption Scanner

This PowerShell script audits **Active Directory** for accounts that store their
password with **reversible encryption** and exports the results to a CSV file.

## Purpose
When the `ENCRYPTED_TEXT_PWD_ALLOWED` flag (`userAccountControl` bit `0x80`) is
set, Active Directory stores the account's password in a form that can be
**decrypted back to plaintext**. Anyone who can read the directory database
(e.g. via a DCSync-capable attacker) can recover the clear-text password. This
is effectively the same risk as storing passwords in clear text and is a common
compliance failure.

- Detects all user accounts with `userAccountControl` bit `0x80` (128) set.
- Flags privileged accounts (`adminCount >= 1`).
- Excludes disabled accounts by default.

## Key Features
- Uses only built-in **System.DirectoryServices** classes, with **no ActiveDirectory module** required.
- Runs **without admin privileges**; only read access to AD is needed.
- Works domain-joined or against a specific DC via `-Server`.
- Paged LDAP query (1000/page), suitable for large domains.

## How It Works
1. Binds to `RootDSE` to discover the default naming context (or uses `-SearchBase`).
2. Runs the LDAP filter:
   ```
   (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))
   ```
   (a `(!(...:=2))` clause is appended to skip disabled accounts unless `-IncludeDisabled` is used)
3. Projects the relevant attributes, converts FileTime values to readable UTC.
4. Exports the results and prints a summary.

## Usage
```powershell
.\ReversiblePwd.ps1
.\ReversiblePwd.ps1 -Server dc01.example.com -OutputPath C:\Audit\reversible.csv
.\ReversiblePwd.ps1 -IncludeDisabled
```

| Parameter | Description |
|-----------|-------------|
| `-Server` | Domain controller to query directly (`dc01.example.com` or `:636`). |
| `-SearchBase` | Distinguished name to scope the search. |
| `-OutputPath` | CSV output path. Defaults to `.\reversible_pwd_<domain>.csv`. |
| `-IncludeDisabled` | Include disabled accounts (excluded by default). |

## CSV Columns
Name, SamAccountName, Enabled, AdminCount, PwdLastSet, LastLogon, DistinguishedName.

## Requirements
- PowerShell 5.1 or higher
- Domain connectivity (domain-joined or reachable DC via `-Server`)
- Read access to Active Directory

## Security Implications
- **Disable reversible encryption** at both the GPO level ("Store passwords using reversible encryption" = Disabled) and per account, then **force a password change**. The reversibly stored copy only clears when the password is next set.
- **Prioritize privileged accounts.**
- The flag is often enabled to support legacy authentication (CHAP, digest, some RADIUS setups); find and replace those dependencies rather than leaving the flag on.
- **Compliance:** most frameworks (PCI-DSS, CIS, NIST) explicitly prohibit reversibly stored passwords.
