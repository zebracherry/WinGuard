# 🛡️ WinGuard

> **Windows Server Security Audit Tool**

A single, self-contained PowerShell script that audits Windows Server against
**CIS Benchmarks**, **DISA STIGs** and the **Microsoft Security Baseline** — plus a
built-in hardening scanner and air-gap isolation checks — with **full non-admin
support**, auto OS detection, and beautiful HTML + JSON reports.
**100% air-gap safe — no internet connection required, zero external dependencies.**

The Windows counterpart of [RHELGuard](https://github.com/zebracherry/RHELGuard):
same check model, same report schema, same options, so a Linux and a Windows
estate can be audited and tracked the same way.

| File | Runs with | Requires |
|---|---|---|
| **`winguard.ps1`** | `powershell -File winguard.ps1` | PowerShell 3.0+ (Server 2012 and later), nothing else |

---

## ✨ What It Does

| Framework | Coverage |
|---|---|
| **CIS Benchmarks** | Windows Server 2016, 2019, 2022, 2025 — Level 1, Member Server + Domain Controller (auto-selected by detected build and role) |
| **DISA STIG** | Server 2016 V2R10, 2019 V3R8, 2022 V2R8, 2025 V1R1 — CAT I/II/III, MS and DC variants |
| **Microsoft Security Baseline** | Security Compliance Toolkit settings for Server 2022 / 2025, including the ones where Microsoft and CIS **disagree** |
| **Hardening Posture** | Built-in scanner across 15 categories: AUTH BOOT CRYP INSE KRNL LOGG MALW PKGS SCHD SHLL STRG TIME TOOL USERS HRDN — including local privilege-escalation and bypass checks (writable `%PATH%`, TPM-only BitLocker, WDAC audit-vs-enforce, AppLocker service state) |
| **Air-Gap Isolation** | Egress & bridging, radios (Wi-Fi/BT/WWAN/USB-tether), DMA ports, phone-home services, telemetry, update source, patch & signature age, NTP/log/tunnel exposure |

### Checks per platform

| Detected host | CIS | STIG | MS Baseline | Posture | Air-gap | **Total** |
|---|---|---|---|---|---|---|
| Server 2016 (MS / DC) | 419 / 411 | 185 / 186 | — | ~107 | ~43 | **~754 / 747** |
| Server 2019 (MS / DC) | 434 / 432 | 185 / 188 | — | ~107 | ~43 | **~769 / 770** |
| Server 2022 (MS / DC) | 460 / 457 | 185 / 188 | 156 / 155 | ~107 | ~43 | **~951 / 950** |
| Server 2025 (MS / DC) | 477 / 474 | 177 / 184 | 180 / 181 | ~107 | ~43 | **~984 / 989** |

Microsoft publishes Security Baseline content for Server 2022 and 2025 only; on
2016/2019 WinGuard says so in the report rather than silently scoring zero.
CIS overlaps the Microsoft baseline heavily, so those hosts remain well covered.

---

## 🚀 Quick Start

```powershell
# Copy to the server, then from an ELEVATED PowerShell prompt:
powershell -ExecutionPolicy Bypass -File .\winguard.ps1          # full scan (recommended)

# Non-admin partial scan — runs everything it can, cleanly skips the rest
powershell -ExecutionPolicy Bypass -File .\winguard.ps1
```

Reports are saved to `.\winguard_reports\` — open the `.html` file in any browser.

`-ExecutionPolicy Bypass` on the command line applies to that process only; it
changes nothing on the host and needs no prior configuration. If local policy
forbids even that, use `powershell -Command "& { ... }"` with the content, or
have the script signed by your code-signing CA.

---

## 🔍 Non-Admin Mode

WinGuard **does not require administrator rights to run**. It executes everything it
can and cleanly skips what needs elevation, marking those `SKIP (administrator
required)` in the report. Skipped checks do **not** count against the score.

| Check Type | Non-Admin | Admin |
|---|---|---|
| Registry policy (the bulk of CIS/STIG) | ✅ | ✅ |
| Services, Windows features | ✅ | ✅ |
| Firewall profiles, TLS/cipher config | ✅ | ✅ |
| Defender status, ASR rules | ✅ | ✅ |
| Local accounts, Administrators group | ✅ | ✅ |
| Listening ports, shares, scheduled tasks | ✅ | ✅ |
| Account policy (password/lockout) | ❌ SKIP | ✅ |
| User Rights Assignment | ❌ SKIP | ✅ |
| Advanced audit policy (`auditpol`) | ❌ SKIP | ✅ |
| Boot configuration (`bcdedit`) | ❌ SKIP | ✅ |
| WinHTTP proxy | ❌ SKIP | ✅ |

---

## ⚙️ Usage

```
powershell -File winguard.ps1 [OPTIONS]

OPTIONS:
  -Mode <m>              cis | stig | baseline | posture | airgap | all   (default: all)
  -Output <dir>          Output directory                     (default: .\winguard_reports)
  -Throttle <ms>         Delay between checks                  (default: 50)
  -Baseline <file>       Previous WinGuard JSON — show drift since that scan
  -Waivers <file>        Accepted deviations, one "CHECK-ID | reason" per line
  -MaxPatchAge <days>    Days since last update before flagging       (default: 90)
  -MaxSignatureAge <d>   Days since last Defender signature update    (default: 7)
  -Bundle                Pack reports + MANIFEST + SHA256SUMS into a .zip
  -Strict                Exit 2 if any FAIL remains (CI / automation)
  -IncludeManual         Also list the STIG rules that need manual review, as INFO
  -IncludeDomainPolicy   Also audit the Default Domain Password Policy (see below)
  -Quiet                 Suppress per-check output (summary still printed)
```

Short aliases match RHELGuard where PowerShell allows it: `-m`, `-o`, `-t`,
`-b` (Baseline), `-w` (Waivers), `-a` (MaxPatchAge), `-q`.
`-Bundle` has no single-letter alias — PowerShell parameter aliases are
case-insensitive, so `-B` would collide with `-b`; `-Bu` works.

### Examples

```powershell
# Full scan — all frameworks
.\winguard.ps1

# CIS only, custom output directory
.\winguard.ps1 -Mode cis -Output C:\Audit

# STIG only, higher throttle for a busy production host
.\winguard.ps1 -Mode stig -Throttle 200

# Air-gap isolation checks only
.\winguard.ps1 -Mode airgap

# Quarterly enclave audit: compare to last run, apply approved waivers,
# bundle for transfer, fail the pipeline if anything is still open
.\winguard.ps1 -Baseline .\last_quarter.json -Waivers .\enclave-waivers.txt -Bundle -Strict

# Complete STIG checklist, including the rules a script cannot determine
.\winguard.ps1 -Mode stig -IncludeManual

# Also audit the Default Domain Password Policy (one LDAP query to your own DC)
.\winguard.ps1 -IncludeDomainPolicy
```

### A note on `-IncludeDomainPolicy`

The account-policy rows in the CIS and STIG sections read the **local** security
policy. On a domain-joined server that is *not* the policy governing domain
accounts — the Default Domain Policy at the DC is. `-IncludeDomainPolicy` audits
that too (minimum length, complexity, reversible encryption, lockout threshold
and duration).

It is off by default because it is the only check in the tool that leaves the
host: it makes one LDAP query to this machine's own domain controller. On a
domain controller it runs automatically, because there the data is local. It
needs the `ActiveDirectory` RSAT module; without it the check reports SKIP and
says why rather than guessing.

Fine-grained password policies (PSOs) override the default policy for specific
users and groups — WinGuard flags that in the finding text and points you at
`Get-ADFineGrainedPasswordPolicy`, but does not enumerate them.

---

## 🔌 Air-Gapped Operations

WinGuard is built for disconnected enclaves: every check reads local state (the
registry, `secedit`, `auditpol`, WMI, the service database) — nothing is resolved,
fetched or probed, and the HTML report carries a strict Content-Security-Policy so
it cannot load or send anything either.

**1. Verify before transfer in.** Check the script against the published
`SHA256SUMS` on your connected side, and again on the enclave side after media
transfer:

```powershell
Get-FileHash .\winguard.ps1 -Algorithm SHA256
```

Each report records the `script_sha256` of the build that produced it, so an
auditor can prove which version ran.

**2. Scan.** `.\winguard.ps1 -Bundle` — works on a Server Core install with no
network, no DNS and no default route.

**3. Track drift without a SIEM.** Keep each JSON and feed it back next time with
`-Baseline`. The report lists every check that is **NEW**, **REGRESSED**,
**FIXED** or **CHANGED**.

**4. Record accepted risk.** Enclaves always have documented deviations. Put them
in a waiver file and they show as `WAIVED` (with the reason) instead of failures,
and are excluded from the score:

```
# enclave-waivers.txt
AIR-TELEM-4   | MAPS kept on per vendor EDR integration, CAB-2291
CIS-18.10.3.1 | Breaks the line-of-business print path, RISK-0147
```

Waiving a base ID also covers auto-suffixed duplicates (`CIS-1.1.1` covers `CIS-1.1.1.2`).

**5. Transfer out.** `-Bundle` produces `WinGuard_<host>_<ts>.zip` containing the
reports, a `MANIFEST.txt` (host, operator, script hash, summary) and `SHA256SUMS`,
and prints the bundle hash for your media transfer log.

### Air-gap checks (`-Mode airgap`)

| ID | Checks |
|---|---|
| AIR-NET-1..6 | Default gateway, multi-homed host, IP forwarding, RRAS, ICS, HTTP/WinHTTP proxy (credentials masked) |
| AIR-DNS-1 | Public (non-private) DNS resolvers — egress path and DNS-tunnel channel |
| AIR-RF-1..4 | Wi-Fi, Bluetooth, cellular/WWAN, USB tethering/RNDIS adapters **and** their services |
| AIR-DMA-1..2 | DMA under lock, device installation restrictions for DMA-capable classes |
| AIR-USB-1 | Removable-disk write denial |
| AIR-SVC-1..10 | DiagTrack, dmwappushservice, Delivery Optimization, WER, Sync Host, Maps, Retail Demo, Insider, Remote Assistance, Mobile Hotspot |
| AIR-TELEM-1..7 | Telemetry level, WER, CEIP, Defender MAPS, sample submission, root-cert auto-update, NCSI probing |
| AIR-WU-1..4 | WSUS vs internet, dual scan, Delivery Optimization peering mode, Microsoft Store |
| AIR-PATCH-1..2 | Days since last update, **Defender signature age** — the risk that actually materialises on a disconnected host |
| AIR-TIME-1 | Public vs enclave-internal NTP peers |
| AIR-TUN-1..5 | Teredo / 6to4 / ISATAP, inbound RDP-WinRM-SSH surface, OpenSSH port/agent/tunnel forwarding |
| AIR-LOG-1 | Event forwarding to a public destination |

Public destinations are classified by private-range IP checks plus a list of
well-known internet domains (`$script:PublicPatterns` near the top of the air-gap
section — extend it for your environment). Names are **never resolved**, so an
unknown internal hostname is treated as internal rather than producing noise.

---

## 🖥️ Supported OS Versions

WinGuard **auto-detects the build number and domain role** and applies the matching checks:

| Version | Build | CIS Benchmark | DISA STIG | Notes |
|---|---|---|---|---|
| Server 2016 | 14393 | v3.0.0 L1 | V2R10 | Full coverage |
| Server 2019 | 17763 | v3.0.0 L1 | V3R8 | Full coverage |
| Server 2022 | 20348 | v4.0.0 L1 | V2R8 | Full coverage + MS Baseline |
| Server 2025 | 26100+ | v1.0.0 L1 | V1R1 | Full coverage + MS Baseline |
| Server 2012 / 2012 R2 | 9200 / 9600 | — | — | Out of support; audited against the 2016 baseline, flagged best-effort |
| Windows 10 / 11 | — | — | — | Best-effort against the nearest server baseline |

Member Server and Domain Controller rules are selected separately: a DC gets the
DC variant of every rule that has one (53 CIS rules and 29 STIG rules differ),
rather than being failed against member-server expectations.

---

## 📊 HTML Report Features

The report is a standalone HTML file — no server required, open in any browser.

- **Compliance Score** — `pass ÷ (pass + fail + warn)`; INFO, SKIP and WAIVED don't count against you
- **Per-framework scores** — CIS, STIG, MS Baseline, Posture and Air-gap scored separately
- **Drift panel** — changes since the `-Baseline` scan
- **Offline-locked** — CSP blocks all network loads; every value HTML-escaped
- **Summary cards** — PASS / FAIL / WARN / WAIVED / INFO / SKIP at a glance
- **Non-admin banner** — shows how many checks were privilege-skipped
- **Filter buttons** — by status *and* by framework, combinable
- **Live search** — filter by check ID, category, finding text, registry path or benchmark reference
- **Benchmark references** — every finding cites the recommendation number for *your* OS (e.g. `CIS 2022 2.3.1.2`, `V-254475 / legacy WN22-00-000150`)
- **Remediation** — every FAIL/WARN shows the exact PowerShell or `gpedit.msc` fix

---

## 📁 Output Files

```
winguard_reports\        (if created by the script: Administrators + SYSTEM + you)
├── WinGuard_<hostname>_<timestamp>.html      ← Human dashboard
├── WinGuard_<hostname>_<timestamp>.json      ← Machine-readable / baseline input
├── WinGuard_<hostname>_<timestamp>.csv       ← Spreadsheet / GRC import
└── WinGuard_<hostname>_<timestamp>.zip       ← with -Bundle: reports + MANIFEST + SHA256SUMS
```

Exit codes: `0` scan completed · `1` usage/setup error (or no checks applicable)
· `2` FAILs present (only with `-Strict`).

---

## 🔒 Production Safety

| Feature | Detail |
|---|---|
| ✅ Read-only | Zero system modifications made |
| ✅ No service restarts | Nothing interrupted |
| ✅ Configurable throttle | `-Throttle 200` for I/O-sensitive systems |
| ✅ No network probing | All checks are local only, unless `-IncludeDomainPolicy` is passed |
| ✅ No port scanning | Listening ports are read from local socket state |
| ✅ Non-admin safe | Runs without elevation, skips privileged checks gracefully |
| ✅ No installs | No modules, no packages, no downloads |
| ✅ Protected output | A report directory the script creates is ACL'd to Administrators, SYSTEM and the account that ran the scan. A directory that already existed is left untouched — the script will not re-permission someone else's folder |

For very busy production systems:

```powershell
.\winguard.ps1 -Throttle 500
```

---

## 🔧 Multi-Host Automation

```powershell
$hosts = 'web01','db01','app01','dc01'
foreach ($h in $hosts) {
    Write-Host "Scanning $h..."
    Copy-Item .\winguard.ps1 "\\$h\C$\Windows\Temp\winguard.ps1" -Force
    Invoke-Command -ComputerName $h -ScriptBlock {
        powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\winguard.ps1 `
            -Quiet -Bundle -Output C:\Windows\Temp\wg_out
    }
    New-Item -ItemType Directory -Path ".\collected\$h" -Force | Out-Null
    Copy-Item "\\$h\C$\Windows\Temp\wg_out\*.zip" ".\collected\$h\" -Force
}
Write-Host 'All done. Reports in .\collected\'
```

---

## 📋 JSON Output — queries

```powershell
$r = Get-Content .\WinGuard_*.json -Raw | ConvertFrom-Json

# All failures with remediation
$r.results | Where-Object status -eq FAIL | Select-Object id, title, remediation

# Compliance summary and per-framework scores
$r.summary
$r.by_framework

# CAT I / High-severity STIG failures
$r.results | Where-Object { $_.framework -eq 'STIG' -and $_.severity -eq 'High' -and $_.status -eq 'FAIL' }

# What regressed since the baseline?
$r.drift | Where-Object { $_.change -in 'REGRESSED','NEW' }

# Count skipped for lack of elevation
$r.summary.priv_skip
```

No JSON tooling inside the enclave? Results are **one JSON object per line**, so
plain text search works:

```powershell
Select-String '"status":"FAIL"' .\WinGuard_*.json
```

---

## 📐 Check Coverage Summary

### CIS (version- and role-aware)

| Area | Checks |
|---|---|
| Account Policies | Password history, age, length, complexity, reversible encryption, lockout threshold/duration/reset, Administrator lockout |
| User Rights Assignment | 51 privilege assignments, with separate DC and member-server expectations |
| Security Options | 74 — accounts, audit, devices, domain controller/member, interactive logon, network access/security, recovery console, shutdown, UAC |
| Advanced Audit Policy | 34 subcategories across all 10 categories |
| Windows Firewall | 23 — profile state, inbound/outbound defaults, logging for Domain/Private/Public |
| MSS (Legacy) | 12 — IP source routing, ICMP redirect, NetBIOS name release, screensaver grace, SYN attack protection |
| MS Security Guide | SMBv1, structured exception overwrite, WDigest, LSASS protection, NetBT NodeType |
| Administrative Templates | 263 — System, Network, Printers, Windows Components (Defender, Remote Desktop, WinRM, PowerShell, Store, OneDrive, Autoplay, LAPS) |
| System Services | Services that must be disabled (print spooler on DC vs MS, and others) |
| Defender ASR | 13 Attack Surface Reduction rules |

### DISA STIG

| Severity | Count (2022/MS) | Areas |
|---|---|---|
| **CAT I** (High) | 18 | Anonymous SID/name translation, anonymous SAM/share enumeration, named-pipe access, LAN Manager auth level, cached credentials, AutoRun/AutoPlay, WinRM Basic/unencrypted, Credential Guard on DCs, blank-password accounts, Installer elevated privileges, act-as-OS / create-token / debug-programs rights, reversible password encryption |
| **CAT II** (Medium) | 201 | Registry policy, user rights, audit policy, account policy, SMBv1 removal, legacy features (Fax, FTP, PNRP, Simple TCP/IP, Telnet/TFTP clients, PowerShell 2.0) |
| **CAT III** (Low) | 12 | Informational and display-level settings |

Every STIG finding cites the current V-ID, the legacy `WN22-xx-xxxxxx` ID, and the
equivalent V-ID on the other supported releases, so a finding can be traced across
STIG revisions.

### Posture (built-in hardening scanner)

| Category | Checks |
|---|---|
| AUTH | WDigest plaintext caching, RunAsPPL, NoLMHash, LM auth level, cached logons, autologon, LAPS, UAC (4), anonymous restrictions |
| USERS | Non-expiring passwords, accounts not requiring a password, account inventory, Administrators group size |
| BOOT | Secure Boot, TPM presence/readiness, ELAM driver policy, `bcdedit` NX / test signing / kernel debug / integrity services |
| CRYP | SSL 2.0/3.0 + TLS 1.0/1.1 disabled (client and server), TLS 1.2 retained, RC4/DES/NULL ciphers, 3DES, MD5, FIPS policy, .NET strong crypto (x86/x64) |
| KRNL | VBS, Credential Guard, HVCI, SEHOP, mandatory ASLR, Kernel DMA protection, PrintNightmare mitigation |
| INSE | SMBv1, PowerShell 2.0 engine, 12 risky services, print spooler, LLMNR, mDNS, WPAD, NetBIOS per-interface, AlwaysInstallElevated, WinRM encryption/Basic, RDP NLA/TLS/encryption |
| LOGG | Script block / module / transcription logging, command-line process auditing, Application/Security/System log sizing, audit-policy coverage, event forwarding, Sysmon |
| MALW | Defender real-time, engine, tamper protection, **signature age**, registered AV products, exclusion count, controlled folder access, PUA protection |
| PKGS | Time since last update, pending reboot |
| SCHD | Unquoted service image paths, machine-wide autoruns, SYSTEM tasks running from user-writable paths |
| SHLL | PowerShell execution policy, Windows Script Host |
| STRG | BitLocker on the OS volume, USBSTOR, Autorun, SMB shares with broad write ACEs |
| TIME | W32Time running, configured time source |
| TOOL | Firewall enabled per profile, default inbound Block, AppLocker/WDAC policy present |
| HRDN | SMB server/client signing, LDAP client signing, DC LDAP signing + channel binding, null-session pipes/shares, listening port inventory, plaintext legacy listeners |

### Local privilege-escalation and bypass checks

These look for exploitable conditions rather than policy compliance, which is a
different question from "does this match the benchmark":

| Check | What it catches |
|---|---|
| `HRD-STRG-5` | **TPM-only BitLocker.** Protected volumes with no pre-boot authentication — the disk unlocks before anyone authenticates, so a stolen machine is readable via LPC/SPI bus sniffing or a DMA attack |
| `HRD-SCHD-4` | **Writable `%PATH%` directories.** Matched by well-known SID, not account name, so it still works on a non-English Windows — the usual reason this check wrongly reports clean |
| `HRD-TOOL-4/5` | **WDAC in audit mode.** A policy that logs what it would have blocked and blocks nothing. Deployed ≠ enforced |
| `HRD-TOOL-6` | **AppLocker with a stopped `AppIDSvc`.** Rules are evaluated by that service, so the policy enforces nothing while the host looks protected |
| `HRD-INSE-31` | **`AlwaysInstallElevated` in both hives.** Only exploitable when HKLM *and* HKCU are set; reported separately so you know whether it is live or one policy change away |
| `HRD-SHLL-3` | **FullLanguage PowerShell under enforced app control**, which means the policy does not cover PowerShell and can be bypassed through it |
| `HRD-KRNL-8/9/10` | Driver co-installers, the DataProtection DMA policy, and whether HVCI is UEFI-locked against a local admin turning it off |
| `HRD-STRG-6/7` | **Recall / Windows AI** policy state, plus on-disk `ukg.db` and `ImageStore` artefacts — evidence it ran, regardless of the current policy |
| `AIR-WU-5` | **WSUS over cleartext HTTP** (pywsus / WSUSpect). An internal WSUS does not make this safe; it only narrows who can reach it |

---

## 🧪 How The Benchmark Data Was Built

The embedded tables are generated by merging the published baselines across all
four OS releases, so one file carries them all and selects the right rows at
runtime (the Windows analogue of RHELGuard's `rhel_ge` version gates):

- **CIS** — transcribed from the CIS Microsoft Windows Server Benchmark PDFs
  (2016 v3.0.0, 2019 v3.0.0, 2022 v4.0.0, 2025 v1.0.0).
- **STIG** — machine-readable rule logic from the DISA STIG XCCDF releases, with
  human-readable titles and legacy IDs taken from the same source.
- **Microsoft Security Baseline** — from the Security Compliance Toolkit, reduced
  to the settings CIS does not already assert identically.

Each row records which releases and roles it applies to, and **what Windows does
when the policy has never been applied**. That last field matters: a hardening
tool that treats every unset value as a failure produces a wall of false findings
on a host that is genuinely fine. WinGuard reports "not configured, and the
shipped default already satisfies this" as a PASS with that explanation, and
"not configured, and the host is exposed" as a FAIL.

---

## 📜 References

- [CIS Microsoft Windows Server Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [DISA STIGs — Microsoft Windows Server](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [Microsoft PowerSTIG](https://github.com/microsoft/PowerStig) *(source of the machine-readable STIG rule data)*
- [HardeningKitty](https://github.com/0x6d69636b/windows_hardening) *(source of the CIS and Microsoft baseline transcriptions)*
- [NIST 800-53](https://nvd.nist.gov/800-53)
- [RHELGuard](https://github.com/zebracherry/RHELGuard) *(the Linux counterpart)*
- [Client-Checker by @LuemmelSec](https://github.com/LuemmelSec/Client-Checker) *(inspiration for the local privilege-escalation checks and the console summary layout)*

---

## 📜 License

MIT — see [LICENSE](LICENSE)
