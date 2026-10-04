# Changelog

## [1.1.0] — 2026-10-04 — PRIVILEGE-ESCALATION CHECKS + CONSOLE SUMMARY

Adds the local privilege-escalation and bypass checks that a benchmark run does
not cover, after comparing WinGuard against
[Client-Checker by @LuemmelSec](https://github.com/LuemmelSec/Client-Checker).
Of its 42 checks, 30 were already covered; these are the 12 that were not.

### New checks (14 new IDs)

Where the two tools disagree on judgement, the reasoning is in the finding text
rather than implied by a colour.

- **`HRD-STRG-5` — BitLocker pre-boot authentication.** Previously only
  `ProtectionStatus` was checked. TPM-only BitLocker unlocks the disk before
  anyone authenticates, so it does not defend against an attacker holding the
  powered-off machine. Protector sets are now classified: TPM+PIN/password
  passes, a removable startup key warns, TPM alone fails.
- **`HRD-SCHD-4` — writable directories on the machine `%PATH%`.** DLL
  search-order hijacking. Identities are matched by **well-known SID**, not by
  account name, so it still works on a non-English Windows — a name comparison
  is the usual way this check is written and the usual reason it reports a clean
  result on a bad host. Reads the machine PATH, not the process PATH, so a
  user-scoped entry is not reported as a system-wide hijack.
- **`HRD-TOOL-4` / `HRD-TOOL-5` — WDAC enforcement status.** WinGuard detected
  whether a policy *existed*; it now reads
  `CodeIntegrityPolicyEnforcementStatus` and the user-mode equivalent, so a
  policy stuck in **audit mode** — logging what it would have blocked and
  blocking nothing — is reported as such.
- **`HRD-TOOL-6` — AppLocker actually enforcing.** A deployed policy with a
  stopped `AppIDSvc` enforces nothing while the host looks protected, so that
  combination is a FAIL rather than a pass.
- **`HRD-INSE-31` — `AlwaysInstallElevated` in both hives.** The escalation
  needs HKLM *and* HKCU; reporting only HKLM could not establish whether it was
  live. Both are now read and the verdict says which.
- **`HRD-SHLL-3` — PowerShell language mode, judged in context.**
  FullLanguage is the Windows default and is not a finding on its own —
  ConstrainedLanguage is a *consequence* of enforced application control, not a
  setting to apply by itself. So: ConstrainedLanguage passes; FullLanguage with
  app control enforced is a FAIL (the policy does not cover PowerShell and can
  be bypassed through it); FullLanguage without app control is INFO.
- **`HRD-KRNL-8`** driver co-installers (`DisableCoInstallers`, both the legacy
  and policy locations), **`HRD-KRNL-9`** the DataProtection
  `DeviceLock\AllowDirectMemoryAccess` policy — a different control from the
  `DmaSecurity` value `HRD-KRNL-6` already covered — and **`HRD-KRNL-10`** HVCI
  `LockConfiguration`, which decides whether a local administrator can turn
  memory integrity off with a registry write and a reboot.
- **`HRD-STRG-6` / `HRD-STRG-7` — Recall / Windows AI.** Policy state across the
  machine hive and every loaded user hive, plus on-disk `ukg.db` and `ImageStore`
  artefacts, which are evidence it ran regardless of the policy now.
- **`HRD-INSE-32` — IPv6 binding (mitm6).** Reported as INFO, deliberately not
  failed: mitm6 abuses rogue DHCPv6/RA on the wire, Microsoft does not support
  disabling IPv6, and neither CIS nor STIG requires it. RA Guard and DHCPv6
  Guard are the actual fix, and the finding says so.
- **`HRD-PKGS-3`** installed software inventory, and **`AIR-WU-5`** WSUS reached
  over cleartext HTTP (pywsus / WSUSpect) — independently exploitable even when
  the WSUS server itself is internal, which `AIR-WU-1` alone did not capture.
- **`HRD-AUTH-13`–`HRD-AUTH-18` — Default Domain Password Policy**, behind the
  new `-IncludeDomainPolicy` switch. The account-policy rows in the CIS and STIG
  sections read the **local** security policy, which does not govern domain
  accounts on a domain-joined host. This is the only check that leaves the
  machine (one LDAP query to its own DC), so it is off by default and runs
  automatically only on a domain controller, where the data is local. The
  finding text flags that a fine-grained password policy can override it.

### Console output

Reworked along the lines of Client-Checker, which is easier to read live:

- Section banners are now boxed and print the **reference URLs** for that
  section, so a finding can be argued from the source without leaving the
  terminal.
- A **results-by-category table** at the end (OK / MAYBE / BAD / INFO / N/T per
  category and framework), coloured by the worst result in each row.
- A **"findings to act on"** table, worst first by status then severity. A
  ~950-check run cannot print one row per check and stay readable, so this is
  capped at 40 with a pointer to the reports for the rest.
- Colours follow the convention the team already reads: green OK, magenta
  "might be", red bad, yellow could-not-test.

### Fixed

- Checks that could silently produce **no result at all** on hosts lacking a
  data source (`HRD-TOOL-5` without `Win32_DeviceGuard`, `HRD-INSE-32` without
  `Get-NetAdapterBinding`, `AIR-WU-5` with no WSUS configured) now always emit a
  row. A check that appears on some hosts and not others shows up in the
  `-Baseline` drift panel as a check that was removed, which is noise in exactly
  the report meant to show real change.

## [1.0.0] — 2026-10-04 — INITIAL RELEASE

First release of WinGuard, the Windows Server counterpart to
[RHELGuard](https://github.com/zebracherry/RHELGuard). Same check model, same
report schema, same options and the same air-gap discipline, so a mixed Linux
and Windows estate can be audited and tracked the same way.

### Frameworks

- **CIS Microsoft Windows Server Benchmarks**, Level 1 — Server 2016 v3.0.0,
  2019 v3.0.0, 2022 v4.0.0 and 2025 v1.0.0. 512 merged recommendations, with the
  Member Server and Domain Controller variants kept separate (53 rules differ by
  role) so a DC is never failed against member-server expectations.
- **DISA STIG** — Server 2016 V2R10, 2019 V3R8, 2022 V2R8 and 2025 V1R1.
  231 automatable rules (18 CAT I, 201 CAT II, 12 CAT III) plus 34 rules that
  genuinely need a human, emitted as INFO under `-IncludeManual` so a STIG
  checklist can be completed without pretending they were tested.
- **Microsoft Security Baseline** (Security Compliance Toolkit) for Server 2022
  and 2025 — 192 settings, reduced to those CIS does not already assert
  identically. The 27 where Microsoft and CIS disagree on the value are kept and
  marked `differs-from-CIS`, because that disagreement is what an auditor needs
  to see rather than have hidden.
- **Hardening posture** — a built-in scanner of ~93 checks across the same 15
  categories RHELGuard uses (AUTH BOOT CRYP INSE KRNL LOGG MALW PKGS SCHD SHLL
  STRG TIME TOOL USERS HRDN), covering the things that are wrong in practice but
  that no single benchmark line item asserts: WDigest caching, LSASS protection,
  TLS/cipher-suite state, VBS/Credential Guard/HVCI, PrintNightmare, LLMNR and
  NetBIOS, unquoted service paths, SYSTEM tasks in user-writable directories,
  Defender signature age, BitLocker, firewall posture and application control.
- **Air-gap isolation** — ~42 checks for disconnected enclaves: egress paths and
  bridging, radios (Wi-Fi, Bluetooth, WWAN, USB tethering) including their
  services, DMA ports, removable media, phone-home services, telemetry and
  sample submission, update source (WSUS vs internet, dual scan, Delivery
  Optimization peering), IPv6 transition tunnels, SSH port forwarding, log
  forwarding destinations, and patch and signature currency.

### Design

- **Single self-contained `.ps1`.** PowerShell 3.0+ (Server 2012 and later),
  no modules, no packages, nothing fetched. The benchmark tables are embedded
  and version-gated, which is what makes the tool air-gap safe.
- **Auto-detection.** Build number and `ProductType` select the OS baseline and
  the MS/DC rule variants. Server 2012/2012 R2 and client SKUs are audited
  against the nearest available baseline and clearly flagged best-effort rather
  than refused.
- **"Not configured" is its own state.** Every table row records what Windows
  does when the policy has never been applied. Where the shipped default already
  satisfies the recommendation, the result is a PASS that says so; where it does
  not, it is a FAIL that names the default. A tool that treats every unset value
  as a failure produces a wall of false findings on a host that is fine.
- **Non-admin safe.** Runs unelevated, skips what needs elevation (account
  policy, user rights, `auditpol`, `bcdedit`, WinHTTP proxy) and marks those
  SKIP. Skipped checks are excluded from the score, so a non-admin run does not
  make a well-configured host look broken.
- **Read-only.** No system modifications, no service restarts, no network
  probing, no port scanning. Listening ports are read from local socket state.
- **Per-user policy done properly.** The four STIG rules that target
  `HKEY_CURRENT_USER` are evaluated against every loaded user hive plus the
  default profile, not against whichever profile happens to be running the scan.
- **Reports.** HTML dashboard (CSP-locked so it can never load or send
  anything), JSON (one result per line, so plain text search works where there is
  no JSON tooling), and CSV with spreadsheet-formula-injection guarding. Each
  report records the `script_sha256` that produced it. Output directory is ACL'd
  to Administrators and SYSTEM — the equivalent of RHELGuard's `umask 077`.
- **Enclave workflow.** `-Baseline` for drift (NEW / REGRESSED / FIXED /
  CHANGED), `-Waivers` for documented accepted risk, `-Bundle` for a transfer
  zip with MANIFEST and SHA256SUMS, `-Strict` for CI.
- **Benchmark citations.** Every finding cites the recommendation number for the
  *detected* OS — `CIS 2022 2.3.1.2`, `V-254475 / legacy WN22-00-000150` — plus
  the equivalent V-ID on the other supported releases, so a finding can be traced
  across STIG revisions.

### Verified

The engine was exercised against a simulated Server 2022 member server covering
all 801 applicable benchmark rows and every check method (registry, per-user
registry, `secedit`, account policy, `auditpol` subcategories, user rights,
services, Windows features, security options, built-in accounts, Defender ASR),
confirming one result per applicable row, no unresolved categories, and
remediation text on every FAIL and WARN. Unit tests cover the comparator (all 13
operators), the OS/role applicability matcher, and the private/public address
classifier. Reports are validated as strict JSON, well-formed CSP-locked HTML,
and CSV with no formula-injection-prone cells.

Notable issues found and fixed during that verification:

- **`continue` inside a PowerShell `switch` does not continue the enclosing
  loop** — it only advances the switch. Every specialised check method
  (`auditpol`, user rights, features, built-in accounts, per-user registry and
  others) therefore recorded its result and then fell through to the generic
  evaluation and recorded a *second*, wrong result. User rights alone were
  double-counted 134 times instead of 67. The switch now sets an explicit flag
  that is honoured after it.
- `[ref]` on an array element silently discards the write in PowerShell, so the
  IPv4 private-address classifier read every octet as 0 and reported every
  private address — including the whole of RFC1918 — as public, failing the
  air-gap egress checks on correctly isolated hosts.
- `Split-Path -Leaf ''` is a parameter-binding error, so a run without
  `-Baseline` aborted the JSON writer part-way and left a truncated report that
  looked valid. Report writers now fail loudly and delete the fragment instead.
- `-b` (Baseline) and `-B` (Bundle) collided: PowerShell parameter aliases are
  case-insensitive, unlike the shell flags RHELGuard uses. `-Bundle` no longer
  has a single-letter alias.
- PowerSTIG transcribes some identity lists with the sentence's full stop
  attached, which split 21 otherwise-identical rules across releases during the
  merge and lost their cross-version V-ID mapping.
