<#
.SYNOPSIS
    WinGuard - Windows Server Security Audit Tool (CIS + DISA STIG + Microsoft Baseline)

.DESCRIPTION
    A single, self-contained PowerShell script that audits Windows Server against
    CIS Benchmarks, DISA STIGs and the Microsoft Security Baseline, plus a built-in
    hardening scanner and air-gap isolation checks. Produces HTML + JSON + CSV reports.

    100% air-gap safe - no internet connection required, zero external dependencies,
    no modules to install, nothing fetched, nothing phoned home. Read-only: the
    script makes no changes to the system.

.PARAMETER Mode
    cis | stig | baseline | posture | airgap | all    (default: all)

.PARAMETER Output
    Output directory (default: .\winguard_reports). If the script creates it,
    it is ACL'd to Administrators, SYSTEM and the account that ran the scan. If
    it already exists, its permissions are left untouched.

.PARAMETER Throttle
    Milliseconds to pause between checks (default: 50)

.PARAMETER Baseline
    A previous WinGuard JSON report - show drift since that scan

.PARAMETER Waivers
    Accepted deviations, one "CHECK-ID | reason" per line

.PARAMETER MaxPatchAge
    Days since the last installed update before it is flagged (default: 90)

.PARAMETER MaxSignatureAge
    Days since the last Defender signature update before it is flagged (default: 7)

.PARAMETER Bundle
    Pack reports + MANIFEST + SHA256SUMS into a .zip for transfer off the enclave.
    Spelled out in full (or as -Bu): -B is reserved for -Baseline, because
    PowerShell parameter aliases are not case-sensitive.

.PARAMETER Strict
    Exit 2 if any FAIL remains (for CI / automation)

.PARAMETER IncludeDomainPolicy
    Also audit the Default Domain Password Policy. This is the only check that
    leaves the host: it makes one LDAP query to this machine's own domain
    controller, so it is off by default to keep the rest of the tool strictly
    local. On a domain controller it runs anyway, because there it is local.

    It matters because the account-policy rows in the CIS/STIG sections read the
    LOCAL security policy, which does not govern domain accounts.

.PARAMETER IncludeManual
    Also emit the STIG rules that cannot be checked automatically, as INFO rows,
    so the report covers the full STIG rather than just the automatable part.

.PARAMETER Quiet
    Suppress per-check console output (the summary is still printed)

.EXAMPLE
    .\winguard.ps1
    Full scan, all frameworks, reports in .\winguard_reports

.EXAMPLE
    .\winguard.ps1 -Mode cis -Output C:\Audit
    CIS Benchmark only, custom output directory

.EXAMPLE
    .\winguard.ps1 -Baseline .\last_quarter.json -Waivers .\enclave-waivers.txt -Bundle -Strict
    Quarterly enclave audit: compare to the last run, apply approved waivers,
    bundle for transfer, and fail the pipeline if anything is still open.

.NOTES
    Version : 1.1.1
    Covers  : Windows Server 2016, 2019, 2022, 2025 (auto-detected; 2012/2012 R2
              best-effort, Windows 10/11 best-effort)
    Sources : CIS Microsoft Windows Server Benchmarks (2016 v3.0.0, 2019 v3.0.0,
              2022 v4.0.0, 2025 v1.0.0)
              DISA STIG (Server 2016 V2R10, 2019 V3R8, 2022 V2R8, 2025 V1R1)
              Microsoft Security Baseline / Security Compliance Toolkit
    License : MIT

    PRODUCTION SAFE
      - 100% read-only. Zero system modifications.
      - Configurable throttle prevents I/O spikes on busy hosts.
      - Non-admin mode: skips privileged checks cleanly, runs everything else.
      - No network probing, no port scanning, no installs.
      - A report directory created by this script is locked down to
        Administrators, SYSTEM and the account that ran the scan (the reports
        describe your weaknesses). A directory that already existed is left
        exactly as it was - the script does not re-permission someone else's
        folder.

.LINK
    https://github.com/zebracherry/WinGuard
#>

[CmdletBinding()]
param(
    [Alias('m')]
    [ValidateSet('cis', 'stig', 'baseline', 'posture', 'airgap', 'all')]
    [string] $Mode = 'all',

    [Alias('o')]
    [string] $Output = '.\winguard_reports',

    [Alias('t')]
    [ValidateRange(0, 600000)]
    [int] $Throttle = 50,

    [Alias('b')]
    [string] $Baseline,

    [Alias('w')]
    [string] $Waivers,

    [Alias('a')]
    [ValidateRange(0, 36500)]
    [int] $MaxPatchAge = 90,

    [ValidateRange(0, 3650)]
    [int] $MaxSignatureAge = 7,

    # No single-letter alias: PowerShell parameter aliases are case-insensitive,
    # so a '-B' here would collide with '-b' for -Baseline. PowerShell's own
    # prefix matching means '-Bu' already works.
    [switch] $Bundle,

    [switch] $Strict,

    [switch] $IncludeManual,

    [switch] $IncludeDomainPolicy,

    [Alias('q')]
    [switch] $Quiet
)

# Deliberately NOT using Set-StrictMode or a terminating ErrorActionPreference.
# A hardening audit reads hundreds of places that may legitimately not exist on a
# given host or SKU; under strict/stop settings a single absent registry key or an
# access-denied WMI class aborted the whole scan and produced no report at all.
# Every check handles its own errors instead - the same approach RHELGuard takes.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
$script:ToolName    = 'WinGuard'
$script:ToolVersion = '1.1.1'
$script:ToolEngine  = 'powershell'

$script:StartTime  = Get-Date
$script:ReportTs   = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:ScriptSha  = 'unavailable'

# Counters
$script:Counts = @{
    PASS = 0; FAIL = 0; WARN = 0; INFO = 0; SKIP = 0; WAIVED = 0
    TOTAL = 0; PRIV_SKIP = 0
}

# Results are accumulated as objects and rendered once at the end
$script:Results    = New-Object System.Collections.ArrayList
$script:SeenIds    = @{}
$script:WaiverMap  = @{}
$script:DriftRows  = New-Object System.Collections.ArrayList
$script:DriftNew   = 0
$script:DriftFixed = 0

# Detected platform (filled in by Get-WgPlatform)
$script:OsCaption   = 'Unknown'
$script:OsVersion   = 'Unknown'
$script:OsBuild     = 0
$script:OsToken     = ''        # 2016 | 2019 | 2022 | 2025 | 2012R2 | 10 | 11
$script:OsRole      = 'MS'      # MS (member/standalone) | DC
$script:IsServer    = $true
$script:IsDC        = $false
$script:IsAdmin     = $false
$script:HostName    = $env:COMPUTERNAME
$script:DomainRole  = 'Unknown'

# Caches - populated lazily, each at most once per run
$script:SecEdit      = $null
$script:SecEditTried = $false
$script:AuditPol     = $null
$script:AuditTried   = $false
$script:FeatureCache = $null
$script:MpPref       = $null
$script:MpPrefTried  = $false


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
function Write-WgLine {
    param([string] $Text, [string] $Color = 'Gray')
    if (-not $script:QuietMode) { Write-Host $Text -ForegroundColor $Color }
}
function Write-WgLog    { param([string] $m) Write-WgLine "[*] $m" 'Cyan' }
function Write-WgBanner {
    param([string] $m, [string[]] $References = @())
    if ($script:QuietMode) { return }
    $w = [Math]::Max(46, $m.Length + 4)
    $rule = '#' * $w
    Write-Host ''
    Write-Host "  $rule" -ForegroundColor DarkCyan
    Write-Host ('  # {0} #' -f $m.PadRight($w - 4)) -ForegroundColor DarkCyan
    Write-Host "  $rule" -ForegroundColor DarkCyan
    foreach ($r in $References) {
        if ($r) { Write-Host "  Reference: $r" -ForegroundColor DarkGray }
    }
    Write-Host ''
}

# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION THROTTLE - keeps the scan from spiking I/O on a busy host
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WgThrottle {
    if ($script:ThrottleMs -gt 0) {
        Start-Sleep -Milliseconds $script:ThrottleMs
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# WMI/CIM WRAPPER
# Get-CimInstance does not exist on PowerShell 2.0 (Server 2008 R2), and
# Get-WmiObject is removed in PowerShell 7. Try the modern call first, fall
# back to the legacy one, so one script covers both ends of the range.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgWmi {
    param([string] $Class, [string] $Filter, [string] $Namespace = 'root\cimv2')
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter -Namespace $Namespace -ErrorAction Stop }
            return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
        }
    } catch { }
    try {
        if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-WmiObject -Class $Class -Filter $Filter -Namespace $Namespace -ErrorAction Stop }
            return Get-WmiObject -Class $Class -Namespace $Namespace -ErrorAction Stop
        }
    } catch { }
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 - Get-FileHash only exists on PowerShell 4.0+, so fall back to .NET
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgSha256 {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 'unavailable' }
    try {
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        }
    } catch { }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::OpenRead($Path)
        try   { return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLower() }
        finally { $fs.Close(); $sha.Dispose() }
    } catch { return 'unavailable' }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY READ - returns $null when the key or the value is absent.
# "Absent" is a meaningful state for a hardening audit (it usually means the
# policy was never applied), so it is reported distinctly from a wrong value.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgRegValue {
    param([string] $Path, [string] $Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $k) { return $null }
        $v = $k.GetValue($Name, $null)
        if ($null -eq $v) { return $null }
        if ($v -is [System.Array]) { return (($v | ForEach-Object { "$_" }) -join ',') }
        return $v
    } catch { return $null }
}

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM DETECTION
# Build number is the reliable discriminator: the caption is localised and the
# major.minor version has not moved since 6.3 / 10.0.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgPlatform {
    $os = Get-WgWmi -Class Win32_OperatingSystem
    if ($os) {
        $script:OsCaption = "$($os.Caption)".Trim()
        $script:OsVersion = "$($os.Version)".Trim()
        $script:IsServer  = ($os.ProductType -ne 1)
        $script:IsDC      = ($os.ProductType -eq 2)
    }

    # Build number: prefer the registry (it carries the UBR), fall back to WMI
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $b  = Get-WgRegValue $cv 'CurrentBuildNumber'
    if (-not $b) { $b = Get-WgRegValue $cv 'CurrentBuild' }
    if (-not $b -and $script:OsVersion -match '^\d+\.\d+\.(\d+)') { $b = $Matches[1] }
    $script:OsBuild = 0
    if ($b) { [void][int]::TryParse("$b", [ref] $script:OsBuild) }

    $ubr = Get-WgRegValue $cv 'UBR'
    if ($ubr) { $script:OsVersion = "$($script:OsVersion) (UBR $ubr)" }

    # Map the build to the baseline family we hold checks for
    $script:OsToken = switch ($script:OsBuild) {
        { $_ -ge 26000 } { '2025'; break }
        { $_ -ge 20348 } { '2022'; break }
        { $_ -ge 17763 } { '2019'; break }
        { $_ -ge 14393 } { '2016'; break }
        { $_ -ge 9600  } { '2012R2'; break }
        { $_ -ge 9200  } { '2012'; break }
        default          { 'unknown' }
    }

    # Client SKUs: audit them against the nearest server baseline, flagged as
    # best-effort, rather than refusing to run.
    if (-not $script:IsServer) {
        if     ($script:OsBuild -ge 22000) { $script:OsToken = '2022' }
        elseif ($script:OsBuild -ge 19041) { $script:OsToken = '2019' }
    }

    $script:OsRole = if ($script:IsDC) { 'DC' } else { 'MS' }
    $script:DomainRole = switch ("$($os.ProductType)") {
        '1' { 'Workstation' }
        '2' { 'Domain Controller' }
        '3' { 'Member / Standalone Server' }
        default { 'Unknown' }
    }

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $script:IsAdmin = $false }

    try { $script:HostName = [System.Net.Dns]::GetHostName() } catch { }
    if (-not $script:HostName) { $script:HostName = $env:COMPUTERNAME }
    if (-not $script:HostName) { $script:HostName = 'unknown' }
}

# Version gates, the Windows analogue of RHELGuard's rhel_ge
function Test-WgBuildAtLeast { param([int] $Build) return ($script:OsBuild -ge $Build) }
function Test-WgOsIn { param([string[]] $Tokens) return ($Tokens -contains $script:OsToken) }

# ─────────────────────────────────────────────────────────────────────────────
# SECEDIT EXPORT - the local security policy database.
# This is the only reliable offline source for account policy, user rights and
# several security options. It needs administrator rights.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgSecEdit {
    if ($script:SecEditTried) { return $script:SecEdit }
    $script:SecEditTried = $true
    if (-not $script:IsAdmin) { return $null }

    $tmp = Join-Path $env:TEMP ("wg_sec_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet 2>&1
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }

        # secedit writes UTF-16LE; reading it as ASCII yields NUL-separated junk
        $lines = Get-Content -LiteralPath $tmp -Encoding Unicode -ErrorAction Stop
        if (-not $lines -or ($lines -join '') -notmatch '\[') {
            $lines = Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue
        }

        $data    = @{}
        $section = ''
        foreach ($line in $lines) {
            $l = "$line".Trim()
            if ($l -match '^\[(.+)\]$') { $section = $Matches[1].Trim(); continue }
            if ($l -match '^([^=]+)=(.*)$') {
                $k = $Matches[1].Trim()
                $v = $Matches[2].Trim()
                $data["$section\$k"] = $v
            }
        }
        $script:SecEdit = $data
    } catch {
        $script:SecEdit = $null
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    return $script:SecEdit
}

function Get-WgSecEditValue {
    param([string] $Key)
    $d = Get-WgSecEdit
    if (-not $d) { return $null }
    if ($d.ContainsKey($Key)) { return $d[$Key] }
    # tolerate section/spelling drift between Windows releases
    foreach ($k in $d.Keys) {
        if ($k -replace '\s', '' -ieq ($Key -replace '\s', '')) { return $d[$k] }
    }
    $leaf = ($Key -split '\\')[-1]
    foreach ($k in $d.Keys) {
        if ((($k -split '\\')[-1]) -ieq $leaf) { return $d[$k] }
    }
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
# SID RESOLUTION - user rights come out of secedit as SIDs. Resolve the ones we
# can locally; leave the rest as raw SIDs rather than guessing (a domain SID is
# not resolvable on an air-gapped member server, and that is fine).
# ─────────────────────────────────────────────────────────────────────────────
$script:SidCache = @{}
function Resolve-WgSid {
    param([string] $Sid)
    $s = "$Sid".Trim().TrimStart('*')
    if (-not $s) { return '' }
    if ($script:SidCache.ContainsKey($s)) { return $script:SidCache[$s] }
    $name = $s
    try {
        $name = (New-Object Security.Principal.SecurityIdentifier($s)).Translate(
            [Security.Principal.NTAccount]).Value
    } catch { $name = $s }
    $script:SidCache[$s] = $name
    return $name
}

# Normalise an account list so "BUILTIN\Administrators" from a benchmark and
# "Administrators" from secedit compare equal, order-independently.
function Normalize-WgAccounts {
    param([string] $List)
    if ([string]::IsNullOrWhiteSpace($List)) { return '' }
    $parts = $List -split '[;,]' | ForEach-Object {
        $p = "$_".Trim()
        if (-not $p) { return }
        if ($p -match '^\*?S-1-') { $p = Resolve-WgSid $p }
        $p = $p -replace '^(BUILTIN|NT AUTHORITY|NT SERVICE|NT VIRTUAL MACHINE|Window Manager)\\', ''
        $p = $p -replace "^$([regex]::Escape($env:COMPUTERNAME))\\", ''
        $p.Trim().ToLower()
    } | Where-Object { $_ } | Sort-Object -Unique
    return ($parts -join ';')
}

# ─────────────────────────────────────────────────────────────────────────────
# AUDIT POLICY - auditpol is the authoritative source for the advanced audit
# subcategories. One bulk CSV export is far cheaper than ~70 individual calls.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgAuditPol {
    if ($script:AuditTried) { return $script:AuditPol }
    $script:AuditTried = $true
    if (-not $script:IsAdmin) { return $null }
    try {
        $raw = & auditpol.exe /get /category:* /r 2>$null
        if (-not $raw) { return $null }
        $map = @{}
        foreach ($row in ($raw | Select-Object -Skip 1)) {
            if (-not "$row".Trim()) { continue }
            # Machine Name,Policy Target,Subcategory,Subcategory GUID,Setting,...
            $f = "$row" -split ','
            if ($f.Count -lt 5) { continue }
            $sub  = $f[2].Trim()
            $guid = $f[3].Trim()
            $set  = $f[4].Trim()
            if ($guid) { $map[$guid.ToLower()] = $set }
            if ($sub)  { $map[$sub.ToLower()]  = $set }
        }
        $script:AuditPol = $map
    } catch { $script:AuditPol = $null }
    return $script:AuditPol
}

function Get-WgAuditSetting {
    param([string] $Key)
    $m = Get-WgAuditPol
    if (-not $m) { return $null }
    $k = "$Key".Trim().ToLower()
    if ($m.ContainsKey($k)) { return $m[$k] }
    $k2 = $k.Trim('{', '}')
    foreach ($cand in @("{$k2}", $k2)) {
        if ($m.ContainsKey($cand)) { return $m[$cand] }
    }
    return $null
}

# Compare an auditpol setting to a benchmark expectation such as
# "Success and Failure" / "Success" / "No Auditing", in either order.
function Test-WgAuditMatch {
    param([string] $Actual, [string] $Expected)
    $norm = {
        param($v)
        $v = "$v".ToLower()
        $s = ($v -match 'success')
        $f = ($v -match 'failure')
        if ($s -and $f) { return 'success and failure' }
        if ($s) { return 'success' }
        if ($f) { return 'failure' }
        return 'no auditing'
    }
    return ((& $norm $Actual) -eq (& $norm $Expected))
}

# ─────────────────────────────────────────────────────────────────────────────
# SERVICES / FEATURES / DEFENDER
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgServiceStart {
    <# Returns Disabled|Manual|Automatic|AutomaticDelayed|Boot|System, or $null
       if the service is not installed. Read from the registry so it works
       without the service control manager cmdlets and without admin. #>
    param([string] $Name)
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $v = Get-WgRegValue $p 'Start'
    if ($null -eq $v) { return $null }
    $delayed = Get-WgRegValue $p 'DelayedAutostart'
    switch ([int] $v) {
        0 { 'Boot' }
        1 { 'System' }
        2 { if ("$delayed" -eq '1') { 'AutomaticDelayed' } else { 'Automatic' } }
        3 { 'Manual' }
        4 { 'Disabled' }
        default { "Unknown($v)" }
    }
}

function Test-WgServiceRunning {
    param([string] $Name)
    try {
        $s = Get-Service -Name $Name -ErrorAction Stop
        return ($s.Status -eq 'Running')
    } catch { return $false }
}

function Get-WgFeatures {
    if ($null -ne $script:FeatureCache) { return $script:FeatureCache }
    $script:FeatureCache = @{}
    if (-not $script:IsServer) { return $script:FeatureCache }
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            foreach ($f in (Get-WindowsFeature -ErrorAction Stop)) {
                if ($f.Name) { $script:FeatureCache[$f.Name.ToLower()] = [bool] $f.Installed }
            }
        }
    } catch { }
    return $script:FeatureCache
}

function Get-WgMpPreference {
    if ($script:MpPrefTried) { return $script:MpPref }
    $script:MpPrefTried = $true
    try {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $script:MpPref = Get-MpPreference -ErrorAction Stop
        }
    } catch { $script:MpPref = $null }
    return $script:MpPref
}

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN GUARD - non-admin callers skip privileged checks gracefully instead of
# reporting a hardened host as broken.
# ─────────────────────────────────────────────────────────────────────────────
function Test-WgNeedsAdmin {
    param([string] $Id, [string] $Title, [string] $Category, [string] $Framework = 'POSTURE')
    if ($script:IsAdmin) { return $true }
    $script:Counts.PRIV_SKIP++
    Add-WgResult -Status 'SKIP' -Id $Id -Title $Title -Category $Category `
        -Framework $Framework -Severity 'Medium' `
        -Description 'ADMINISTRATOR REQUIRED - re-run from an elevated prompt for full coverage.' `
        -Remediation 'Start-Process powershell -Verb RunAs, then re-run winguard.ps1'
    return $false
}

# ─────────────────────────────────────────────────────────────────────────────
# RECORD RESULT
# ─────────────────────────────────────────────────────────────────────────────
function Add-WgResult {
    param(
        [ValidateSet('PASS', 'FAIL', 'WARN', 'INFO', 'SKIP', 'WAIVED')]
        [string] $Status,
        [string] $Id,
        [string] $Title,
        [string] $Category,
        [string] $Description,
        [string] $Remediation = '',
        [string] $Framework = 'POSTURE',
        [string] $Severity = 'Medium',
        [string] $Refs = ''
    )

    # ── Guarantee unique check IDs (baselines and waivers key off them) ──────
    $baseId = $Id
    if ($script:SeenIds.ContainsKey($Id)) {
        $n = $script:SeenIds[$Id] + 1
        $script:SeenIds[$Id] = $n
        $Id = "$baseId.$n"
    } else {
        $script:SeenIds[$Id] = 1
    }

    # ── Waivers: documented, accepted deviations (FAIL/WARN only) ───────────
    if ($script:WaiverMap.Count -gt 0 -and ($Status -eq 'FAIL' -or $Status -eq 'WARN')) {
        $reason = $null
        foreach ($cand in @($Id, $baseId)) {
            if ($script:WaiverMap.ContainsKey($cand.ToLower())) {
                $reason = $script:WaiverMap[$cand.ToLower()]
                break
            }
        }
        if ($null -ne $reason) {
            if (-not $reason) { $reason = '(no reason given)' }
            $Description = "WAIVED (was $Status): $reason - $Description"
            $Status = 'WAIVED'
        }
    }

    $script:Counts.TOTAL++
    $script:Counts[$Status]++

    [void] $script:Results.Add([PSCustomObject] @{
        id          = $Id
        status      = $Status
        title       = $Title
        category    = $Category
        framework   = $Framework
        severity    = $Severity
        description = $Description
        remediation = $Remediation
        refs        = $Refs
        os          = $script:OsToken
        role        = $script:OsRole
        ts          = (Get-Date).ToString('o')
    })

    if (-not $script:QuietMode) {
        $label = "$Id - $Title"
        switch ($Status) {
            'PASS'   { Write-Host '[PASS] ' -ForegroundColor Green     -NoNewline; Write-Host $label }
            'FAIL'   { Write-Host '[FAIL] ' -ForegroundColor Red       -NoNewline; Write-Host $label }
            'WARN'   { Write-Host '[WARN] ' -ForegroundColor Yellow    -NoNewline; Write-Host $label }
            'INFO'   { Write-Host '[INFO] ' -ForegroundColor Cyan      -NoNewline; Write-Host $label }
            'SKIP'   { Write-Host '[SKIP] ' -ForegroundColor DarkGray  -NoNewline; Write-Host $label }
            'WAIVED' { Write-Host '[WAIV] ' -ForegroundColor Magenta   -NoNewline; Write-Host $label }
        }
    }

    Invoke-WgThrottle
}


# ─────────────────────────────────────────────────────────────────────────────
# COMPARATOR
# The benchmark tables use a small, fixed operator set. Keeping it closed means
# every row is evaluated by code that was actually exercised, rather than by an
# expression evaluated at runtime.
#
#   =        equal                        !=       not equal
#   >=  <=   numeric bound                >   <    numeric bound, exclusive
#   <=!0     at most N, and not 0 (0 = "never", which is not a hardening win)
#   >=|0     at least N, or exactly 0 (0 = "forever", which is acceptable)
#   =|0      equal to N, or 0
#   in       one of a comma-separated set
#   in|absent  one of a set, or not present at all
#   contains actual contains the expected substring
#   absent   the value must not exist
# ─────────────────────────────────────────────────────────────────────────────
function Test-WgCompare {
    param([string] $Operator, $Actual, [string] $Expected)

    $a = if ($null -eq $Actual) { '' } else { "$Actual".Trim() }
    $e = "$Expected".Trim()

    # numeric comparison where both sides are numbers
    $an = 0L; $en = 0L
    $aNum = [long]::TryParse($a, [ref] $an)
    $eNum = [long]::TryParse($e, [ref] $en)

    switch ($Operator) {
        '=' {
            if ($aNum -and $eNum) { return ($an -eq $en) }
            return ($a -ieq $e)
        }
        '!=' {
            if ($aNum -and $eNum) { return ($an -ne $en) }
            return ($a -ine $e)
        }
        '>='  { if (-not ($aNum -and $eNum)) { return $false }; return ($an -ge $en) }
        '<='  { if (-not ($aNum -and $eNum)) { return $false }; return ($an -le $en) }
        '>'   { if (-not ($aNum -and $eNum)) { return $false }; return ($an -gt $en) }
        '<'   { if (-not ($aNum -and $eNum)) { return $false }; return ($an -lt $en) }
        '<=!0' {
            if (-not ($aNum -and $eNum)) { return $false }
            return (($an -le $en) -and ($an -ne 0))
        }
        '>=|0' {
            if (-not ($aNum -and $eNum)) { return $false }
            return (($an -ge $en) -or ($an -eq 0))
        }
        '=|0' {
            if (-not ($aNum -and $eNum)) { return $false }
            return (($an -eq $en) -or ($an -eq 0))
        }
        'in' {
            foreach ($opt in ($e -split ',')) {
                $o = "$opt".Trim()
                if (-not $o) { continue }
                $on = 0L
                if ($aNum -and [long]::TryParse($o, [ref] $on)) {
                    if ($an -eq $on) { return $true }
                } elseif ($a -ieq $o) { return $true }
            }
            return $false
        }
        'in|absent' {
            if ($null -eq $Actual) { return $true }
            return (Test-WgCompare -Operator 'in' -Actual $Actual -Expected $e)
        }
        'contains' {
            if (-not $e) { return $true }
            return ($a -and ($a.ToLower().Contains($e.ToLower())))
        }
        'absent' { return ($null -eq $Actual) }
        default  { return ($a -ieq $e) }
    }
}

# Human-readable rendering of an operator, for the finding text
function Format-WgExpectation {
    param([string] $Operator, [string] $Expected)
    switch ($Operator) {
        '='         { "'$Expected'" }
        '!='         { "anything other than '$Expected'" }
        '>='        { "at least $Expected" }
        '<='        { "at most $Expected" }
        '>'         { "more than $Expected" }
        '<'         { "less than $Expected" }
        '<=!0'      { "at most $Expected and not 0" }
        '>=|0'      { "at least $Expected, or 0" }
        '=|0'       { "'$Expected' or 0" }
        'in'        { "one of: $Expected" }
        'in|absent' { "one of: $Expected (or not configured)" }
        'contains'  { "a value containing '$Expected'" }
        'absent'    { 'the value to be absent' }
        default     { "'$Expected'" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# APPLICABILITY
# A row's Applies field is '*' (every supported OS and role) or a comma list of
# '<os>' / '<os>:<role>' tokens. This is the Windows analogue of RHELGuard's
# version gates, and it is what lets one script carry four OS baselines.
# ─────────────────────────────────────────────────────────────────────────────
function Test-WgApplies {
    param([string] $Applies)
    if ([string]::IsNullOrWhiteSpace($Applies) -or $Applies -eq '*') { return $true }
    foreach ($tok in ($Applies -split ',')) {
        $t = "$tok".Trim()
        if (-not $t) { continue }
        if ($t -match '^([^:]+):(.+)$') {
            if ($Matches[1] -eq $script:OsToken -and $Matches[2] -eq $script:OsRole) { return $true }
        } elseif ($t -eq $script:OsToken) {
            return $true
        }
    }
    return $false
}

# Pick out the benchmark reference that matches the detected OS, so the report
# cites the recommendation number the auditor will actually look up.
function Format-WgRefs {
    param([string] $Refs, [string] $Framework)
    if ([string]::IsNullOrWhiteSpace($Refs)) { return '' }
    if ($Refs -match '^\*=(.+)$') {
        $n = $Matches[1]
        if ($Framework -eq 'CIS')  { return "CIS $($script:OsToken) $n" }
        if ($Framework -eq 'STIG') { return $n }
        return $n
    }
    $parts = @()
    $mine  = $null
    foreach ($p in ($Refs -split ';')) {
        if ($p -match '^([^=]+)=(.+)$') {
            $k = $Matches[1]; $v = $Matches[2]
            if ($k -eq $script:OsToken) { $mine = $v }
            elseif ($k -eq 'legacy')    { $parts += "legacy $v" }
        } else { $parts += $p }
    }
    $out = @()
    if ($mine) {
        if ($Framework -eq 'CIS')  { $out += "CIS $($script:OsToken) $mine" }
        elseif ($Framework -eq 'STIG') { $out += $mine }
        else { $out += $mine }
    }
    $out += $parts
    return (($out | Where-Object { $_ }) -join ' / ')
}

# ─────────────────────────────────────────────────────────────────────────────
# NAMED-SETTING LOOKUPS
# A handful of benchmark rows address a setting by its Group Policy name rather
# than by registry path. Map those to a concrete source once, here, rather than
# scattering special cases through the evaluator.
# ─────────────────────────────────────────────────────────────────────────────
$script:AcctPolicyKeys = @{
    'passwordhistorysize'   = 'System Access\PasswordHistorySize'
    'maximumpasswordage'    = 'System Access\MaximumPasswordAge'
    'minimumpasswordage'    = 'System Access\MinimumPasswordAge'
    'minimumpasswordlength' = 'System Access\MinimumPasswordLength'
    'passwordcomplexity'    = 'System Access\PasswordComplexity'
    'cleartextpassword'     = 'System Access\ClearTextPassword'
    'lockoutduration'       = 'System Access\LockoutDuration'
    'lockoutbadcount'       = 'System Access\LockoutBadCount'
    'resetlockoutcount'     = 'System Access\ResetLockoutCount'
}

# Security options addressed by their policy name. 'Kind' selects the source.
$script:SecOptMap = @{
    'accounts: guest account status' = @{
        Kind = 'secedit'; Key = 'System Access\EnableGuestAccount'
        Map  = @{ 'disabled' = '0'; 'enabled' = '1' }
    }
    'accounts: rename administrator account' = @{
        Kind = 'secedit'; Key = 'System Access\NewAdministratorName'
    }
    'accounts: rename guest account' = @{
        Kind = 'secedit'; Key = 'System Access\NewGuestName'
    }
    'network access: allow anonymous sid/name translation' = @{
        Kind = 'secedit'; Key = 'System Access\LSAAnonymousNameLookup'
        Map  = @{ 'disabled' = '0'; 'enabled' = '1' }
    }
    'domain_controller_ldap_server_signing_requirements' = @{
        Kind = 'reg'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        Item = 'LDAPServerIntegrity'
        Map  = @{ 'require signing' = '2'; 'none' = '1' }
    }
}

# secedit stores renamed-account values quoted; strip that for comparison
function Format-WgSecEditString { param([string] $v) return ("$v".Trim().Trim('"')) }

# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION TEXT
# Generated from the row rather than stored, which keeps the embedded tables
# small and guarantees the fix always matches the value actually asserted.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgRemediation {
    param([string] $Method, [string] $Target, [string] $Item,
          [string] $Operator, [string] $Expected, [string] $Category)

    switch ($Method) {
        'reg' {
            if ($Operator -eq 'absent') {
                return "Remove-ItemProperty -Path '$Target' -Name '$Item' -Force"
            }
            $val = ($Expected -split ',')[0]
            $type = if ($val -match '^-?\d+$') { 'DWord' } else { 'String' }
            return ("New-Item -Path '$Target' -Force | Out-Null; " +
                    "New-ItemProperty -Path '$Target' -Name '$Item' " +
                    "-PropertyType $type -Value '$val' -Force")
        }
        'secedit' {
            return ("gpedit.msc >> $Category, or: secedit /export /cfg C:\wg.inf ; " +
                    "set '$Target' = $Expected ; secedit /configure /db secedit.sdb /cfg C:\wg.inf")
        }
        'accountpolicy' {
            return ("gpedit.msc >> Computer Configuration >> Windows Settings >> " +
                    "Security Settings >> Account Policies - set '$Target' to " +
                    (Format-WgExpectation $Operator $Expected))
        }
        'auditpol' {
            $s = if ($Expected -match 'success') { 'enable' } else { 'disable' }
            $f = if ($Expected -match 'failure') { 'enable' } else { 'disable' }
            return "auditpol /set /subcategory:`"$Target`" /success:$s /failure:$f"
        }
        'auditsub' {
            $s = if ($Item -ieq 'Success') { 'enable' } else { 'disable' }
            $f = if ($Item -ieq 'Failure') { 'enable' } else { 'disable' }
            if ($Operator -eq 'absent') { $s = 'disable'; $f = 'disable' }
            $flag = if ($Item -ieq 'Success') { "/success:$s" } else { "/failure:$f" }
            return "auditpol /set /subcategory:`"$Target`" $flag"
        }
        'userright' {
            $who = if ($Expected) { $Expected } else { '(no accounts - remove all entries)' }
            return ("gpedit.msc >> Computer Configuration >> Windows Settings >> " +
                    "Security Settings >> Local Policies >> User Rights Assignment - " +
                    "set '$Target' to: $who")
        }
        'service' { return "Set-Service -Name '$Target' -StartupType $Expected" }
        'feature' {
            if ($Expected -eq 'Absent') { return "Uninstall-WindowsFeature -Name $Target -Remove" }
            return "Install-WindowsFeature -Name $Target"
        }
        'secopt' {
            return ("gpedit.msc >> Computer Configuration >> Windows Settings >> " +
                    "Security Settings >> Local Policies >> Security Options - " +
                    "set '$Target' to '$Expected'")
        }
        'localaccount' {
            if ($Operator -eq '!=') {
                return "Rename the built-in account with RID $Target to a non-default name"
            }
            return "Disable the built-in account with RID $Target"
        }
        'asr' {
            return ("Add-MpPreference -AttackSurfaceReductionRules_Ids $Target " +
                    "-AttackSurfaceReductionRules_Actions Enabled")
        }
        default { return '' }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN ACCOUNTS (RID 500 / 501)
# ─────────────────────────────────────────────────────────────────────────────
$script:LocalAcctCache = $null
function Get-WgLocalBuiltins {
    if ($null -ne $script:LocalAcctCache) { return $script:LocalAcctCache }
    $script:LocalAcctCache = @{}
    try {
        $accts = Get-WgWmi -Class Win32_UserAccount -Filter "LocalAccount=True"
        foreach ($a in $accts) {
            if ("$($a.SID)" -match '-(\d+)$') {
                $rid = $Matches[1]
                $script:LocalAcctCache[$rid] = [PSCustomObject] @{
                    Name = "$($a.Name)"; Disabled = [bool] $a.Disabled
                }
            }
        }
    } catch { }
    return $script:LocalAcctCache
}

# ─────────────────────────────────────────────────────────────────────────────
# DEFENDER ATTACK SURFACE REDUCTION
# ─────────────────────────────────────────────────────────────────────────────
$script:AsrCache = $null
function Get-WgAsrRules {
    if ($null -ne $script:AsrCache) { return $script:AsrCache }
    $script:AsrCache = @{}
    $mp = Get-WgMpPreference
    if ($mp -and $mp.AttackSurfaceReductionRules_Ids) {
        $ids  = @($mp.AttackSurfaceReductionRules_Ids)
        $acts = @($mp.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $act = if ($i -lt $acts.Count) { "$($acts[$i])" } else { '' }
            $script:AsrCache["$($ids[$i])".ToLower()] = $act
        }
    }
    # Group Policy also writes the rules here; useful when the module is absent
    $gp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    try {
        $k = Get-Item -LiteralPath $gp -ErrorAction Stop
        foreach ($n in $k.GetValueNames()) {
            $key = "$n".ToLower()
            if (-not $script:AsrCache.ContainsKey($key)) {
                $script:AsrCache[$key] = "$($k.GetValue($n))"
            }
        }
    } catch { }
    return $script:AsrCache
}

# ─────────────────────────────────────────────────────────────────────────────
# PER-USER POLICY HIVES
# A few STIG rules target HKEY_CURRENT_USER. Reading HKCU would only describe
# whichever profile happens to be running the scan, which is not what the rule
# means - it requires the setting for users. So the check is evaluated against
# every loaded user hive plus the default profile, and the worst result wins.
# ─────────────────────────────────────────────────────────────────────────────
$script:UserHives = $null
function Get-WgUserHives {
    if ($null -ne $script:UserHives) { return $script:UserHives }
    $hives = New-Object System.Collections.ArrayList
    try {
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -Name HKU -PSProvider Registry -Root 'HKEY_USERS' -ErrorAction Stop
        }
        foreach ($k in (Get-ChildItem 'HKU:\' -ErrorAction Stop)) {
            $leaf = Split-Path -Leaf $k.Name
            if ($leaf -like '*_Classes') { continue }
            # Real interactive profiles, plus the template new profiles inherit
            if ($leaf -eq '.DEFAULT' -or $leaf -match '^S-1-5-21-[\d-]+$') {
                [void] $hives.Add([PSCustomObject] @{
                    Path = "HKU:\$leaf"
                    Name = if ($leaf -eq '.DEFAULT') { 'default profile' } else { (Resolve-WgSid $leaf) }
                })
            }
        }
    } catch { }
    $script:UserHives = $hives
    return $script:UserHives
}


# ─────────────────────────────────────────────────────────────────────────────
# USER RIGHTS (from the secedit export's [Privilege Rights] section)
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgUserRight {
    param([string] $Constant)
    $d = Get-WgSecEdit
    if (-not $d) { return $null }
    $k = "Privilege Rights\$Constant"
    foreach ($cand in $d.Keys) {
        if ($cand -ieq $k) { return $d[$cand] }
    }
    # A right held by nobody is simply absent from the export, which is a real
    # answer (empty), not a failure to read it.
    return ''
}

# ─────────────────────────────────────────────────────────────────────────────
# TABLE-DRIVEN CHECK RUNNER
#
# Row layout (TAB separated):
#  0 Id  1 CategoryCode  2 Title  3 Method  4 Target  5 Item
#  6 Operator  7 Expected  8 WindowsDefault  9 Severity  10 Applies  11 Refs
#
# Field 8 is what Windows does when the policy has never been applied. It is
# the difference between "not configured, and the shipped default is already
# what the benchmark wants" and "not configured, and the host is exposed" -
# a distinction that otherwise produces a wall of false failures on a host
# that is genuinely fine.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WgTable {
    param(
        [string[]] $Rows,
        [string] $Framework,
        [hashtable] $Categories
    )

    $sevName = @{ 'H' = 'High'; 'M' = 'Medium'; 'L' = 'Low' }

    foreach ($line in $Rows) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = $line -split "`t"
        if ($f.Count -lt 12) { continue }

        $id = $f[0]; $catCode = $f[1]; $title = $f[2]; $method = $f[3]
        $target = $f[4]; $item = $f[5]; $op = $f[6]; $exp = $f[7]
        $dflt = $f[8]; $sevCode = $f[9]; $applies = $f[10]; $refs = $f[11]

        if (-not (Test-WgApplies $applies)) { continue }

        $category = if ($Categories -and $Categories.ContainsKey($catCode)) {
            $Categories[$catCode]
        } else { $catCode }
        $severity = if ($sevName.ContainsKey($sevCode)) { $sevName[$sevCode] } else { 'Medium' }
        $refText  = Format-WgRefs -Refs $refs -Framework $Framework
        $rem      = Get-WgRemediation -Method $method -Target $target -Item $item `
                        -Operator $op -Expected $exp -Category $category

        # A benchmark deviation at High/Medium is a failure; Low-severity items
        # are warnings, so the score is not dominated by cosmetic findings.
        $badStatus = if ($sevCode -eq 'L') { 'WARN' } else { 'FAIL' }

        $actual   = $null
        $haveData = $true
        $source   = ''
        # Set by any branch that records its own result. A `continue` inside a
        # PowerShell switch only advances the switch, so without this flag those
        # branches would fall through and be recorded a second time by the
        # generic evaluation below.
        $recorded = $false

        switch ($method) {
            'reg' {
                $actual = Get-WgRegValue $target $item
                $source = "$target\$item"
            }
            'reguser' {
                $hives = Get-WgUserHives
                if ($hives.Count -eq 0) {
                    Add-WgResult -Status 'SKIP' -Id $id -Title $title -Category $category `
                        -Framework $Framework -Severity $severity -Refs $refText `
                        -Description ('No user profile hive is loaded, so this per-user policy ' +
                                      'cannot be evaluated. Re-run while a user profile is loaded.')
                    $recorded = $true; break
                }
                $bad = @(); $good = @()
                foreach ($hv in $hives) {
                    $v = Get-WgRegValue "$($hv.Path)\$target" $item
                    if (Test-WgCompare -Operator $op -Actual $v -Expected $exp) {
                        $good += $hv.Name
                    } else {
                        $bad += ("{0} ({1})" -f $hv.Name,
                                 $(if ($null -eq $v) { 'not configured' } else { $v }))
                    }
                }
                $ok = ($bad.Count -eq 0)
                Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                    -Title $title -Category $category -Framework $Framework -Severity $severity `
                    -Refs $refText `
                    -Remediation $(if ($ok) { '' } else {
                        ("Set HKCU:\$target\$item for all users (deploy via Group Policy " +
                         'user configuration so new profiles inherit it)') }) `
                    -Description $(if ($ok) {
                        ("$item is compliant in all $($hives.Count) loaded user hive(s): " +
                         (($good | Select-Object -First 6) -join ', ') + '.')
                    } else {
                        ("$item does not meet $(Format-WgExpectation $op $exp) in " +
                         "$($bad.Count) of $($hives.Count) user hive(s): " +
                         (($bad | Select-Object -First 6) -join '; ') + '.')
                    })
                $recorded = $true; break
            }
            'secedit' {
                if (-not $script:IsAdmin) { $haveData = $false; break }
                $actual = Get-WgSecEditValue $target
                $source = "Local Security Policy [$target]"
            }
            'accountpolicy' {
                if (-not $script:IsAdmin) { $haveData = $false; break }
                $key = $script:AcctPolicyKeys[$target.ToLower()]
                if (-not $key) { $key = "System Access\$target" }
                $actual = Get-WgSecEditValue $key
                $source = "Account Policy [$target]"
                # STIG expresses two of these as Enabled/Disabled
                if ($exp -ieq 'Enabled')  { $exp = '1' }
                if ($exp -ieq 'Disabled') { $exp = '0' }
            }
            'auditpol' {
                if (-not $script:IsAdmin) { $haveData = $false; break }
                $actual = Get-WgAuditSetting $target
                $source = "auditpol subcategory $target"
                if ($null -eq $actual) { $haveData = $false; break }
                $ok = Test-WgAuditMatch -Actual $actual -Expected $exp
                Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                    -Title $title -Category $category -Framework $Framework -Severity $severity `
                    -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                    -Description $(if ($ok) {
                        "Audit subcategory is '$actual', as required."
                    } else {
                        "Audit subcategory is '$actual'; expected '$exp'."
                    })
                $recorded = $true; break
            }
            'auditsub' {
                if (-not $script:IsAdmin) { $haveData = $false; break }
                $actual = Get-WgAuditSetting $target
                $source = "auditpol subcategory '$target'"
                if ($null -eq $actual) { $haveData = $false; break }
                # STIG asserts one flag at a time: does the setting include it?
                $has = ("$actual".ToLower() -match [regex]::Escape($item.ToLower()))
                $ok  = if ($op -eq 'absent') { -not $has } else { $has }
                Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                    -Title $title -Category $category -Framework $Framework -Severity $severity `
                    -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                    -Description $(if ($ok) {
                        "Subcategory '$target' is set to '$actual', which includes '$item' as required."
                    } else {
                        "Subcategory '$target' is set to '$actual'; '$item' auditing is required."
                    })
                $recorded = $true; break
            }
            'userright' {
                if (-not $script:IsAdmin) { $haveData = $false; break }
                if (-not (Get-WgSecEdit)) { $haveData = $false; break }
                $raw      = Get-WgUserRight $target
                $actualN  = Normalize-WgAccounts $raw
                $expectN  = Normalize-WgAccounts $exp
                $source   = "User right $target"
                $shownAct = if ($actualN) { ($actualN -split ';') -join ', ' } else { '(nobody)' }
                $shownExp = if ($expectN) { ($expectN -split ';') -join ', ' } else { '(nobody)' }

                if ($op -eq 'in' -or $op -eq 'in|absent') {
                    $ok = $false
                    foreach ($cand in ($exp -split ',')) {
                        if ((Normalize-WgAccounts $cand) -eq $actualN) { $ok = $true; break }
                    }
                } else {
                    $ok = ($actualN -eq $expectN)
                }
                Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                    -Title $title -Category $category -Framework $Framework -Severity $severity `
                    -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                    -Description $(if ($ok) {
                        "'$target' is held by: $shownAct."
                    } else {
                        "'$target' is held by: $shownAct; expected: $shownExp."
                    })
                $recorded = $true; break
            }
            'service' {
                $actual = Get-WgServiceStart $target
                $source = "Service '$target' start type"
                if ($null -eq $actual) {
                    Add-WgResult -Status 'PASS' -Id $id -Title $title -Category $category `
                        -Framework $Framework -Severity $severity -Refs $refText `
                        -Description "Service '$target' is not installed, so it cannot run."
                    $recorded = $true; break
                }
            }
            'feature' {
                if (-not $script:IsServer) {
                    Add-WgResult -Status 'SKIP' -Id $id -Title $title -Category $category `
                        -Framework $Framework -Severity $severity -Refs $refText `
                        -Description 'Windows feature checks apply to Server SKUs only.'
                    $recorded = $true; break
                }
                $feat = Get-WgFeatures
                if ($feat.Count -eq 0) { $haveData = $false; $source = 'Get-WindowsFeature'; break }
                $installed = $false
                if ($feat.ContainsKey($target.ToLower())) { $installed = $feat[$target.ToLower()] }
                $want = ($exp -ieq 'Present')
                $ok   = ($installed -eq $want)
                Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                    -Title $title -Category $category -Framework $Framework -Severity $severity `
                    -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                    -Description $(
                        "Feature '$target' is " + $(if ($installed) { 'installed' } else { 'not installed' }) +
                        '; required: ' + $(if ($want) { 'installed' } else { 'not installed' }) + '.')
                $recorded = $true; break
            }
            'secopt' {
                $m = $script:SecOptMap[$target.ToLower()]
                if (-not $m) { $haveData = $false; $source = "Security option '$target'"; break }
                if ($m.Kind -eq 'reg') {
                    $actual = Get-WgRegValue $m.Path $m.Item
                    $source = "$($m.Path)\$($m.Item)"
                } else {
                    if (-not $script:IsAdmin) { $haveData = $false; break }
                    $actual = Format-WgSecEditString (Get-WgSecEditValue $m.Key)
                    $source = "Local Security Policy [$($m.Key)]"
                }
                if ($m.Map -and $m.Map.ContainsKey($exp.ToLower())) { $exp = $m.Map[$exp.ToLower()] }
            }
            'localaccount' {
                $b = Get-WgLocalBuiltins
                if ($b.Count -eq 0) { $haveData = $false; $source = 'Win32_UserAccount'; break }
                if (-not $b.ContainsKey($target)) {
                    Add-WgResult -Status 'PASS' -Id $id -Title $title -Category $category `
                        -Framework $Framework -Severity $severity -Refs $refText `
                        -Description "No local account with RID $target exists on this host."
                    $recorded = $true; break
                }
                $acct = $b[$target]
                if ($op -eq '!=') {
                    # rename checks: compare the account name
                    $ok = -not ($acct.Name -ieq $exp)
                    Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                        -Title $title -Category $category -Framework $Framework -Severity $severity `
                        -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                        -Description $(if ($ok) {
                            "The built-in account (RID $target) has been renamed to '$($acct.Name)'."
                        } else {
                            "The built-in account (RID $target) still uses its default name '$($acct.Name)'."
                        })
                } else {
                    # status checks: expected 'False' means the account is enabled=False
                    $enabled = -not $acct.Disabled
                    $wantEnabled = ($exp -ieq 'True')
                    $ok = ($enabled -eq $wantEnabled)
                    Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id `
                        -Title $title -Category $category -Framework $Framework -Severity $severity `
                        -Refs $refText -Remediation $(if ($ok) { '' } else { $rem }) `
                        -Description $(
                            "Account '$($acct.Name)' (RID $target) is " +
                            $(if ($enabled) { 'enabled' } else { 'disabled' }) + '.')
                }
                $recorded = $true; break
            }
            'asr' {
                $mp = Get-WgMpPreference
                $rules = Get-WgAsrRules
                if (-not $mp -and $rules.Count -eq 0) { $haveData = $false; $source = 'Get-MpPreference'; break }
                $actual = $null
                if ($rules.ContainsKey($target.ToLower())) { $actual = $rules[$target.ToLower()] }
                $source = "ASR rule $target"
                if ($null -eq $actual) {
                    Add-WgResult -Status $badStatus -Id $id -Title $title -Category $category `
                        -Framework $Framework -Severity $severity -Refs $refText -Remediation $rem `
                        -Description "Attack Surface Reduction rule $target is not configured."
                    $recorded = $true; break
                }
            }
            default { $haveData = $false }
        }

        if ($recorded) { continue }

        if (-not $haveData) {
            $why = if (-not $script:IsAdmin) {
                'ADMINISTRATOR REQUIRED - re-run from an elevated prompt for full coverage.'
            } else {
                "Could not read $source on this host."
            }
            if (-not $script:IsAdmin) { $script:Counts.PRIV_SKIP++ }
            Add-WgResult -Status 'SKIP' -Id $id -Title $title -Category $category `
                -Framework $Framework -Severity $severity -Refs $refText -Description $why
            continue
        }

        # ── Evaluate, treating "not configured" as its own state ─────────────
        $expText = Format-WgExpectation $op $exp

        if ($null -eq $actual -and $op -ne 'absent' -and $op -ne 'in|absent') {
            if ($dflt -ne '' -and (Test-WgCompare -Operator $op -Actual $dflt -Expected $exp)) {
                Add-WgResult -Status 'PASS' -Id $id -Title $title -Category $category `
                    -Framework $Framework -Severity $severity -Refs $refText `
                    -Description ("Not explicitly configured, but the Windows default for this " +
                                  "setting is '$dflt', which satisfies $expText. Setting it " +
                                  'explicitly is still recommended so the value survives a ' +
                                  'policy change.')
                continue
            }
            $extra = if ($dflt -ne '') { " The Windows default is '$dflt'." } else { '' }
            Add-WgResult -Status $badStatus -Id $id -Title $title -Category $category `
                -Framework $Framework -Severity $severity -Refs $refText -Remediation $rem `
                -Description "Not configured ($source is absent); expected $expText.$extra"
            continue
        }

        $ok = Test-WgCompare -Operator $op -Actual $actual -Expected $exp
        $shown = if ($null -eq $actual) { '(absent)' } elseif ("$actual" -eq '') { '(empty)' } else { "$actual" }

        Add-WgResult -Status $(if ($ok) { 'PASS' } else { $badStatus }) -Id $id -Title $title `
            -Category $category -Framework $Framework -Severity $severity -Refs $refText `
            -Remediation $(if ($ok) { '' } else { $rem }) `
            -Description $(if ($ok) {
                "$source is $shown, as required."
            } else {
                "$source is $shown; expected $expText."
            })
    }
}


# =============================================================================
#  EMBEDDED BENCHMARK TABLES
#
#  Transcribed from the published benchmarks and merged across OS versions, so
#  one file carries Server 2016, 2019, 2022 and 2025 and selects the right rows
#  at runtime. Nothing here is fetched: this is what makes the tool air-gap safe.
#
#  Row layout (TAB separated):
#    Id / CategoryCode / Title / Method / Target / Item /
#    Operator / Expected / WindowsDefault / Severity / Applies / Refs
#
#  Sources:
#    CIS Microsoft Windows Server Benchmarks - 2016 v3.0.0, 2019 v3.0.0,
#      2022 v4.0.0, 2025 v1.0.0 (Level 1, Member Server and Domain Controller)
#    DISA STIG - Server 2016 V2R10, 2019 V3R8, 2022 V2R8, 2025 V1R1
#    Microsoft Security Baseline / Security Compliance Toolkit
# =============================================================================

# CIS category codes, expanded at runtime to keep the table compact.
$script:CisCategories = @{
    '0' = 'ACCOUNT POLICIES'
    '1' = 'ADMINISTRATIVE TEMPLATES: CONTROL PANEL'
    '2' = 'ADMINISTRATIVE TEMPLATES: LAPS'
    '3' = 'ADMINISTRATIVE TEMPLATES: NETWORK'
    '4' = 'ADMINISTRATIVE TEMPLATES: PRINTERS'
    '5' = 'ADMINISTRATIVE TEMPLATES: START MENU AND TASKBAR'
    '6' = 'ADMINISTRATIVE TEMPLATES: SYSTEM'
    '7' = 'ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS'
    '8' = 'ADVANCED AUDIT POLICY CONFIGURATION'
    '9' = 'MS SECURITY GUIDE'
    '10' = 'MSS (LEGACY)'
    '11' = 'SECURITY OPTIONS'
    '12' = 'SYSTEM SERVICES'
    '13' = 'USER RIGHTS ASSIGNMENT'
    '14' = 'WINDOWS FIREWALL'
}


# CIS Benchmark - Level 1, version-aware across Server 2016/2019/2022/2025.
$script:CisTable = @'
CIS-1.1.1	0	Length of password history maintained	accountpolicy	PasswordHistorySize		>=	24		L	*	*=1.1.1
CIS-1.1.2	0	Maximum password age	accountpolicy	MaximumPasswordAge		<=!0	365	42	L	*	*=1.1.2
CIS-1.1.3	0	Minimum password age	accountpolicy	MinimumPasswordAge		>=	1	0	L	*	*=1.1.3
CIS-1.1.4	0	Minimum password length	accountpolicy	MinimumPasswordLength		>=	14	0	M	*	*=1.1.4
CIS-1.1.5	0	Password must meet complexity requirements	secedit	System Access\PasswordComplexity		=	1	0	M	*	*=1.1.5
CIS-1.1.6	0	Relax minimum password length limits	reg	HKLM:\System\CurrentControlSet\Control\SAM	RelaxMinimumPasswordLengthLimits	=	1	0	M	2022,2025	*=1.1.6
CIS-1.1.7	0	Store passwords using reversible encryption	secedit	System Access\ClearTextPassword		=	0	0	H	*	2016=1.1.6;2019=1.1.6;2022=1.1.7;2025=1.1.7
CIS-1.2.1	0	Account lockout duration	accountpolicy	LockoutDuration		>=	15	30	L	*	*=1.2.1
CIS-1.2.2	0	Account lockout threshold	accountpolicy	LockoutBadCount		<=!0	5	Never	L	*	*=1.2.2
CIS-1.2.3	0	Allow Administrator account lockout	secedit	System Access\AllowAdministratorLockout		=	1	1	M	*	*=1.2.3
CIS-1.2.4	0	Reset account lockout counter	accountpolicy	ResetLockoutCount		>=	15	30	L	*	*=1.2.4
CIS-2.2.1	13	Access Credential Manager as a trusted caller	userright	SeTrustedCredManAccessPrivilege		=			M	*	*=2.2.1
CIS-2.2.2	13	Access this computer from the network (DC)	userright	SeNetworkLogonRight		=	NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS;BUILTIN\Administrators;NT AUTHORITY\Authenticated Users	NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS;BUILTIN\Pre-Windows 2000 Compatible Access;BUILTIN\Administrators;NT AUTHORITY\Authenticated Users;Everyone	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.2
CIS-2.2.3	13	Access this computer from the network (Member)	userright	SeNetworkLogonRight		=	BUILTIN\Administrators;NT AUTHORITY\Authenticated Users	BUILTIN\Pre-Windows 2000 Compatible Access;BUILTIN\Administrators;NT AUTHORITY\Authenticated Users;Everyone	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.3
CIS-2.2.4	13	Act as part of the operating system	userright	SeTcbPrivilege		=			M	*	*=2.2.4
CIS-2.2.5	13	Add workstations to domain (DC)	userright	SeMachineAccountPrivilege		=	BUILTIN\Administrators	NT AUTHORITY\Authenticated Users	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.5
CIS-2.2.6	13	Adjust memory quotas for a process	userright	SeIncreaseQuotaPrivilege		=	BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.6
CIS-2.2.7	13	Allow log on locally (DC only)	userright	SeInteractiveLogonRight		=	BUILTIN\Administrators;NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS;	BUILTIN\Backup Operators;BUILTIN\Users;BUILTIN\Administrators;COMPUTERNAME\Guest	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.7
CIS-2.2.8	13	Allow log on locally	userright	SeInteractiveLogonRight		=	BUILTIN\Administrators	BUILTIN\Backup Operators;BUILTIN\Users;BUILTIN\Administrators;COMPUTERNAME\Guest	M	*	*=2.2.8
CIS-2.2.9	13	Allow log on through Remote Desktop Services (DC)	userright	SeRemoteInteractiveLogonRight		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.9
CIS-2.2.10	13	Allow log on through Remote Desktop Services (Member)	userright	SeRemoteInteractiveLogonRight		=	BUILTIN\Remote Desktop Users;BUILTIN\Administrators	BUILTIN\Remote Desktop Users;BUILTIN\Administrators	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.10
CIS-2.2.11	13	Back up files and directories	userright	SeBackupPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators;BUILTIN\Backup Operators	M	*	*=2.2.11
CIS-2.2.12	13	Change the system time	userright	SeSystemTimePrivilege		=	BUILTIN\Administrators;NT AUTHORITY\LOCAL SERVICE	BUILTIN\Administrators;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.12
CIS-2.2.13	13	Change the time zone	userright	SeTimeZonePrivilege		=	BUILTIN\Administrators;NT AUTHORITY\LOCAL SERVICE	BUILTIN\Device Owners;BUILTIN\Users;BUILTIN\Administrators;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.13
CIS-2.2.14	13	Create a pagefile	userright	SeCreatePagefilePrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.14
CIS-2.2.15	13	Create a token object	userright	SeCreateTokenPrivilege		=			M	*	*=2.2.15
CIS-2.2.16	13	Create global objects	userright	SeCreateGlobalPrivilege		=	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.16
CIS-2.2.17	13	Create permanent shared objects	userright	SeCreatePermanentPrivilege		=			M	*	*=2.2.17
CIS-2.2.18	13	Create symbolic links (DC)	userright	SeCreateSymbolicLinkPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.2.18.1;2019=2.2.18;2022=2.2.18;2025=2.2.18
CIS-2.2.19.1	13	Create symbolic links (Member)	userright	SeCreateSymbolicLinkPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:MS,2019:MS,2022:MS,2025:MS	2016=2.2.18.2;2019=2.2.19.1;2022=2.2.19.1;2025=2.2.19.1
CIS-2.2.19.2	13	Create symbolic links (Member, Hyper-V)	userright	SeCreateSymbolicLinkPrivilege		=	NT VIRTUAL MACHINE\Virtual Machines;BUILTIN\Administrators	S-1-5-83-0;BUILTIN\Administrators	M	2016:MS,2019:MS,2022:MS,2025:MS	2016=2.2.19;2019=2.2.19.2;2022=2.2.19.2;2025=2.2.19.2
CIS-2.2.20	13	Debug programs	userright	SeDebugPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.20
CIS-2.2.21	13	Deny access to this computer from the network (DC)	userright	SeDenyNetworkLogonRight		=	BUILTIN\Guests	BUILTIN\Guests	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.21
CIS-2.2.22	13	Deny access to this computer from the network (Member)	userright	SeDenyNetworkLogonRight		=	BUILTIN\Guests;NT AUTHORITY\Local account and member of Administrators group	BUILTIN\Guests	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.22
CIS-2.2.23	13	Deny log on as a batch job	userright	SeDenyBatchLogonRight		=	BUILTIN\Guests		M	*	*=2.2.23
CIS-2.2.24	13	Deny log on as a service	userright	SeDenyServiceLogonRight		=	BUILTIN\Guests		M	*	*=2.2.24
CIS-2.2.25	13	Deny log on locally	userright	SeDenyInteractiveLogonRight		=	BUILTIN\Guests	BUILTIN\Guests	M	*	*=2.2.25
CIS-2.2.26	13	Deny log on through Remote Desktop Services (DC)	userright	SeDenyRemoteInteractiveLogonRight		=	BUILTIN\Guests		M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.26
CIS-2.2.27	13	Deny log on through Remote Desktop Services (Member)	userright	SeDenyRemoteInteractiveLogonRight		=	BUILTIN\Guests;NT AUTHORITY\Local account		M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.27
CIS-2.2.28	13	Enable computer and user accounts to be trusted for delegation (DC)	userright	SeEnableDelegationPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.28
CIS-2.2.29	13	Enable computer and user accounts to be trusted for delegation (Member)	userright	SeEnableDelegationPrivilege		=			M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.29
CIS-2.2.30	13	Force shutdown from a remote system	userright	SeRemoteShutdownPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.30
CIS-2.2.31	13	Generate security audits	userright	SeAuditPrivilege		=	NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.31
CIS-2.2.32	13	Impersonate a client after authentication (DC)	userright	SeImpersonatePrivilege		=	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.32
CIS-2.2.33	13	Impersonate a client after authentication (Member)	userright	SeImpersonatePrivilege		=	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.33
CIS-2.2.34	13	Increase scheduling priority	userright	SeIncreaseBasePriorityPrivilege		=	Window Manager\Window Manager Group;BUILTIN\Administrators	Window Manager\Window Manager Group;BUILTIN\Administrators	M	*	*=2.2.34
CIS-2.2.35	13	Load and unload device drivers	userright	SeLoadDriverPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.35
CIS-2.2.36	13	Lock pages in memory	userright	SeLockMemoryPrivilege		=			M	*	*=2.2.36
CIS-2.2.37	13	Log on as a batch job (DC)	userright	SeBatchLogonRight		=	BUILTIN\Administrators	BUILTIN\Performance Log Users;BUILTIN\Backup Operators;BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.2.37.1;2019=2.2.37;2022=2.2.37;2025=2.2.37
CIS-2.2.38.1	13	Manage auditing and security log (DC)	userright	SeSecurityPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.2.37.2;2019=2.2.38.1;2022=2.2.38.1;2025=2.2.38.1
CIS-2.2.38.2	13	Manage auditing and security log (DC and Exchange)	userright	SeSecurityPrivilege		=	NT AUTHORITY\EXCHANGE SERVERS;BUILTIN\Administrators	BUILTIN\Administrators	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.2.38;2019=2.2.38.2;2022=2.2.38.2;2025=2.2.38.2
CIS-2.2.39	13	Manage auditing and security log (Member)	userright	SeSecurityPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.2.39
CIS-2.2.40	13	Modify an object label	userright	SeReLabelPrivilege		=			M	*	*=2.2.40
CIS-2.2.41	13	Modify firmware environment values	userright	SeSystemEnvironmentPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.41
CIS-2.2.42	13	Perform volume maintenance tasks	userright	SeManageVolumePrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.42
CIS-2.2.43	13	Profile single process	userright	SeProfileSingleProcessPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.43
CIS-2.2.44	13	Profile system performance	userright	SeSystemProfilePrivilege		=	NT SERVICE\WdiServiceHost;BUILTIN\Administrators	NT SERVICE\WdiServiceHost;BUILTIN\Administrators	M	*	*=2.2.44
CIS-2.2.45	13	Replace a process level token	userright	SeAssignPrimaryTokenPrivilege		=	NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	*	*=2.2.45
CIS-2.2.46	13	Restore files and directories	userright	SeRestorePrivilege		=	BUILTIN\Administrators	BUILTIN\Backup Operators;BUILTIN\Administrators	M	*	*=2.2.46
CIS-2.2.47	13	Shut down the system	userright	SeShutdownPrivilege		=	BUILTIN\Administrators	BUILTIN\Backup Operators;BUILTIN\Users;BUILTIN\Administrators	M	*	*=2.2.47
CIS-2.2.48	13	Synchronize directory service data (DC)	userright	SeSyncAgentPrivilege		=			M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.2.48
CIS-2.2.49	13	Take ownership of files or other objects	userright	SeTakeOwnershipPrivilege		=	BUILTIN\Administrators	BUILTIN\Administrators	M	*	*=2.2.49
CIS-2.3.1.1	11	Accounts: Block Microsoft accounts	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	NoConnectedUser	=	3	0	L	2016,2019	*=2.3.1.1
CIS-2.3.1.1#2	11	Accounts: Guest account status (Member)	localaccount	501		=	False	False	M	2016:MS,2019:MS,2022:MS,2025:MS	2016=2.3.1.2;2019=2.3.1.2;2022=2.3.1.1;2025=2.3.1.1
CIS-2.3.1.2	11	Accounts: Limit local account use of blank passwords to console logon only	reg	HKLM:\System\CurrentControlSet\Control\Lsa	LimitBlankPasswordUse	=	1	1	M	*	2016=2.3.1.3;2019=2.3.1.3;2022=2.3.1.2;2025=2.3.1.2
CIS-2.3.1.3	11	Accounts: Rename administrator account	localaccount	500		!=	Administrator	Administrator	L	*	2016=2.3.1.4;2019=2.3.1.4;2022=2.3.1.3;2025=2.3.1.3
CIS-2.3.1.4	11	Accounts: Rename guest account	localaccount	501		!=	Guest	Guest	L	*	2016=2.3.1.5;2019=2.3.1.5;2022=2.3.1.4;2025=2.3.1.4
CIS-2.3.2.1	11	Audit: Force audit policy subcategory settings to override audit policy category settings	reg	HKLM:\System\CurrentControlSet\Control\Lsa	SCENoApplyLegacyAuditPolicy	=	1	1	L	*	*=2.3.2.1
CIS-2.3.2.2	11	Audit: Shut down system immediately if unable to log security audits	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	CrashOnAuditFail	=	0	0	L	*	*=2.3.2.2
CIS-2.3.4.1	11	Devices: Prevent users from installing printer drivers	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers	AddPrinterDrivers	=	1	0	M	*	*=2.3.4.1
CIS-2.3.5.1	11	Domain controller: Allow server operators to schedule tasks (DC)	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	SubmitControl	=	0	0	M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.3.5.1
CIS-2.3.5.2	11	Domain controller: Allow vulnerable Netlogon secure channel connections	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	VulnerableChannelAllowList	=			M	*	*=2.3.5.2
CIS-2.3.5.3	11	Domain controller: LDAP server channel binding token requirements	reg	HKLM:\System\CurrentControlSet\Services\NTDS\Parameters	LdapEnforceChannelBinding	=	2	1	M	*	*=2.3.5.3
CIS-2.3.5.4	11	Domain controller: LDAP server signing requirements	reg	HKLM:\System\CurrentControlSet\Services\NTDS\Parameters	LDAPServerIntegrity	=	2	1	M	*	*=2.3.5.4
CIS-2.3.5.5#2	11	Domain controller: LDAP server signing requirements Enforcement	reg	HKLM:\System\CurrentControlSet\Services\NTDS\Parameters	LDAPServerEnforceIntegrity	=	1		M	2025	*=2.3.5.5
CIS-2.3.5.5	11	Domain controller: Refuse machine account password changes (DC)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	RefusePasswordChange	=	0	1	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.3.5.5;2019=2.3.5.5;2022=2.3.5.5;2025=2.3.5.6
CIS-2.3.6.1	11	Domain member: Digitally encrypt or sign secure channel data (always)	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	RequireSignOrSeal	=	1	1	M	*	*=2.3.6.1
CIS-2.3.6.2	11	Domain member: Digitally encrypt secure channel data (when possible)	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	SealSecureChannel	=	1	1	M	*	*=2.3.6.2
CIS-2.3.6.3	11	Domain member: Digitally sign secure channel data (when possible)	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	SignSecureChannel	=	1	1	M	*	*=2.3.6.3
CIS-2.3.6.4	11	Domain member: Disable machine account password changes	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	DisablePasswordChange	=	0	0	M	*	*=2.3.6.4
CIS-2.3.6.5	11	Domain member: Maximum machine account password age	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	MaximumPasswordAge	<=!0	30	30	M	*	*=2.3.6.5
CIS-2.3.6.6	11	Domain member: Require strong (Windows 2000 or later) session key	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	RequireStrongKey	=	1	1	M	*	*=2.3.6.6
CIS-2.3.7.1	11	Interactive logon: Don't display username at sign-in	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	DontDisplayUserName	=	1	0	L	2016	*=2.3.7.1
CIS-2.3.7.1#2	11	Interactive logon: Do not require CTRL+ALT+DEL	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	DisableCAD	=	0	1	L	*	2016=2.3.7.2;2019=2.3.7.1;2022=2.3.7.1;2025=2.3.7.1
CIS-2.3.7.2	11	Interactive logon: Don't display last signed-in	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	DontDisplayLastUserName	=	1	0	L	2019,2022,2025	*=2.3.7.2
CIS-2.3.7.3	11	Interactive logon: Machine inactivity limit	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	InactivityTimeoutSecs	<=!0	900	900	M	*	*=2.3.7.3
CIS-2.3.7.4	11	Interactive logon: Message text for users attempting to log on	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LegalNoticeText	!=			L	*	*=2.3.7.4
CIS-2.3.7.5	11	Interactive logon: Message title for users attempting to log on	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LegalNoticeCaption	!=			L	*	*=2.3.7.5
CIS-2.3.7.6	11	Interactive logon: Number of previous logons to cache (in case domain controller is not available)	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon	CachedLogonsCount	<=	4	10	M	*	*=2.3.7.6
CIS-2.3.7.7.1	11	Interactive logon: Prompt user to change password before expiration (Max)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	PasswordExpiryWarning	<=	14	5	L	*	*=2.3.7.7.1
CIS-2.3.7.7.2	11	Interactive logon: Prompt user to change password before expiration (Min)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	PasswordExpiryWarning	>=	5	5	L	*	*=2.3.7.7.2
CIS-2.3.7.8	11	Interactive logon: Require Domain Controller Authentication to unlock workstation (Member)	reg	HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon	ForceUnlockLogon	=	1	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.7.8
CIS-2.3.7.9	11	Interactive logon: Smart card removal behavior	reg	HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon	ScRemoveOption	=	1	0	M	*	*=2.3.7.9
CIS-2.3.8.1	11	Microsoft network client: Digitally sign communications (always)	reg	HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters	RequireSecuritySignature	=	1	0	M	*	*=2.3.8.1
CIS-2.3.8.2	11	Microsoft network client: Digitally sign communications (if server agrees)	reg	HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters	EnableSecuritySignature	=	1	1	M	*	*=2.3.8.2
CIS-2.3.8.3	11	Microsoft network client: Send unencrypted password to third-party SMB servers	reg	HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters	EnablePlainTextPassword	=	0	0	M	*	*=2.3.8.3
CIS-2.3.9.1	11	Microsoft network server: Amount of idle time required before suspending session	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters	AutoDisconnect	<=	15	15	M	*	*=2.3.9.1
CIS-2.3.9.2	11	Microsoft network server: Digitally sign communications (always)	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	RequireSecuritySignature	=	1	0	M	*	*=2.3.9.2
CIS-2.3.9.3	11	Microsoft network server: Digitally sign communications (if client agrees)	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	EnableSecuritySignature	=	1	0	M	*	*=2.3.9.3
CIS-2.3.9.4	11	Microsoft network server: Disconnect clients when logon hours expire	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	enableforcedlogoff	=	1	1	M	*	*=2.3.9.4
CIS-2.3.9.5	11	Microsoft network server: Server SPN target name validation level (Member)	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	SMBServerNameHardeningLevel	>=	1	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.9.5
CIS-2.3.10.1	11	Network access: Allow anonymous SID/Name translation	secedit	System Access\LSAAnonymousNameLookup		=	0	0	M	*	*=2.3.10.1
CIS-2.3.10.2	11	Network access: Do not allow anonymous enumeration of SAM accounts (Member)	reg	HKLM:\System\CurrentControlSet\Control\Lsa	RestrictAnonymousSAM	=	1	1	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.10.2
CIS-2.3.10.3	11	Network access: Do not allow anonymous enumeration of SAM accounts and shares (Member)	reg	HKLM:\System\CurrentControlSet\Control\Lsa	RestrictAnonymous	=	1	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.10.3
CIS-2.3.10.4	11	Network access: Do not allow storage of passwords and credentials for network authentication	reg	HKLM:\System\CurrentControlSet\Control\Lsa	DisableDomainCreds	=	1	0	M	*	*=2.3.10.4
CIS-2.3.10.5	11	Network access: Let Everyone permissions apply to anonymous users	reg	HKLM:\System\CurrentControlSet\Control\Lsa	EveryoneIncludesAnonymous	=	0	0	M	*	*=2.3.10.5
CIS-2.3.10.6	11	Network access: Named Pipes that can be accessed anonymously (DC)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters	NullSessionPipes	=	netlogon;samr;lsarpc		M	2016:DC,2019:DC,2022:DC,2025:DC	*=2.3.10.6
CIS-2.3.10.7	11	Network access: Named Pipes that can be accessed anonymously (Member)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters	NullSessionPipes	=			M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.10.7
CIS-2.3.10.8	11	Network access: Remotely accessible registry paths	reg	HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths	Machine	=	System\CurrentControlSet\Control\ProductOptions;System\CurrentControlSet\Control\Server Applications;Software\Microsoft\Windows NT\CurrentVersion	System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion	M	*	*=2.3.10.8
CIS-2.3.10.9	11	Network access: Remotely accessible registry paths and sub-paths	reg	HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths	Machine	=	System\CurrentControlSet\Control\Print\Printers;System\CurrentControlSet\Services\Eventlog;Software\Microsoft\OLAP Server;Software\Microsoft\Windows NT\CurrentVersion\Print;Software\Microsoft\Windows NT\CurrentVersion\Windows;System\CurrentControlSet\Control\ContentIndex;System\CurrentControlSet\Control\Terminal Server;System\CurrentControlSet\Control\Terminal Server\UserConfig;System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration;Software\Microsoft\Windows NT\CurrentVersion\Perflib;System\CurrentControlSet\Services\SysmonLog	System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Software\Microsoft\Windows NT\CurrentVersion\Windows System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server System\CurrentControlSet\Control\Terminal Server\UserConfig System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib System\CurrentControlSet\Services\SysmonLog	M	*	*=2.3.10.9
CIS-2.3.10.10	11	Network access: Restrict anonymous access to Named Pipes and Shares	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	RestrictNullSessAccess	=	1	1	M	*	*=2.3.10.10
CIS-2.3.10.11	11	Network access: Restrict clients allowed to make remote calls to SAM (Member)	reg	HKLM:\System\CurrentControlSet\Control\Lsa	RestrictRemoteSAM	=	O:BAG:BAD:(A;;RC;;;BA)		M	2016:MS,2019:MS,2022:MS,2025:MS	*=2.3.10.11
CIS-2.3.10.12	11	Network access: Shares that can be accessed anonymously	reg	HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters	NullSessionShares	=			M	*	*=2.3.10.12
CIS-2.3.10.13	11	Network access: Sharing and security model for local accounts	reg	HKLM:\System\CurrentControlSet\Control\Lsa	ForceGuest	=	0	0	M	*	*=2.3.10.13
CIS-2.3.11.1	11	Network security: Allow Local System to use computer identity for NTLM	reg	HKLM:\System\CurrentControlSet\Control\Lsa	UseMachineId	=	1	0	M	*	*=2.3.11.1
CIS-2.3.11.2	11	Network security: Allow LocalSystem NULL session fallback	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	allownullsessionfallback	=	0	0	M	*	*=2.3.11.2
CIS-2.3.11.3	11	Network security: Allow PKU2U authentication requests to this computer to use online identities	reg	HKLM:\System\CurrentControlSet\Control\Lsa\pku2u	AllowOnlineID	=	0		M	*	*=2.3.11.3
CIS-2.3.11.4	11	Network security: Configure encryption types allowed for Kerberos	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	SupportedEncryptionTypes	<=	2147483640	2147483644	M	*	*=2.3.11.4
CIS-2.3.11.5	11	Network security: Do not store LAN Manager hash value on next password change	reg	HKLM:\System\CurrentControlSet\Control\Lsa	NoLMHash	=	1	1	H	*	*=2.3.11.5
CIS-2.3.11.6	11	Network security: Force logoff when logon hours expires	secedit	System Access\ForceLogoffWhenHourExpire		=	1	0	L	*	*=2.3.11.6
CIS-2.3.11.7	11	Network security: LAN Manager authentication level	reg	HKLM:\System\CurrentControlSet\Control\Lsa	LmCompatibilityLevel	=	5	3	M	*	*=2.3.11.7
CIS-2.3.11.8	11	Network security: LDAP client encryption requirements	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LDAP	LDAPClientConfidentiality	>=	1	1	M	2022,2025	*=2.3.11.8
CIS-2.3.11.9	11	Network security: LDAP client signing requirements	reg	HKLM:\System\CurrentControlSet\Services\LDAP	LDAPClientIntegrity	>=	1	1	M	*	2016=2.3.11.8;2019=2.3.11.8;2022=2.3.11.9;2025=2.3.11.9
CIS-2.3.11.10	11	Network security: Minimum session security for NTLM SSP based (including secure RPC) clients	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	NTLMMinClientSec	=	537395200	536870912	M	*	2016=2.3.11.9;2019=2.3.11.9;2022=2.3.11.10;2025=2.3.11.10
CIS-2.3.11.11	11	Network security: Minimum session security for NTLM SSP based (including secure RPC) servers	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	NTLMMinServerSec	=	537395200	536870912	M	*	2016=2.3.11.10;2019=2.3.11.10;2022=2.3.11.11;2025=2.3.11.11
CIS-2.3.11.12	11	Network security: Restrict NTLM: Audit Incoming NTLM Traffic	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	AuditReceivingNTLMTraffic	=	2	0	M	*	2016=2.3.11.11;2019=2.3.11.11;2022=2.3.11.12;2025=2.3.11.12
CIS-2.3.11.13	11	Network security: Restrict NTLM: Audit NTLM authentication in this domain (DC only)	reg	HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters	AuditNTLMInDomain	=	7	0	M	2016:DC,2019:DC,2022:DC,2025:DC	2016=2.3.11.12;2019=2.3.11.12;2022=2.3.11.13;2025=2.3.11.13
CIS-2.3.11.14	11	Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	RestrictSendingNTLMTraffic	>=	1	0	M	*	2016=2.3.11.13;2019=2.3.11.13;2022=2.3.11.14;2025=2.3.11.14
CIS-2.3.13.1	11	Shutdown: Allow system to be shut down without having to log on	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	ShutdownWithoutLogon	=	0	1	M	*	*=2.3.13.1
CIS-2.3.15.1	11	System objects: Require case insensitivity for non-Windows subsystem	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel	ObCaseInsensitive	=	1	1	M	*	*=2.3.15.1
CIS-2.3.15.2	11	System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)	reg	HKLM:\System\CurrentControlSet\Control\Session Manager	ProtectionMode	=	1	1	M	*	*=2.3.15.2
CIS-2.3.17.1	11	User Account Control: Admin Approval Mode for the Built-in Administrator account	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	FilterAdministratorToken	=	1	0	M	*	*=2.3.17.1
CIS-2.3.17.2	11	User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	ConsentPromptBehaviorAdmin	=	2	5	M	*	*=2.3.17.2
CIS-2.3.17.3	11	User Account Control: Behavior of the elevation prompt for standard users	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	ConsentPromptBehaviorUser	=	0	0	M	*	*=2.3.17.3
CIS-2.3.17.4	11	User Account Control: Detect application installations and prompt for elevation	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableInstallerDetection	=	1	1	M	*	*=2.3.17.4
CIS-2.3.17.5	11	User Account Control: Only elevate UIAccess applications that are installed in secure locations	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableSecureUIAPaths	=	1	1	M	*	*=2.3.17.5
CIS-2.3.17.6	11	User Account Control: Run all administrators in Admin Approval Mode	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableLUA	=	1	1	M	*	*=2.3.17.6
CIS-2.3.17.7	11	User Account Control: Switch to the secure desktop when prompting for elevation	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	PromptOnSecureDesktop	=	1	1	M	*	*=2.3.17.7
CIS-2.3.17.8	11	User Account Control: Virtualize file and registry write failures to per-user locations	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableVirtualization	=	1	1	M	*	*=2.3.17.8
CIS-5.1.1	12	Print Spooler (Spooler) (DC only)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Spooler	Start	=	4	2	M	2016:DC,2019:DC,2022:DC,2025:DC	*=5.1.1
CIS-5.1.2	12	Print Spooler (Spooler) (Service Startup type) (DC only)	service	Spooler		=	Disabled	Automatic	M	2016:DC,2019:DC,2022:DC,2025:DC	*=5.1.2
CIS-5.2.1	12	Print Spooler (Spooler) (MS only)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Spooler	Start	=	4	2	M	2022:MS,2025:MS	*=5.2.1
CIS-5.2.2	12	Print Spooler (Spooler) (Service Startup type) (MS only)	service	Spooler		=	Disabled	Automatic	M	2022:MS,2025:MS	*=5.2.2
CIS-9.1.1	14	EnableFirewall (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile	EnableFirewall	=	1	0	M	*	*=9.1.1
CIS-9.1.2	14	Inbound Connections (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile	DefaultInboundAction	=	1	1	M	*	*=9.1.2
CIS-9.1.3	14	Display a notification (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile	DisableNotifications	=	1	0	L	*	*=9.1.3
CIS-9.1.4	14	Name of log file (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging	LogFilePath	=	%SystemRoot%\System32\logfiles\firewall\domainfw.log	%SystemRoot%\System32\logfiles\firewall\pfirewall.log	L	*	*=9.1.4
CIS-9.1.5	14	Log size limit (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging	LogFileSize	>=	16384	4096	M	*	*=9.1.5
CIS-9.1.6	14	Log dropped packets (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging	LogDroppedPackets	=	1	0	M	*	*=9.1.6
CIS-9.1.7	14	Log successful connections (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging	LogSuccessfulConnections	=	1	0	L	*	*=9.1.7
CIS-9.2.1	14	EnableFirewall (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile	EnableFirewall	=	1	0	M	*	*=9.2.1
CIS-9.2.2	14	Inbound Connections (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile	DefaultInboundAction	=	1	1	M	*	*=9.2.2
CIS-9.2.3	14	Display a notification (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile	DisableNotifications	=	1	0	L	*	*=9.2.3
CIS-9.2.4	14	Name of log file (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging	LogFilePath	=	%SystemRoot%\System32\logfiles\firewall\privatefw.log	%SystemRoot%\System32\logfiles\firewall\pfirewall.log	L	*	*=9.2.4
CIS-9.2.5	14	Log size limit (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging	LogFileSize	>=	16384	4096	M	*	*=9.2.5
CIS-9.2.6	14	Log dropped packets (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging	LogDroppedPackets	=	1	0	M	*	*=9.2.6
CIS-9.2.7	14	Log successful connections (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging	LogSuccessfulConnections	=	1	0	L	*	*=9.2.7
CIS-9.3.1	14	EnableFirewall (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	EnableFirewall	=	1	0	M	*	*=9.3.1
CIS-9.3.2	14	Inbound Connections (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	DefaultInboundAction	=	1	1	M	*	*=9.3.2
CIS-9.3.3	14	Display a notification (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	DisableNotifications	=	1	0	L	*	*=9.3.3
CIS-9.3.4	14	Apply local firewall rules (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	AllowLocalPolicyMerge	=	0	0	L	*	*=9.3.4
CIS-9.3.5	14	Apply local connection security rules (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	AllowLocalIPsecPolicyMerge	=	0	0	L	*	*=9.3.5
CIS-9.3.6	14	Name of log file (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging	LogFilePath	=	%SystemRoot%\System32\logfiles\firewall\publicfw.log	%SystemRoot%\System32\logfiles\firewall\pfirewall.log	L	*	*=9.3.6
CIS-9.3.7	14	Log size limit (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging	LogFileSize	>=	16384	4096	M	*	*=9.3.7
CIS-9.3.8	14	Log dropped packets (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging	LogDroppedPackets	=	1	0	M	*	*=9.3.8
CIS-9.3.9	14	Log successful connections (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging	LogSuccessfulConnections	=	1	0	L	*	*=9.3.9
CIS-17.1.1	8	Credential Validation	auditpol	{0CCE923F-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.1.1
CIS-17.1.2	8	Kerberos Authentication Service	auditpol	{0CCE9242-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success	L	*	*=17.1.2
CIS-17.1.3	8	Kerberos Service Ticket Operations	auditpol	{0CCE9240-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success	L	*	*=17.1.3
CIS-17.2.1	8	Application Group Management	auditpol	{0CCE9239-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.2.1
CIS-17.2.2	8	Computer Account Management	auditpol	{0CCE9236-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.2.2
CIS-17.2.3	8	Distribution Group Management	auditpol	{0CCE9238-69AE-11D9-BED3-505054503030}		contains	Success		L	*	*=17.2.3
CIS-17.2.4	8	Other Account Management Events	auditpol	{0CCE923A-69AE-11D9-BED3-505054503030}		contains	Success		L	*	*=17.2.4
CIS-17.2.5	8	Security Group Management	auditpol	{0CCE9237-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.2.5
CIS-17.2.6	8	User Account Management	auditpol	{0CCE9235-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success	L	*	*=17.2.6
CIS-17.3.1	8	Plug and Play Events	auditpol	{0cce9248-69ae-11d9-bed3-505054503030}		contains	Success	No Auditing	L	*	*=17.3.1
CIS-17.3.2	8	Process Creation	auditpol	{0CCE922B-69AE-11D9-BED3-505054503030}		contains	Success	No Auditing	L	*	*=17.3.2
CIS-17.4.1	8	Directory Service Access	auditpol	{0CCE923B-69AE-11D9-BED3-505054503030}		contains	Failure	Success	L	*	*=17.4.1
CIS-17.4.2	8	Directory Service Changes	auditpol	{0CCE923C-69AE-11D9-BED3-505054503030}		contains	Success		L	*	*=17.4.2
CIS-17.5.1	8	Account Lockout	auditpol	{0CCE9217-69AE-11D9-BED3-505054503030}		contains	Failure	Success	L	*	*=17.5.1
CIS-17.5.2	8	Group Membership	auditpol	{0cce9249-69ae-11d9-bed3-505054503030}		contains	Success	No Auditing	L	*	*=17.5.2
CIS-17.5.3	8	Logoff	auditpol	{0CCE9216-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.5.3
CIS-17.5.4	8	Logon	auditpol	{0CCE9215-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success and Failure	L	*	*=17.5.4
CIS-17.5.5	8	Other Logon/Logoff Events	auditpol	{0CCE921C-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.5.5
CIS-17.5.6	8	Special Logon	auditpol	{0CCE921B-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.5.6
CIS-17.6.1	8	Detailed File Share	auditpol	{0CCE9244-69AE-11D9-BED3-505054503030}		contains	Failure	No Auditing	L	*	*=17.6.1
CIS-17.6.2	8	File Share	auditpol	{0CCE9224-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.6.2
CIS-17.6.3	8	Other Object Access Events	auditpol	{0CCE9227-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.6.3
CIS-17.6.4	8	Removable Storage	auditpol	{0CCE9245-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.6.4
CIS-17.7.1	8	Audit Policy Change	auditpol	{0CCE922F-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.7.1
CIS-17.7.2	8	Authentication Policy Change	auditpol	{0CCE9230-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.7.2
CIS-17.7.3	8	Authorization Policy Change	auditpol	{0CCE9231-69AE-11D9-BED3-505054503030}		contains	Success	No Auditing	L	*	*=17.7.3
CIS-17.7.4	8	MPSSVC Rule-Level Policy Change	auditpol	{0CCE9232-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.7.4
CIS-17.7.5	8	Other Policy Change Events	auditpol	{0CCE9234-69AE-11D9-BED3-505054503030}		contains	Failure	No Auditing	L	*	*=17.7.5
CIS-17.8.1	8	Sensitive Privilege Use	auditpol	{0CCE9228-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.8.1
CIS-17.9.1	8	IPsec Driver	auditpol	{0CCE9213-69AE-11D9-BED3-505054503030}		=	Success and Failure	No Auditing	L	*	*=17.9.1
CIS-17.9.2	8	Other System Events	auditpol	{0CCE9214-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success and Failure	L	*	*=17.9.2
CIS-17.9.3	8	Security State Change	auditpol	{0CCE9210-69AE-11D9-BED3-505054503030}		contains	Success	Success	L	*	*=17.9.3
CIS-17.9.4	8	Security System Extension	auditpol	{0CCE9211-69AE-11D9-BED3-505054503030}		contains	Success	No Auditing	L	*	*=17.9.4
CIS-17.9.5	8	System Integrity	auditpol	{0CCE9212-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success and Failure	L	*	*=17.9.5
CIS-18.1.1.1	1	Personalization: Prevent enabling lock screen camera	reg	HKLM:\Software\Policies\Microsoft\Windows\Personalization	NoLockScreenCamera	=	1	0	L	*	*=18.1.1.1
CIS-18.1.1.2	1	Personalization: Prevent enabling lock screen slide show	reg	HKLM:\Software\Policies\Microsoft\Windows\Personalization	NoLockScreenSlideshow	=	1	0	L	*	*=18.1.1.2
CIS-18.1.2.2	1	Regional and Language Options: Allow users to enable online speech recognition services	reg	HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization	AllowInputPersonalization	=	0	1	M	*	*=18.1.2.2
CIS-18.1.3	1	Allow Online Tips	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	AllowOnlineTips	=	0	1	M	*	*=18.1.3
CIS-18.3.1	2	LAPS AdmPwd GPO Extension / CSE (Member)	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}	DllName	=	C:\Program Files\LAPS\CSE\AdmPwd.dll		M	2016:MS	*=18.3.1
CIS-18.3.2	2	Do not allow password expiration time longer than required by policy (Member)	reg	HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd	PwdExpirationProtectionEnabled	=	1	0	M	2016:MS	*=18.3.2
CIS-18.3.3	2	Enable local admin password management (Member)	reg	HKLM:\Software\Policies\Microsoft Services\AdmPwd	AdmPwdEnabled	=	1	0	M	2016:MS	*=18.3.3
CIS-18.3.4	2	Password Settings: Password Complexity (Member)	reg	HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd	PasswordComplexity	=	4	4	M	2016:MS	*=18.3.4
CIS-18.3.5	2	Password Settings: Password Length (Member)	reg	HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd	PasswordLength	>=	15	14	M	2016:MS	*=18.3.5
CIS-18.3.6	2	Password Settings: Password Age (Days) (Member)	reg	HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd	PasswordAgeDays	<=	30	30	M	2016:MS	*=18.3.6
CIS-18.4.1	9	Apply UAC restrictions to local accounts on network logons (Member)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LocalAccountTokenFilterPolicy	=	0	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.4.1
CIS-18.4.2	9	Configure SMB v1 client driver	reg	HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10	Start	=	4	1	M	*	2016=18.4.3;2019=18.4.3;2022=18.4.2;2025=18.4.2
CIS-18.4.3	9	Configure SMB v1 server	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters	SMB1	=	0	1	M	*	2016=18.4.4;2019=18.4.4;2022=18.4.3;2025=18.4.3
CIS-18.4.4.1	9	Enable Certificate Padding	reg	HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config	EnableCertPaddingCheck	=	1		M	*	2016=18.4.5;2019=18.4.5;2022=18.4.4.1;2025=18.4.4
CIS-18.4.4.2	9	Enable Certificate Padding (32-bit subsystem on 64-bit OS)	reg	HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config	EnableCertPaddingCheck	=	1		M	2022	*=18.4.4.2
CIS-18.4.5	9	Enable Structured Exception Handling Overwrite Protection (SEHOP)	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel	DisableExceptionChainValidation	=	0	0	M	*	2016=18.4.6;2019=18.4.6;2022=18.4.5;2025=18.4.5
CIS-18.4.6	9	NetBT NodeType configuration	reg	HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters	NodeType	=	2	0	M	*	2016=18.4.8;2019=18.4.8;2022=18.4.6;2025=18.4.6
CIS-18.4.7	9	WDigest Authentication	reg	HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest	UseLogonCredential	=	0	0	H	*	2016=18.4.9;2019=18.4.9;2022=18.4.7;2025=18.4.7
CIS-18.5.1	10	MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon	AutoAdminLogon	=	0	0	M	*	*=18.5.1
CIS-18.5.2	10	MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)	reg	HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters	DisableIPSourceRouting	=	2	0	M	*	*=18.5.2
CIS-18.5.3	10	MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)	reg	HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters	DisableIPSourceRouting	=	2	1	M	*	*=18.5.3
CIS-18.5.4	10	MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes	reg	HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters	EnableICMPRedirect	=	0	1	M	*	*=18.5.4
CIS-18.5.5	10	MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters	KeepAliveTime	<=	300000	7200000	M	*	*=18.5.5
CIS-18.5.6	10	MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers	reg	HKLM:\System\CurrentControlSet\Services\Netbt\Parameters	NoNameReleaseOnDemand	=	1	0	M	*	*=18.5.6
CIS-18.5.7	10	MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters	PerformRouterDiscovery	=	0	0	M	*	*=18.5.7
CIS-18.5.8	10	MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager	SafeDLLSearchMode	=	1	0	M	*	*=18.5.8
CIS-18.5.9	10	MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon	ScreenSaverGracePeriod	<=	5	5	M	*	*=18.5.9
CIS-18.5.10	10	MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted	reg	HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters	TcpMaxDataRetransmissions	<=	3	5	M	*	*=18.5.10
CIS-18.5.11	10	MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted	reg	HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters	TcpMaxDataRetransmissions	<=	3	5	M	*	*=18.5.11
CIS-18.5.12	10	MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security	WarningLevel	<=	90	0	M	*	*=18.5.12
CIS-18.6.4.1	3	DNS Client: Configure multicast DNS (mDNS) protocol	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	EnableMDNS	=	0	0	M	2022,2025	*=18.6.4.1
CIS-18.6.4.2	3	DNS Client: Configure NetBIOS settings	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	EnableNetbios	=	2		M	2016,2019,2025	2016=18.6.4.1;2019=18.6.4.1;2025=18.6.4.2
CIS-18.6.4.2#2	3	DNS Client: Configure NetBIOS settings	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	EnableNetbios	=|0	2		M	2022	*=18.6.4.2
CIS-18.6.4.3	3	DNS Client: Turn off default IPv6 DNS Servers	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	DisableIPv6DefaultDnsServers	=	1	0	M	2022,2025	*=18.6.4.3
CIS-18.6.4.4	3	DNS Client: Turn off multicast name resolution (LLMNR)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	EnableMulticast	=	0	1	M	*	2016=18.6.4.2;2019=18.6.4.2;2022=18.6.4.4;2025=18.6.4.4
CIS-18.6.5.1	3	Fonts: Enable Font Providers	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	EnableFontProviders	=	0	1	M	*	*=18.6.5.1
CIS-18.6.7.1	3	Lanman Server: Mandate the minimum version of SMB	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	MinSmb2Dialect	=	785		M	2022,2025	2022=18.6.7.1;2025=18.6.7.6
CIS-18.6.7.1#2	3	Lanman Server: Audit client does not support encryption	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	AuditClientDoesNotSupportEncryption	=	1	0	M	2025	*=18.6.7.1
CIS-18.6.7.2	3	Lanman Server: Audit client does not support signing	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	AuditClientDoesNotSupportSigning	=	1	0	M	2025	*=18.6.7.2
CIS-18.6.7.3	3	Lanman Server: Audit insecure guest logon	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	AuditInsecureGuestLogon	=	1	0	M	2025	*=18.6.7.3
CIS-18.6.7.3#2	3	Lanman Server: Enable authentication rate limiter	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	EnableAuthRateLimiter	=	1	1	M	2025	*=18.6.7.3
CIS-18.6.7.5	3	Lanman Server: Enable remote mailslots	reg	HKLM:\Software\Policies\Microsoft\Windows\Bowser	EnableMailslots	=	0	1	M	2025	*=18.6.7.5
CIS-18.6.7.7	3	Lanman Server: Set authentication rate limiter delay (milliseconds)	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	InvalidAuthenticationDelayTimeInMs	=	2000		M	2025	*=18.6.7.7
CIS-18.6.8.1	3	Lanman Workstation: Enable insecure guest logons	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	AllowInsecureGuestAuth	=	0	1	M	*	2016=18.6.8.1;2019=18.6.8.1;2022=18.6.8.1;2025=18.6.8.4
CIS-18.6.8.1#2	3	Lanman Workstation: Audit insecure guest logon	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	AuditInsecureGuestLogon	=	1	0	M	2025	*=18.6.8.1
CIS-18.6.8.2	3	Lanman Workstation: Require Encryption	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	RequireEncryption	=	1	0	M	2022,2025	2022=18.6.8.2;2025=18.6.8.7
CIS-18.6.8.2#2	3	Lanman Workstation: Audit server does not support encryption	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	AuditServerDoesNotSupportEncryption	=	1	0	M	2025	*=18.6.8.2
CIS-18.6.8.3	3	Lanman Workstation: Audit server does not support signing	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	AuditServerDoesNotSupportSigning	=	1	0	M	2025	*=18.6.8.3
CIS-18.6.8.5	3	Lanman Workstation: Enable remote mailslots	reg	HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider	EnableMailslots	=	0	1	M	2025	*=18.6.8.5
CIS-18.6.8.6	3	Lanman Workstation: Mandate the minimum version of SMB	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	MinSmb2Dialect	=	785		M	2025	*=18.6.8.6
CIS-18.6.9.1.1	3	Link-Layer Topology Discovery: Turn on Mapper I/O (LLTDIO) driver (AllowLLTDIOOndomain)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	AllowLLTDIOOndomain	=	0	0	M	*	*=18.6.9.1.1
CIS-18.6.9.1.2	3	Link-Layer Topology Discovery: Turn on Mapper I/O (LLTDIO) driver (AllowLLTDIOOnPublicNet)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	AllowLLTDIOOnPublicNet	=	0	0	M	*	*=18.6.9.1.2
CIS-18.6.9.1.3	3	Link-Layer Topology Discovery: Turn on Mapper I/O (LLTDIO) driver (EnableLLTDIO)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	EnableLLTDIO	=	0	0	M	*	*=18.6.9.1.3
CIS-18.6.9.1.4	3	Link-Layer Topology Discovery: Turn on Mapper I/O (LLTDIO) driver (ProhibitLLTDIOOnPrivateNet)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	ProhibitLLTDIOOnPrivateNet	=	0	0	M	*	*=18.6.9.1.4
CIS-18.6.9.2.1	3	Turn on Responder (RSPNDR) driver (AllowRspndrOnDomain)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD	AllowRspndrOnDomain	=	0	0	M	*	*=18.6.9.2.1
CIS-18.6.9.2.2	3	Turn on Responder (RSPNDR) driver (AllowRspndrOnPublicNet)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	AllowRspndrOnPublicNet	=	0	0	M	*	*=18.6.9.2.2
CIS-18.6.9.2.3	3	Turn on Responder (RSPNDR) driver (EnableRspndr)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	EnableRspndr	=	0	0	M	*	*=18.6.9.2.3
CIS-18.6.9.2.4	3	Turn on Responder (RSPNDR) driver (ProhibitRspndrOnPrivateNet)	reg	HKLM:\Software\Policies\Microsoft\Windows\LLTD	ProhibitRspndrOnPrivateNet	=	0	0	M	*	*=18.6.9.2.4
CIS-18.6.10.2	3	Turn off Microsoft Peer-to-Peer Networking Services	reg	HKLM:\Software\policies\Microsoft\Peernet	Disabled	=	1	0	M	*	*=18.6.10.2
CIS-18.6.11.2	3	Network Connections: Prohibit installation and configuration of Network Bridge on your DNS domain network	reg	HKLM:\Software\Policies\Microsoft\Windows\Network Connections	NC_AllowNetBridge_NLA	=	0	0	M	*	*=18.6.11.2
CIS-18.6.11.3	3	Network Connections: Prohibit use of Internet Connection Sharing on your DNS domain network	reg	HKLM:\Software\Policies\Microsoft\Windows\Network Connections	NC_ShowSharedAccessUI	=	0	1	M	*	*=18.6.11.3
CIS-18.6.11.4	3	Network Connections: Require domain users to elevate when setting a network's location	reg	HKLM:\Software\Policies\Microsoft\Windows\Network Connections	NC_StdDomainUserSetLocation	=	1	0	M	*	*=18.6.11.4
CIS-18.6.14.1.1	3	Network Provider: Hardened UNC Paths (NETLOGON)	reg	HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\NETLOGON	=	RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1		M	*	*=18.6.14.1.1
CIS-18.6.14.1.2	3	Network Provider: Hardened UNC Paths (SYSVOL)	reg	HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\SYSVOL	=	RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1		M	*	*=18.6.14.1.2
CIS-18.6.19.2.1	3	Disable IPv6	reg	HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters	DisabledComponents	=	255	0	M	*	*=18.6.19.2.1
CIS-18.6.20.1.1	3	Windows Connect Now: Configuration of wireless settings using Windows Connect Now (EnableRegistrars)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars	EnableRegistrars	=	0	1	M	*	*=18.6.20.1.1
CIS-18.6.20.1.2	3	Windows Connect Now: Configuration of wireless settings using Windows Connect Now (DisableUPnPRegistrar)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars	DisableUPnPRegistrar	=	0	1	M	*	*=18.6.20.1.2
CIS-18.6.20.1.3	3	Windows Connect Now: Configuration of wireless settings using Windows Connect Now (DisableInBand802DOT11Registrar)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars	DisableInBand802DOT11Registrar	=	0	1	M	*	*=18.6.20.1.3
CIS-18.6.20.1.4	3	Windows Connect Now: Configuration of wireless settings using Windows Connect Now (DisableFlashConfigRegistrar)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars	DisableFlashConfigRegistrar	=	0	1	M	*	*=18.6.20.1.4
CIS-18.6.20.1.5	3	Windows Connect Now: Configuration of wireless settings using Windows Connect Now (DisableWPDRegistrar)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars	DisableWPDRegistrar	=	0	1	M	*	*=18.6.20.1.5
CIS-18.6.20.2	3	Windows Connect Now: Prohibit access of the Windows Connect Now wizards	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI	DisableWcnUi	=	1	0	M	*	*=18.6.20.2
CIS-18.6.21.1	3	Windows Connection Manager: Minimize the number of simultaneous connections to the Internet or a Windows Domain	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy	fMinimizeConnections	=	3	1	M	*	*=18.6.21.1
CIS-18.6.21.2	3	Windows Connection Manager: Prohibit connection to non-domain networks when connected to domain authenticated network	reg	HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy	fBlockNonDomain	=	1	0	M	*	*=18.6.21.2
CIS-18.7.1	4	Allow Print Spooler to accept client connections	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers	RegisterSpoolerRemoteRpcEndPoint	=	2	1	M	*	*=18.7.1
CIS-18.7.2	4	Configure Redirection Guard	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers	RedirectionGuardPolicy	=	1		M	*	*=18.7.2
CIS-18.7.3	4	Configure RPC connection settings (RpcUseNamedPipeProtocol)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	RpcUseNamedPipeProtocol	=	0		M	*	*=18.7.3
CIS-18.7.4	4	Configure RPC connection settings (RpcAuthentication)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	RpcAuthentication	=	0		M	*	*=18.7.4
CIS-18.7.5	4	Configure RPC listener settings (RpcProtocols)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	RpcProtocols	=	5		M	*	*=18.7.5
CIS-18.7.6	4	Configure RPC listener settings (ForceKerberosForRpc)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	ForceKerberosForRpc	>=	0		M	*	*=18.7.6
CIS-18.7.7	4	Configure RPC over TCP port	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	RpcTcpPort	=	0		M	*	*=18.7.7
CIS-18.7.8	4	Configure RPC packet level privacy setting for incoming connections	reg	HKLM:\System\CurrentControlSet\Control\Print	RpcAuthnLevelPrivacyEnabled	=	1		M	*	2016=18.4.2;2019=18.4.2;2022=18.7.8;2025=18.7.8
CIS-18.7.9	4	Limits print driver installation to Administrators	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint	RestrictDriverInstallationToAdministrators	=	1		M	*	2016=18.7.8;2019=18.7.8;2022=18.7.9;2025=18.7.10
CIS-18.7.9#2	4	Configure Windows protected print	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\WPP	WindowsProtectedPrintGroupPolicyState	=	1	0	M	2025	*=18.7.9
CIS-18.7.10	4	Manage processing of Queue-specific files	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers	CopyFilesPolicy	=	1		M	*	2016=18.7.9;2019=18.7.9;2022=18.7.10;2025=18.7.11
CIS-18.7.11	4	Point and Print Restrictions: When installing drivers for a new connection	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint	NoWarningNoElevationOnInstall	=	0	0	M	*	2016=18.7.10;2019=18.7.10;2022=18.7.11;2025=18.7.12
CIS-18.7.12	4	Point and Print Restrictions: When updating drivers for an existing connection	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint	UpdatePromptSettings	=	0	0	M	*	2016=18.7.11;2019=18.7.11;2022=18.7.12;2025=18.7.13
CIS-18.8.1.1	5	Notifications: Turn off notifications network usage	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications	NoCloudApplicationNotification	=	1	0	M	*	*=18.8.1.1
CIS-18.9.3.1	6	Audit Process Creation: Include command line in process creation events	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit	ProcessCreationIncludeCmdLine_Enabled	=	1	0	M	*	*=18.9.3.1
CIS-18.9.4.1	6	Credentials Delegation: Encryption Oracle Remediation	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters	AllowEncryptionOracle	=	0	0	M	*	*=18.9.4.1
CIS-18.9.4.2	6	Credentials Delegation: Remote host allows delegation of non-exportable credentials	reg	HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation	AllowProtectedCreds	=	1	0	M	*	*=18.9.4.2
CIS-18.9.5.1	6	Device Guard: Turn On Virtualization Based Security (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	EnableVirtualizationBasedSecurity	=	1		M	*	*=18.9.5.1
CIS-18.9.5.2	6	Device Guard: Select Platform Security Level (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	RequirePlatformSecurityFeatures	>=	1		M	*	*=18.9.5.2
CIS-18.9.5.3	6	Device Guard: Virtualization Based Protection of Code Integrity (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	HypervisorEnforcedCodeIntegrity	=	1		M	*	*=18.9.5.3
CIS-18.9.5.4	6	Device Guard: Require UEFI Memory Attributes Table (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	HVCIMATRequired	=	1		M	*	*=18.9.5.4
CIS-18.9.5.5	6	Device Guard: Credential Guard Configuration (Member)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	LsaCfgFlags	=	1		M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.9.5.5
CIS-18.9.5.6	6	Device Guard: Credential Guard Configuration (DC)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	LsaCfgFlags	=	0		M	2016:DC,2019:DC,2022:DC,2025:DC	*=18.9.5.6
CIS-18.9.5.7	6	Device Guard: Secure Launch Configuration (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	ConfigureSystemGuardLaunch	=	1	0	M	*	*=18.9.5.7
CIS-18.9.7.2	6	Device Installation: Device Installation Restrictions: Prevent device metadata retrieval from the Internet	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata	PreventDeviceMetadataFromNetwork	=	1		M	*	*=18.9.7.2
CIS-18.9.13.1	6	Early Launch Antimalware: Boot-Start Driver Initialization Policy	reg	HKLM:\System\CurrentControlSet\Policies\EarlyLaunch	DriverLoadPolicy	=	3	0	M	*	*=18.9.13.1
CIS-18.9.19.2	6	Group Policy: Do not apply during periodic background processing	reg	HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}	NoGPOListChanges	=	0	0	M	*	*=18.9.19.2
CIS-18.9.19.3	6	Group Policy: Process even if the Group Policy objects have not changed	reg	HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}	NoBackgroundPolicy	=	0	1	M	*	*=18.9.19.3
CIS-18.9.19.4	6	Group Policy: Configure security policy processing: Do not apply during periodic background processing	reg	HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}	NoBackgroundPolicy	=	0	1	M	*	*=18.9.19.4
CIS-18.9.19.5	6	Group Policy: Configure security policy processing: Process even if the Group Policy objects have not changed	reg	HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}	NoGPOListChanges	=	0	1	M	*	*=18.9.19.5
CIS-18.9.19.6	6	Group Policy: Continue experiences on this device	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	EnableCdp	=	0	1	M	*	*=18.9.19.6
CIS-18.9.19.7	6	Group Policy: Turn off background refresh of Group Policy	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	DisableBkGndGroupPolicy	=	0	0	M	*	*=18.9.19.7
CIS-18.9.20.1.1	6	Internet Communication Management: Internet Communication settings: Turn off downloading of print drivers over HTTP	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers	DisableWebPnPDownload	=	1	0	M	*	*=18.9.20.1.1
CIS-18.9.20.1.2	6	Internet Communication Management: Internet Communication settings: Turn off handwriting personalization data sharing	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC	PreventHandwritingDataSharing	=	1	0	M	*	*=18.9.20.1.2
CIS-18.9.20.1.3	6	Internet Communication Management: Internet Communication settings: Turn off handwriting recognition error reporting	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports	PreventHandwritingErrorReports	=	1	0	M	*	*=18.9.20.1.3
CIS-18.9.20.1.4	6	Internet Communication Management: Internet Communication settings: Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard	ExitOnMSICW	=	1	0	M	*	*=18.9.20.1.4
CIS-18.9.20.1.5	6	Internet Communication Management: Internet Communication settings: Turn off Internet download for Web publishing and online ordering wizards	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoWebServices	=	1	0	M	*	*=18.9.20.1.5
CIS-18.9.20.1.6	6	Internet Communication Management: Internet Communication settings: Turn off printing over HTTP	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers	DisableHTTPPrinting	=	1	0	M	*	*=18.9.20.1.6
CIS-18.9.20.1.7	6	Internet Communication Management: Internet Communication settings: Turn off Registration if URL connection is referring to Microsoft.com	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control	NoRegistration	=	1	0	M	*	*=18.9.20.1.7
CIS-18.9.20.1.8	6	Internet Communication Management: Internet Communication settings: Turn off Search Companion content file updates	reg	HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion	DisableContentFileUpdates	=	1	0	M	*	*=18.9.20.1.8
CIS-18.9.20.1.9	6	Internet Communication Management: Internet Communication settings: Turn off the 'Order Prints' picture task	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoOnlinePrintsWizard	=	1	0	M	*	*=18.9.20.1.9
CIS-18.9.20.1.10	6	Internet Communication Management: Internet Communication settings: Turn off the 'Publish to Web' task for files and folders	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoPublishingWizard	=	1	0	M	*	*=18.9.20.1.10
CIS-18.9.20.1.11	6	Internet Communication Management: Internet Communication settings: Turn off the Windows Messenger Customer Experience Improvement Program	reg	HKLM:\Software\Policies\Microsoft\Messenger\Client	CEIP	=	2	0	M	*	*=18.9.20.1.11
CIS-18.9.20.1.12	6	Internet Communication Management: Internet Communication settings: Turn off Windows Customer Experience Improvement Program	reg	HKLM:\Software\Policies\Microsoft\SQMClient\Windows	CEIPEnable	=	0	1	M	*	*=18.9.20.1.12
CIS-18.9.20.1.13.1	6	Internet Communication Management: Internet Communication settings: Turn off Windows Error Reporting 1	reg	HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting	DoReport	=	0	1	M	*	*=18.9.20.1.13.1
CIS-18.9.20.1.13.2	6	Internet Communication Management: Internet Communication settings: Turn off Windows Error Reporting 2	reg	HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting	Disabled	=	1	0	M	*	*=18.9.20.1.13.2
CIS-18.9.23.1.1	6	Kerberos: Support device authentication using certificate (DevicePKInitBehavior)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters	DevicePKInitBehavior	=	0	1	M	*	*=18.9.23.1.1
CIS-18.9.23.1.2	6	Kerberos: Support device authentication using certificate (DevicePKInitEnabled)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters	DevicePKInitEnabled	=	1	1	M	*	*=18.9.23.1.2
CIS-18.9.24.1	6	Kernel DMA Protection: Enumeration policy for external devices incompatible with Kernel DMA Protection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection	DeviceEnumerationPolicy	=	0	2	M	2019,2022,2025	*=18.9.24.1
CIS-18.9.25.1	6	LAPS: Configure password backup directory	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	BackupDirectory	<=!0	2		M	2019,2022,2025	*=18.9.25.1
CIS-18.9.25.2	6	LAPS: Do not allow password expiration time longer than required by policy	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PwdExpirationProtectionEnabled	=	1		M	2019,2022,2025	*=18.9.25.2
CIS-18.9.25.3	6	LAPS: Enable password encryption	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	ADPasswordEncryptionEnabled	=	1		M	2019,2022,2025	*=18.9.25.3
CIS-18.9.25.4	6	LAPS: Password Settings: Password Complexity	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PasswordComplexity	=	4		M	2019,2022,2025	*=18.9.25.4
CIS-18.9.25.5	6	LAPS: Password Settings: Password Length	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PasswordLength	>=	15		M	2019,2022,2025	*=18.9.25.5
CIS-18.9.25.6	6	LAPS: Password Settings: Password Age (Days)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PasswordAgeDays	<=	30		M	2019,2022,2025	*=18.9.25.6
CIS-18.9.25.7	6	LAPS: Post-authentication actions: Grace period (hours)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PostAuthenticationResetDelay	<=!0	8		M	2019,2022,2025	*=18.9.25.7
CIS-18.9.25.8	6	LAPS: Post-authentication actions: Actions	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS	PostAuthenticationActions	>=	3		M	2019,2022,2025	*=18.9.25.8
CIS-18.9.26.1	6	Local Security Authority: Allow Custom SSPs and APs to be loaded into LSASS	reg	HKLM:\Software\Policies\Microsoft\Windows\System	AllowCustomSSPsAPs	=	0		M	2022,2025	*=18.9.26.1
CIS-18.9.26.2	6	Local Security Authority: Configures LSASS to run as a protected process	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	RunAsPPL	=	1		M	*	2016=18.4.7;2019=18.4.7;2022=18.9.26.2;2025=18.9.26.2
CIS-18.9.27.1	6	Locale Services: Disallow copying of user input methods to the system account for sign-in	reg	HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International	BlockUserInputMethodsForSignIn	=	1	0	M	*	*=18.9.27.1
CIS-18.9.28.1	6	Logon: Block user from showing account details on sign-in	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	BlockUserFromShowingAccountDetailsOnSignin	=	1	0	M	*	*=18.9.28.1
CIS-18.9.28.2	6	Logon: Do not display network selection UI	reg	HKLM:\Software\Policies\Microsoft\Windows\System	DontDisplayNetworkSelectionUI	=	1	0	M	*	*=18.9.28.2
CIS-18.9.28.3	6	Logon: Do not enumerate connected users on domain-joined computers	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	DontEnumerateConnectedUsers	=	1	0	M	*	*=18.9.28.3
CIS-18.9.28.4	6	Logon: Enumerate local users on domain-joined computers (Member)	reg	HKLM:\Software\Policies\Microsoft\Windows\System	EnumerateLocalUsers	=	0	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.9.28.4
CIS-18.9.28.5	6	Logon: Turn off app notifications on the lock screen	reg	HKLM:\Software\Policies\Microsoft\Windows\System	DisableLockScreenAppNotifications	=	1	0	M	*	*=18.9.28.5
CIS-18.9.28.6	6	Logon: Turn off picture password sign-in	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	BlockDomainPicturePassword	=	1	0	M	*	*=18.9.28.6
CIS-18.9.28.7	6	Logon: Turn on convenience PIN sign-in	reg	HKLM:\Software\Policies\Microsoft\Windows\System	AllowDomainPINLogon	=	0	1	M	*	*=18.9.28.7
CIS-18.9.30.1.1	6	Net Logon: DC Locator DNS Records: Block NetBIOS-based discovery for domain controller location	reg	HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters	BlockNetbiosDiscovery	=	1	1	M	2025	*=18.9.30.1.1
CIS-18.9.31.1	6	OS Policies: Allow Clipboard synchronization across devices	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	AllowCrossDeviceClipboard	=	0	1	M	2019,2022,2025	*=18.9.31.1
CIS-18.9.31.2	6	OS Policies: Allow upload of User Activities	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	UploadUserActivities	=	0	1	M	2019,2022,2025	*=18.9.31.2
CIS-18.9.33.6.1	6	Sleep Settings: Allow network connectivity during connected-standby (on battery)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9	DCSettingIndex	=	0	1	M	*	*=18.9.33.6.1
CIS-18.9.33.6.2	6	Sleep Settings: Allow network connectivity during connected-standby (plugged in)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9	ACSettingIndex	=	0	1	M	*	*=18.9.33.6.2
CIS-18.9.33.6.3	6	Sleep Settings: Require a password when a computer wakes (on battery)	reg	HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51	DCSettingIndex	=	1	0	M	*	*=18.9.33.6.3
CIS-18.9.33.6.4	6	Sleep Settings: Require a password when a computer wakes (plugged in)	reg	HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51	ACSettingIndex	=	1	0	M	*	*=18.9.33.6.4
CIS-18.9.35.1	6	Remote Assistance: Configure Offer Remote Assistance	reg	HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services	fAllowUnsolicited	=	0	1	M	*	*=18.9.35.1
CIS-18.9.35.2	6	Remote Assistance: Configure Solicited Remote Assistance	reg	HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services	fAllowToGetHelp	=	0	1	M	*	*=18.9.35.2
CIS-18.9.36.1	6	Remote Procedure Call: Enable RPC Endpoint Mapper Client Authentication (Member)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Rpc	EnableAuthEpResolution	=	1	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.9.36.1
CIS-18.9.36.2	6	Remote Procedure Call: Restrict Unauthenticated RPC clients (Member)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Rpc	RestrictRemoteClients	=	1	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.9.36.2
CIS-18.9.39.1	6	Security Account Manager: Configure validation of ROCA-vulnerable WHfB keys during authentication (DC only)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\SAM	SamNGCKeyROCAValidation	>=	1		M	2022:DC,2025:DC	*=18.9.39.1
CIS-18.9.39.2	6	Security Account Manager: Configure SAM change password RPC methods policy (DC)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM	SamrChangeUserPasswordApiPolicy	=	2	1	M	2025:DC	*=18.9.39.2
CIS-18.9.39.3	6	Security Account Manager: Configure SAM change password RPC methods policy (Member)	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM	SamrChangeUserPasswordApiPolicy	=	1	1	M	2025:MS	*=18.9.39.3
CIS-18.9.47.5.1	6	Troubleshooting and Diagnostics: Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy	DisableQueryRemoteServer	=	0	1	M	*	*=18.9.47.5.1
CIS-18.9.47.11.1	6	Windows Performance PerfTrack: Enable/Disable PerfTrack	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}	ScenarioExecutionEnabled	=	0	1	M	*	*=18.9.47.11.1
CIS-18.9.49.1	6	User Profiles: Turn off the advertising ID	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo	DisabledByGroupPolicy	=	1	0	M	*	*=18.9.49.1
CIS-18.9.51.1.1	6	Time Providers: Enable Windows NTP Client	reg	HKLM:\Software\Policies\Microsoft\W32time\TimeProviders\NtpClient	Enabled	=	1	0	M	*	*=18.9.51.1.1
CIS-18.9.51.1.2	6	Time Providers: Enable Windows NTP Server (Member)	reg	HKLM:\Software\Policies\Microsoft\W32time\TimeProviders\NtpServer	Enabled	=	0	0	M	2016:MS,2019:MS,2022:MS,2025:MS	*=18.9.51.1.2
CIS-18.10.4.1	7	App Package Deployment: Allow a Windows app to share application data between users	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager	AllowSharedLocalAppData	=	0	1	M	*	2016=18.10.3.1;2019=18.10.3.1;2022=18.10.4.1;2025=18.10.4.1
CIS-18.10.4.2	7	App Package Deployment: Not allow per-user unsigned packages to install by default (requires explicitly allow per install)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx	DisablePerUserUnsignedPackagesByDefault	=	1	0	M	2025	*=18.10.4.2
CIS-18.10.6.1	7	App runtime: Allow Microsoft accounts to be optional	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	MSAOptional	=	1	0	M	*	2016=18.10.5.1;2019=18.10.5.1;2022=18.10.6.1;2025=18.10.6.1
CIS-18.10.8.1	7	AutoPlay Policies: Disallow Autoplay for non-volume devices	reg	HKLM:\Software\Policies\Microsoft\Windows\Explorer	NoAutoplayfornonVolume	=	1	0	M	*	2016=18.10.7.1;2019=18.10.7.1;2022=18.10.8.1;2025=18.10.8.1
CIS-18.10.8.2	7	AutoPlay Policies: Set the default behavior for AutoRun	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoAutorun	=	1	0	M	*	2016=18.10.7.2;2019=18.10.7.2;2022=18.10.8.2;2025=18.10.8.2
CIS-18.10.8.3	7	AutoPlay Policies: Turn off Autoplay	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoDriveTypeAutoRun	=	255	0	M	*	2016=18.10.7.3;2019=18.10.7.3;2022=18.10.8.3;2025=18.10.8.3
CIS-18.10.9.1.1	7	Biometrics: Facial Features: Configure enhanced anti-spoofing	reg	HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures	EnhancedAntiSpoofing	=	1		M	*	2016=18.10.8.1.1;2019=18.10.8.1.1;2022=18.10.9.1.1;2025=18.10.9.1.1
CIS-18.10.11.1	7	Camera: Allow Use of Camera	reg	HKLM:\SOFTWARE\Policies\Microsoft\Camera	AllowCamera	=	0	1	M	*	2016=18.10.10.1;2019=18.10.10.1;2022=18.10.11.1;2025=18.10.11.1
CIS-18.10.13.1	7	Cloud Content: Turn off cloud consumer account state content	reg	HKLM:\Software\Policies\Microsoft\Windows\CloudContent	DisableConsumerAccountStateContent	=	1		M	2016,2022,2025	2016=18.10.12.1;2022=18.10.13.1;2025=18.10.13.1
CIS-18.10.13.2	7	Cloud Content: Turn off cloud optimized content	reg	HKLM:\Software\Policies\Microsoft\Windows\CloudContent	DisableCloudOptimizedContent	=	1	0	M	2019,2022,2025	2019=18.10.12.1;2022=18.10.13.2;2025=18.10.13.2
CIS-18.10.13.3	7	Cloud Content: Turn off Microsoft consumer experiences	reg	HKLM:\Software\Policies\Microsoft\Windows\CloudContent	DisableWindowsConsumerFeatures	=	1	0	M	*	2016=18.10.12.2;2019=18.10.12.2;2022=18.10.13.3;2025=18.10.13.3
CIS-18.10.14.1	7	Connect: Require pin for pairing	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect	RequirePinForPairing	>=	1	0	M	*	2016=18.10.13.1;2019=18.10.13.1;2022=18.10.14.1;2025=18.10.14.1
CIS-18.10.15.1	7	Credential User Interface: Do not display the password reveal button	reg	HKLM:\Software\Policies\Microsoft\Windows\CredUI	DisablePasswordReveal	=	1	0	M	*	2016=18.10.14.1;2019=18.10.14.1;2022=18.10.15.1;2025=18.10.15.1
CIS-18.10.15.2	7	Credential User Interface: Enumerate administrator accounts on elevation	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI	EnumerateAdministrators	=	0	1	M	*	2016=18.10.14.2;2019=18.10.14.2;2022=18.10.15.2;2025=18.10.15.2
CIS-18.10.16.1	7	Data Collection and Preview Builds: Allow Diagnostic Data	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	AllowTelemetry	<=	1	2	M	*	2016=18.10.15.1;2019=18.10.15.1;2022=18.10.16.1;2025=18.10.16.1
CIS-18.10.16.2	7	Data Collection and Preview Builds: Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	DisableEnterpriseAuthProxy	=	1	0	M	*	2016=18.10.15.2;2019=18.10.15.2;2022=18.10.16.2;2025=18.10.16.2
CIS-18.10.16.3	7	Data Collection and Preview Builds: Disable OneSettings Downloads	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	DisableOneSettingsDownloads	=	1		M	*	2016=18.10.15.3;2019=18.10.15.3;2022=18.10.16.3;2025=18.10.16.3
CIS-18.10.16.4	7	Data Collection and Preview Builds: Do not show feedback notifications	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	DoNotShowFeedbackNotifications	=	1	0	M	*	2016=18.10.15.4;2019=18.10.15.4;2022=18.10.16.4;2025=18.10.16.4
CIS-18.10.16.5	7	Data Collection and Preview Builds: Enable OneSettings Auditing	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	EnableOneSettingsAuditing	=	1		M	*	2016=18.10.15.5;2019=18.10.15.5;2022=18.10.16.5;2025=18.10.16.5
CIS-18.10.16.6	7	Data Collection and Preview Builds: Limit Diagnostic Log Collection	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	LimitDiagnosticLogCollection	=	1		M	*	2016=18.10.15.6;2019=18.10.15.6;2022=18.10.16.6;2025=18.10.16.6
CIS-18.10.16.7	7	Data Collection and Preview Builds: Limit Dump Collection	reg	HKLM:\Software\Policies\Microsoft\Windows\DataCollection	LimitDumpCollection	=	1		M	*	2016=18.10.15.7;2019=18.10.15.7;2022=18.10.16.7;2025=18.10.16.7
CIS-18.10.16.8	7	Data Collection and Preview Builds: Toggle user control over Insider builds	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds	AllowBuildPreview	=	0	1	M	2016,2019,2025	2016=18.10.15.8;2019=18.10.15.8;2025=18.10.16.8
CIS-18.10.18.1	7	Desktop App Installer: Enable App Installer	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableAppInstaller	=	0		M	2019,2022,2025	2019=18.10.17.1;2022=18.10.18.1;2025=18.10.18.1
CIS-18.10.18.2	7	Desktop App Installer: Enable App Installer Experimental Features	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableExperimentalFeatures	=	0		M	2019,2022,2025	2019=18.10.17.2;2022=18.10.18.2;2025=18.10.18.2
CIS-18.10.18.3	7	Desktop App Installer: Enable App Installer Hash Override	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableHashOverride	=	0		M	2019,2022,2025	2019=18.10.17.3;2022=18.10.18.3;2025=18.10.18.3
CIS-18.10.18.4	7	Desktop App Installer: Enable App Installer Local Archive Malware Scan Override	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableLocalArchiveMalwareScanOverride	=	0		M	2022,2025	*=18.10.18.4
CIS-18.10.18.5	7	Desktop App Installer: Enable App Installer ms-appinstaller protocol	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableMSAppInstallerProtocol	=	0		M	2019,2022,2025	2019=18.10.17.4;2022=18.10.18.5;2025=18.10.18.5
CIS-18.10.18.6	7	Desktop App Installer: Enable App Installer Microsoft Store Source Certificate Validation Bypass	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableBypassCertificatePinningForMicrosoftStore	=	0		M	2022,2025	*=18.10.18.6
CIS-18.10.18.7	7	Desktop App Installer: Enable Windows Package Manager command line interfaces	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller	EnableWindowsPackageManagerCommandLineInterfaces	=	0	1	M	2022,2025	*=18.10.18.7
CIS-18.10.26.1.1	7	Event Log Service: Application: Control Event Log behavior when the log file reaches its maximum size	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application	Retention	=	0	0	M	*	2016=18.10.25.1.1;2019=18.10.25.1.1;2022=18.10.26.1.1;2025=18.10.26.1.1
CIS-18.10.26.1.2	7	Event Log Service: Application: Specify the maximum log file size (KB)	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application	MaxSize	>=	32768	4096	M	*	2016=18.10.25.1.2;2019=18.10.25.1.2;2022=18.10.26.1.2;2025=18.10.26.1.2
CIS-18.10.26.2.1	7	Event Log Service: Security: Control Event Log behavior when the log file reaches its maximum size	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security	Retention	=	0	0	M	*	2016=18.10.25.2.1;2019=18.10.25.2.1;2022=18.10.26.2.1;2025=18.10.26.2.1
CIS-18.10.26.2.2	7	Event Log Service: Security: Specify the maximum log file size (KB)	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security	MaxSize	>=	196608	4096	M	*	2016=18.10.25.2.2;2019=18.10.25.2.2;2022=18.10.26.2.2;2025=18.10.26.2.2
CIS-18.10.26.3.1	7	Event Log Service: Setup: Control Event Log behavior when the log file reaches its maximum size	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup	Retention	=	0	0	M	*	2016=18.10.25.3.1;2019=18.10.25.3.1;2022=18.10.26.3.1;2025=18.10.26.3.1
CIS-18.10.26.3.2	7	Event Log Service: Setup: Specify the maximum log file size (KB)	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup	MaxSize	>=	32768	4096	M	*	2016=18.10.25.3.2;2019=18.10.25.3.2;2022=18.10.26.3.2;2025=18.10.26.3.2
CIS-18.10.26.4.1	7	Event Log Service: System: Control Event Log behavior when the log file reaches its maximum size	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\System	Retention	=	0	0	M	*	2016=18.10.25.4.1;2019=18.10.25.4.1;2022=18.10.26.4.1;2025=18.10.26.4.1
CIS-18.10.26.4.2	7	Event Log Service: System: Specify the maximum log file size (KB)	reg	HKLM:\Software\Policies\Microsoft\Windows\EventLog\System	MaxSize	>=	32768	4096	M	*	2016=18.10.25.4.2;2019=18.10.25.4.2;2022=18.10.26.4.2;2025=18.10.26.4.2
CIS-18.10.29.2	7	File Explorer: Do not apply the Mark of the Web tag to files copied from insecure sources	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	DisableMotWOnInsecurePathCopy	=	0	0	M	2022,2025	*=18.10.29.2
CIS-18.10.29.3	7	File Explorer: Turn off Data Execution Prevention for Explorer	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoDataExecutionPrevention	=	0	0	M	*	2016=18.10.28.2;2019=18.10.28.2;2022=18.10.29.3;2025=18.10.28.3
CIS-18.10.29.4	7	File Explorer: Turn off heap termination on corruption	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoHeapTerminationOnCorruption	=	0	0	M	*	2016=18.10.28.3;2019=18.10.28.3;2022=18.10.29.4;2025=18.10.28.4
CIS-18.10.29.5	7	File Explorer: Turn off shell protocol protected mode	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	PreXPSP2ShellProtocolBehavior	=	0	0	M	*	2016=18.10.28.4;2019=18.10.28.4;2022=18.10.29.5;2025=18.10.28.5
CIS-18.10.37.1	7	Location and Sensors: Turn off location	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors	DisableLocation	=	1	0	M	*	2016=18.10.36.1;2019=18.10.36.1;2022=18.10.37.1;2025=18.10.37.1
CIS-18.10.41.1	7	Messaging: Allow Message Service Cloud Sync	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging	AllowMessageSync	=	0	1	M	*	2016=18.10.40.1;2019=18.10.40.1;2022=18.10.41.1;2025=18.10.41.1
CIS-18.10.42.1	7	Microsoft account: Block all consumer Microsoft account user authentication	reg	HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount	DisableUserAuth	=	1		M	*	2016=18.10.41.1;2019=18.10.41.1;2022=18.10.42.1;2025=18.10.42.1
CIS-18.10.42.17	7	Microsoft Defender Antivirus: Turn off Microsoft Defender Antivirus	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	DisableAntiSpyware	=	0	0	M	2016,2019	*=18.10.42.17
CIS-18.10.43.4.1	7	Microsoft Defender Antivirus: Features: Enable EDR in block mode	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Features	PassiveRemediation	=	1	0	M	2022,2025	*=18.10.43.4.1
CIS-18.10.43.5.1	7	Microsoft Defender Antivirus: MAPS: Configure local setting override for reporting to Microsoft MAPS	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet	LocalSettingOverrideSpynetReporting	=	0		M	*	2016=18.10.42.3.1;2019=18.10.42.5.1;2022=18.10.43.5.1;2025=18.10.43.5.1
CIS-18.10.43.5.2	7	Microsoft Defender Antivirus: MAPS: Join Microsoft MAPS	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet	SpynetReporting	=|0	0	0	M	*	2016=18.10.42.3.2;2019=18.10.42.5.2;2022=18.10.43.5.2;2025=18.10.43.5.2
CIS-18.10.43.6.1.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: Attack Surface Reduction rules	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR	ExploitGuard_ASR_Rules	=	1	0	M	*	2016=18.10.42.6.1.1;2019=18.10.42.6.1.1;2022=18.10.43.6.1.1;2025=18.10.43.6.1.1
CIS-18.10.43.6.1.2.1.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block all Office applications from creating child processes (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	d4f940ab-401b-4efc-aadc-ad5f3c50688a	=	1	0	M	*	2016=18.10.42.6.1.2.10.1;2019=18.10.42.6.1.2.1.1;2022=18.10.43.6.1.2.1.1;2025=18.10.43.6.1.2.1.1
CIS-18.10.43.6.1.2.1.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block all Office applications from creating child processes	asr	d4f940ab-401b-4efc-aadc-ad5f3c50688a		=	1	0	M	*	2016=18.10.42.6.1.2.10.2;2019=18.10.42.6.1.2.1.2;2022=18.10.43.6.1.2.1.2;2025=18.10.43.6.1.2.1.2
CIS-18.10.43.6.1.2.2.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office applications from creating executable content (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	3b576869-a4ec-4529-8536-b80a7769e899	=	1	0	M	*	2016=18.10.42.6.1.2.2.1;2019=18.10.42.6.1.2.2.1;2022=18.10.43.6.1.2.2.1;2025=18.10.43.6.1.2.2.1
CIS-18.10.43.6.1.2.2.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office applications from creating executable content	asr	3b576869-a4ec-4529-8536-b80a7769e899		=	1	0	M	*	2016=18.10.42.6.1.2.2.2;2019=18.10.42.6.1.2.2.2;2022=18.10.43.6.1.2.2.2;2025=18.10.43.6.1.2.2.2
CIS-18.10.43.6.1.2.3.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block execution of potentially obfuscated scripts (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	5beb7efe-fd9a-4556-801d-275e5ffc04cc	=	1	0	M	*	2016=18.10.42.6.1.2.4.1;2019=18.10.42.6.1.2.3.1;2022=18.10.43.6.1.2.3.1;2025=18.10.43.6.1.2.3.1
CIS-18.10.43.6.1.2.3.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block execution of potentially obfuscated scripts	asr	5beb7efe-fd9a-4556-801d-275e5ffc04cc		=	1	0	M	*	2016=18.10.42.6.1.2.4.2;2019=18.10.42.6.1.2.3.2;2022=18.10.43.6.1.2.3.2;2025=18.10.43.6.1.2.3.2
CIS-18.10.43.6.1.2.4.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office applications from injecting code into other processes (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84	=	1	0	M	*	2016=18.10.42.6.1.2.5.1;2019=18.10.42.6.1.2.4.1;2022=18.10.43.6.1.2.4.1;2025=18.10.43.6.1.2.4.1
CIS-18.10.43.6.1.2.4.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office applications from injecting code into other processes	asr	75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84		=	1	0	M	*	2016=18.10.42.6.1.2.5.2;2019=18.10.42.6.1.2.4.2;2022=18.10.43.6.1.2.4.2;2025=18.10.43.6.1.2.4.2
CIS-18.10.43.6.1.2.5.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Adobe Reader from creating child processes (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c	=	1	0	M	*	2016=18.10.42.6.1.2.6.1;2019=18.10.42.6.1.2.5.1;2022=18.10.43.6.1.2.5.1;2025=18.10.43.6.1.2.5.1
CIS-18.10.43.6.1.2.5.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Adobe Reader from creating child processes	asr	7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c		=	1	0	M	*	2016=18.10.42.6.1.2.6.2;2019=18.10.42.6.1.2.5.2;2022=18.10.43.6.1.2.5.2;2025=18.10.43.6.1.2.5.2
CIS-18.10.43.6.1.2.6.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Win32 API calls from Office macros (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b	=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.6.1;2022=18.10.43.6.1.2.6.1;2025=18.10.43.6.1.2.6.1
CIS-18.10.43.6.1.2.6.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Win32 API calls from Office macros	asr	92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b		=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.6.2;2022=18.10.43.6.1.2.6.2;2025=18.10.43.6.1.2.6.2
CIS-18.10.43.6.1.2.7.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe) (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2	=	1	0	M	*	2016=18.10.42.6.1.2.7.1;2019=18.10.42.6.1.2.7.1;2022=18.10.43.6.1.2.7.1;2025=18.10.43.6.1.2.7.1
CIS-18.10.43.6.1.2.7.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe)	asr	9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2		=	1	0	M	*	2016=18.10.42.6.1.2.7.2;2019=18.10.42.6.1.2.7.2;2022=18.10.43.6.1.2.7.2;2025=18.10.43.6.1.2.7.2
CIS-18.10.43.6.1.2.8.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block untrusted and unsigned processes that run from USB (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4	=	1	0	M	*	2016=18.10.42.6.1.2.8.1;2019=18.10.42.6.1.2.8.1;2022=18.10.43.6.1.2.8.1;2025=18.10.43.6.1.2.8.1
CIS-18.10.43.6.1.2.8.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block untrusted and unsigned processes that run from USB	asr	b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4		=	1	0	M	*	2016=18.10.42.6.1.2.8.2;2019=18.10.42.6.1.2.8.2;2022=18.10.43.6.1.2.8.2;2025=18.10.43.6.1.2.8.2
CIS-18.10.43.6.1.2.9.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block executable content from email client and webmail (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	be9ba2d9-53ea-4cdc-84e5-9b1eeee46550	=	1	0	M	*	2016=18.10.42.6.1.2.9.1;2019=18.10.42.6.1.2.9.1;2022=18.10.43.6.1.2.9.1;2025=18.10.43.6.1.2.9.1
CIS-18.10.43.6.1.2.9.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block executable content from email client and webmail	asr	be9ba2d9-53ea-4cdc-84e5-9b1eeee46550		=	1	0	M	*	2016=18.10.42.6.1.2.9.2;2019=18.10.42.6.1.2.9.2;2022=18.10.43.6.1.2.9.2;2025=18.10.43.6.1.2.9.2
CIS-18.10.43.6.1.2.10.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block JavaScript or VBScript from launching downloaded executable content (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	d3e037e1-3eb8-44c8-a917-57927947596d	=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.10.1;2022=18.10.43.6.1.2.10.1;2025=18.10.43.6.1.2.10.1
CIS-18.10.43.6.1.2.10.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block JavaScript or VBScript from launching downloaded executable content	asr	d3e037e1-3eb8-44c8-a917-57927947596d		=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.10.2;2022=18.10.43.6.1.2.10.2;2025=18.10.43.6.1.2.10.2
CIS-18.10.43.6.1.2.11.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office communication application from creating child processes (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	26190899-1602-49e8-8b27-eb1d0a1ce869	=	1	0	M	*	2016=18.10.42.6.1.2.1.1;2019=18.10.42.6.1.2.11.1;2022=18.10.43.6.1.2.11.1;2025=18.10.43.6.1.2.11.1
CIS-18.10.43.6.1.2.11.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Office communication application from creating child processes	asr	26190899-1602-49e8-8b27-eb1d0a1ce869		=	1	0	M	*	2016=18.10.42.6.1.2.1.2;2019=18.10.42.6.1.2.11.2;2022=18.10.43.6.1.2.11.2;2025=18.10.43.6.1.2.11.2
CIS-18.10.43.6.1.2.12.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block persistence through WMI event subscription (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	e6db77e5-3df2-4cf1-b95a-636979351e5b	=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.12.1;2022=18.10.43.6.1.2.12.1;2025=18.10.43.6.1.2.12.1
CIS-18.10.43.6.1.2.12.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block persistence through WMI event subscription	asr	e6db77e5-3df2-4cf1-b95a-636979351e5b		=	1	0	M	2019,2022,2025	2019=18.10.42.6.1.2.12.2;2022=18.10.43.6.1.2.12.2;2025=18.10.43.6.1.2.12.2
CIS-18.10.43.6.1.2.13.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block abuse of exploited vulnerable signed drivers (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	56a863a9-875e-4185-98a7-b882c64b5ce5	=	1	0	M	*	2016=18.10.42.6.1.2.3.1;2019=18.10.42.6.1.2.13.1;2022=18.10.43.6.1.2.13.1;2025=18.10.43.6.1.2.13.1
CIS-18.10.43.6.1.2.13.2	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block abuse of exploited vulnerable signed drivers	asr	56a863a9-875e-4185-98a7-b882c64b5ce5		=	1	0	M	*	2016=18.10.42.6.1.2.3.2;2019=18.10.42.6.1.2.13.2;2022=18.10.43.6.1.2.13.2;2025=18.10.43.6.1.2.13.2
CIS-18.10.43.6.3.1	7	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: Network Protection: Prevent users and apps from accessing dangerous websites	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection	EnableNetworkProtection	=	1		M	*	2016=18.10.42.6.3.1;2019=18.10.42.6.3.1;2022=18.10.43.6.3.1;2025=18.10.43.6.3.1
CIS-18.10.43.7.1	7	Microsoft Defender Antivirus: MpEngine: Enable file hash computation feature	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine	EnableFileHashComputation	=	1		M	*	2016=18.10.42.7.1;2019=18.10.42.7.1;2022=18.10.43.7.1;2025=18.10.43.7.1
CIS-18.10.43.8.1	7	Microsoft Defender Antivirus: Network Inspection System: Convert warn verdict to block	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\NIS	EnableConvertWarnToBlock	=	1	0	M	2022,2025	*=18.10.43.8.1
CIS-18.10.43.10.1	7	Microsoft Defender Antivirus: Real-time Protection: Configure real-time protection and Security Intelligence Updates during OOBE	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection	OobeEnableRtpAndSigUpdate	=	1	1	M	2022,2025	*=18.10.43.10.1
CIS-18.10.43.10.2	7	Microsoft Defender Antivirus: Real-time Protection: Scan all downloaded files and attachments	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection	DisableIOAVProtection	=	0	0	M	*	2016=18.10.42.10.1;2019=18.10.42.10.1;2022=18.10.43.10.2;2025=18.10.43.10.2
CIS-18.10.43.10.3	7	Microsoft Defender Antivirus: Real-time Protection: Turn off real-time protection	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection	DisableRealtimeMonitoring	=	0	0	M	*	2016=18.10.42.10.2;2019=18.10.42.10.2;2022=18.10.43.10.3;2025=18.10.43.10.3
CIS-18.10.43.10.4	7	Microsoft Defender Antivirus: Real-time Protection: Turn on behavior monitoring (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection	DisableBehaviorMonitoring	=	0	0	M	*	2016=18.10.42.10.3;2019=18.10.42.10.3;2022=18.10.43.10.4;2025=18.10.43.10.4
CIS-18.10.43.10.5	7	Microsoft Defender Antivirus: Real-time Protection: Turn on script scanning	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection	DisableScriptScanning	=	0	0	M	*	2016=18.10.42.10.4;2019=18.10.42.10.4;2022=18.10.43.10.5;2025=18.10.43.10.5
CIS-18.10.43.11.1.1.1	7	Microsoft Defender Antivirus: Remediation: Behavioral Network Blocks: Brute-Force Protection: Configure Brute-Force Protection aggressiveness	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection	BruteForceProtectionAggressiveness	>=	1	0	M	2022,2025	*=18.10.43.11.1.1.1
CIS-18.10.43.11.1.1.2	7	Microsoft Defender Antivirus: Remediation: Behavioral Network Blocks: Brute-Force Protection: Configure Remote Encryption Protection Mode	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection	BruteForceProtectionConfiguredState	>=	1		M	2022,2025	*=18.10.43.11.1.1.2
CIS-18.10.43.11.1.2.1	7	Microsoft Defender Antivirus: Remediation: Behavioral Network Blocks: Remote Encryption Protection: Configure how aggressively Remote Encryption Protection blocks threats	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection	RemoteEncryptionProtectionAggressiveness	>=	1	0	M	2022,2025	*=18.10.43.11.1.2.1
CIS-18.10.43.12.1	7	Microsoft Defender Antivirus: Reporting: Configure Watson events	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting	DisableGenericRePorts	=	1	0	M	*	2016=18.10.42.12.1;2019=18.10.42.12.1;2022=18.10.43.12.1;2025=18.10.43.12.1
CIS-18.10.43.13.1	7	Microsoft Defender Antivirus: Scan: Scan excluded files and directories during quick scans	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Scan	QuickScanIncludeExclusions	=	1	0	M	2022,2025	*=18.10.43.13.1
CIS-18.10.43.13.2	7	Microsoft Defender Antivirus: Scan: Scan packed executables	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Scan	DisablePackedExeScanning	=	0		M	*	2016=18.10.42.13.1;2019=18.10.42.13.1;2022=18.10.43.13.2;2025=18.10.43.13.2
CIS-18.10.43.13.3	7	Microsoft Defender Antivirus: Scan: Scan removable drives	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Scan	DisableRemovableDriveScanning	=	0	1	M	*	2016=18.10.42.13.2;2019=18.10.42.13.2;2022=18.10.43.13.3;2025=18.10.43.13.3
CIS-18.10.43.13.4	7	Microsoft Defender Antivirus: Scan: Trigger a quick scan after X days without any scans	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Scan	DaysUntilAggressiveCatchupQuickScan	=	7		M	2022,2025	*=18.10.43.13.4
CIS-18.10.43.13.5	7	Microsoft Defender Antivirus: Scan: Turn on e-mail scanning	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Scan	DisableEmailScanning	=	0	1	M	*	2016=18.10.42.13.3;2019=18.10.42.13.3;2022=18.10.43.13.5;2025=18.10.43.13.5
CIS-18.10.43.16	7	Microsoft Defender Antivirus: Configure detection for potentially unwanted applications	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	PUAProtection	=	1	0	M	*	2016=18.10.42.16;2019=18.10.42.16;2022=18.10.43.16;2025=18.10.43.16
CIS-18.10.43.17	7	Microsoft Defender Antivirus: Control whether exclusions are visible to local users	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	HideExclusionsFromLocalUsers	=	1	0	M	2022,2025	*=18.10.43.17
CIS-18.10.51.1	7	OneDrive: Prevent the usage of OneDrive for file storage	reg	HKLM:\Software\Policies\Microsoft\Windows\OneDrive	DisableFileSyncNGSC	=	1	0	M	*	2016=18.10.50.1;2019=18.10.50.1;2022=18.10.51.1;2025=18.10.51.1
CIS-18.10.56.1	7	Push To Install: Turn off Push To Install service	reg	HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall	DisablePushToInstall	=	1		M	*	2016=18.10.55.1;2019=18.10.55.1;2022=18.10.56.1;2025=18.10.56.1
CIS-18.10.56.3.10.1	7	Remote Desktop Session Host: Session Time Limits: Set time limit for active but idle Remote Desktop Services sessions	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	MaxIdleTime	<=	900000	0	M	2019	*=18.10.56.3.10.1
CIS-18.10.57.2.2	7	Remote Desktop Connection Client: Do not allow passwords to be saved	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	DisablePasswordSaving	=	1	0	M	*	2016=18.10.56.2.2;2019=18.10.56.2.2;2022=18.10.57.2.2;2025=18.10.57.2.2
CIS-18.10.57.3.2.1	7	Remote Desktop Session Host: Connections: Restrict Remote Desktop Services users to a single Remote Desktop Services session	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fSingleSessionPerUser	=	1	1	M	*	2016=18.10.56.3.2.1;2019=18.10.56.3.2.1;2022=18.10.57.3.2.1;2025=18.10.57.3.2.1
CIS-18.10.57.3.3.1	7	Remote Desktop Session Host: Device and Resource Redirection: Allow UI Automation redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	EnableUiaRedirection	=	0		M	2022,2025	*=18.10.57.3.3.1
CIS-18.10.57.3.3.2	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow COM port redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableCcm	=	1	0	M	*	2016=18.10.56.3.3.1;2019=18.10.56.3.3.1;2022=18.10.57.3.3.2;2025=18.10.57.3.3.2
CIS-18.10.57.3.3.3	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow drive redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableCdm	=	1	0	M	*	2016=18.10.56.3.3.2;2019=18.10.56.3.3.2;2022=18.10.57.3.3.3;2025=18.10.57.3.3.3
CIS-18.10.57.3.3.4	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow location redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableLocationRedir	=	1		M	2022,2025	*=18.10.57.3.3.4
CIS-18.10.57.3.3.5	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow LPT port redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableLPT	=	1	0	M	*	2016=18.10.56.3.3.3;2019=18.10.56.3.3.3;2022=18.10.57.3.3.5;2025=18.10.57.3.3.5
CIS-18.10.57.3.3.6	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow supported Plug and Play device redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisablePNPRedir	=	1	0	M	*	2016=18.10.56.3.3.4;2019=18.10.56.3.3.4;2022=18.10.57.3.3.6;2025=18.10.57.3.3.6
CIS-18.10.57.3.3.7	7	Remote Desktop Session Host: Device and Resource Redirection: Do not allow WebAuthn redirection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableWebAuthn	=	1		M	2022,2025	*=18.10.57.3.3.7
CIS-18.10.57.3.3.8	7	Remote Desktop Session Host: Device and Resource Redirection: Restrict clipboard transfer from server to client	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	SCClipLevel	=	0		M	2025	*=18.10.57.3.3.8
CIS-18.10.57.3.9.1	7	Remote Desktop Session Host: Security: Always prompt for password upon connection	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fPromptForPassword	=	1	0	M	*	2016=18.10.56.3.9.1;2019=18.10.56.3.9.1;2022=18.10.57.3.9.1;2025=18.10.57.3.9.1
CIS-18.10.57.3.9.2	7	Remote Desktop Session Host: Security: Require secure RPC communication	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fEncryptRPCTraffic	=	1	0	M	*	2016=18.10.56.3.9.2;2019=18.10.56.3.9.2;2022=18.10.57.3.9.2;2025=18.10.57.3.9.2
CIS-18.10.57.3.9.3	7	Remote Desktop Session Host: Security: Require use of specific security layer for remote (RDP) connections	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	SecurityLayer	=	2	0	M	*	2016=18.10.56.3.9.3;2019=18.10.56.3.9.3;2022=18.10.57.3.9.3;2025=18.10.57.3.9.3
CIS-18.10.57.3.9.4	7	Remote Desktop Session Host: Security: Require user authentication for remote connections by using Network Level Authentication	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	UserAuthentication	=	1	0	M	*	2016=18.10.56.3.9.4;2019=18.10.56.3.9.4;2022=18.10.57.3.9.4;2025=18.10.57.3.9.4
CIS-18.10.57.3.9.5	7	Remote Desktop Session Host: Security: Set client connection encryption level	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	MinEncryptionLevel	=	3	0	M	*	2016=18.10.56.3.9.5;2019=18.10.56.3.9.5;2022=18.10.57.3.9.5;2025=18.10.57.3.9.5
CIS-18.10.57.3.10.1	7	Remote Desktop Session Host: Session Time Limits: Set time limit for active but idle Remote Desktop Services sessions	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	MaxIdleTime	<=!0	900000	0	M	2016,2022,2025	2016=18.10.56.3.10.1;2022=18.10.57.3.10.1;2025=18.10.57.3.10.1
CIS-18.10.57.3.10.2	7	Remote Desktop Session Host: Session Time Limits: Set time limit for disconnected sessions	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	MaxDisconnectionTime	=	60000	0	M	*	2016=18.10.56.3.10.2;2019=18.10.56.3.10.2;2022=18.10.57.3.10.2;2025=18.10.57.3.10.2
CIS-18.10.57.3.11.1	7	Remote Desktop Session Host: Temporary folders: Do not delete temp folders upon exit	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	DeleteTempDirsOnExit	=	1	1	M	*	2016=18.10.56.3.11.1;2019=18.10.56.3.11.1;2022=18.10.57.3.11.1;2025=18.10.57.3.11.1
CIS-18.10.57.3.11.2	7	Remote Desktop Session Host: Temporary folders: Do not use temporary folders per session	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	PerSessionTempDir	=	1	1	M	*	2016=18.10.56.3.11.2;2019=18.10.56.3.11.2;2022=18.10.57.3.11.2;2025=18.10.57.3.11.2
CIS-18.10.58.1	7	RSS Feeds: Prevent downloading of enclosures	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds	DisableEnclosureDownload	=	1	0	M	*	2016=18.10.57.1;2019=18.10.57.1;2022=18.10.58.1;2025=18.10.58.1
CIS-18.10.58.2	7	RSS Feeds: Turn on Basic feed authentication over HTTP	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds	AllowBasicAuthInClear	=	0	0	M	2022,2025	*=18.10.58.2
CIS-18.10.58.4	7	Search: Allow Cortana above lock screen	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search	AllowCortanaAboveLock	=	0	1	M	2019	*=18.10.58.4
CIS-18.10.59.2	7	Search: Allow Cloud Search	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search	AllowCloudSearch	=	0	1	M	*	2016=18.10.58.2;2019=18.10.58.2;2022=18.10.59.2;2025=18.10.59.2
CIS-18.10.59.3	7	Search: Allow indexing of encrypted files	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search	AllowIndexingEncryptedStoresOrItems	=	0	1	M	*	2016=18.10.58.3;2019=18.10.58.3;2022=18.10.59.3;2025=18.10.59.3
CIS-18.10.59.4	7	Search: Allow search highlights	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search	EnableDynamicContentInWSB	=	0		M	2016,2022,2025	2016=18.10.58.4;2022=18.10.59.4;2025=18.10.59.4
CIS-18.10.63.1	7	Software Protection Platform: Turn off KMS Client Online AVS Validation	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform	NoGenTicket	=	1	0	M	*	2016=18.10.62.1;2019=18.10.62.1;2022=18.10.63.1;2025=18.10.63.1
CIS-18.10.76.1.1.1	7	File Explorer: Configure Windows Defender SmartScreen	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	EnableSmartScreen	=	1	1	M	*	2016=18.10.75.2.1.1;2019=18.10.75.2.1.1;2022=18.10.76.1.1.1;2025=18.10.76.2.1.1
CIS-18.10.76.1.1.2	7	File Explorer: Configure Windows Defender SmartScreen to warn and prevent bypass	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	ShellSmartScreenLevel	=	Block	Warn	M	*	2016=18.10.75.2.1.2;2019=18.10.75.2.1.2;2022=18.10.76.1.1.2;2025=18.10.76.2.1.2
CIS-18.10.80.1	7	Windows Ink Workspace: Allow suggested apps in Windows Ink Workspace	reg	HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace	AllowSuggestedAppsInWindowsInkWorkspace	=	0	1	M	*	2016=18.10.79.1;2019=18.10.79.1;2022=18.10.80.1;2025=18.10.80.1
CIS-18.10.80.2	7	Windows Ink Workspace: Allow Windows Ink Workspace	reg	HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace	AllowWindowsInkWorkspace	<=	1	1	M	*	2016=18.10.79.2;2019=18.10.79.2;2022=18.10.80.2;2025=18.10.80.2
CIS-18.10.81.1	7	Windows Installer: Allow user control over installs	reg	HKLM:\Software\Policies\Microsoft\Windows\Installer	EnableUserControl	=	0	1	M	*	2016=18.10.80.1;2019=18.10.80.1;2022=18.10.81.1;2025=18.10.81.1
CIS-18.10.81.2	7	Windows Installer: Always install with elevated privileges	reg	HKLM:\Software\Policies\Microsoft\Windows\Installer	AlwaysInstallElevated	=	0	0	M	*	2016=18.10.80.2;2019=18.10.80.2;2022=18.10.81.2;2025=18.10.81.2
CIS-18.10.81.3	7	Windows Installer: Prevent Internet Explorer security prompt for Windows Installer scripts	reg	HKLM:\Software\Policies\Microsoft\Windows\Installer	SafeForScripting	=	0	1	M	*	2016=18.10.80.3;2019=18.10.80.3;2022=18.10.81.3;2025=18.10.81.3
CIS-18.10.82.1	7	Windows Logon Options: Configure the transmission of the user's password in the content of MPR notifications sent by winlogon	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System	EnableMPR	=	0		M	2022,2025	*=18.10.82.1
CIS-18.10.82.2	7	Windows Logon Options: Sign-in and lock last interactive user automatically after a restart	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	DisableAutomaticRestartSignOn	=	1	0	M	*	2016=18.10.81.1;2019=18.10.81.1;2022=18.10.82.2;2025=18.10.82.2
CIS-18.10.87.1	7	Windows PowerShell: Turn on PowerShell Script Block Logging	reg	HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging	EnableScriptBlockLogging	=	1	0	M	*	2016=18.10.86.1;2019=18.10.86.1;2022=18.10.87.1;2025=18.10.87.1
CIS-18.10.87.2	7	Windows PowerShell: Turn on PowerShell Transcription	reg	HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription	EnableTranscripting	=	1	0	M	*	2016=18.10.86.2;2019=18.10.86.2;2022=18.10.87.2;2025=18.10.87.2
CIS-18.10.89.1.1	7	WinRM Client: Allow Basic authentication	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client	AllowBasic	=	0	0	M	*	2016=18.10.88.1.1;2019=18.10.88.1.1;2022=18.10.89.1.1;2025=18.10.89.1.1
CIS-18.10.89.1.2	7	WinRM Client: Allow unencrypted traffic	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client	AllowUnencryptedTraffic	=	0	0	M	*	2016=18.10.88.1.2;2019=18.10.88.1.2;2022=18.10.89.1.2;2025=18.10.89.1.2
CIS-18.10.89.1.3	7	WinRM Client: Disallow Digest authentication	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client	AllowDigest	=	0	0	M	*	2016=18.10.88.1.3;2019=18.10.88.1.3;2022=18.10.89.1.3;2025=18.10.89.1.3
CIS-18.10.89.2.1	7	WinRM Service: Allow Basic authentication	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service	AllowBasic	=	0	0	M	*	2016=18.10.88.2.1;2019=18.10.88.2.1;2022=18.10.89.2.1;2025=18.10.89.2.1
CIS-18.10.89.2.2	7	WinRM Service: Allow remote server management through WinRM	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service	AllowAutoConfig	=	0	0	M	*	2016=18.10.88.2.2;2019=18.10.88.2.2;2022=18.10.89.2.2;2025=18.10.89.2.2
CIS-18.10.89.2.3	7	WinRM Service: Allow unencrypted traffic	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service	AllowUnencryptedTraffic	=	0	0	M	*	2016=18.10.88.2.3;2019=18.10.88.2.3;2022=18.10.89.2.3;2025=18.10.89.2.3
CIS-18.10.89.2.4	7	WinRM Service: Disallow WinRM from storing RunAs credentials	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service	DisableRunAs	=	1	0	M	*	2016=18.10.88.2.4;2019=18.10.88.2.4;2022=18.10.89.2.4;2025=18.10.89.2.4
CIS-18.10.90.1	7	Windows Remote Shell: Allow Remote Shell Access	reg	HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS	AllowRemoteShellAccess	=	0	1	M	*	2016=18.10.89.1;2019=18.10.89.1;2022=18.10.90.1;2025=18.10.90.1
CIS-18.10.92.2.1	7	App and browser protection: Prevent users from modifying settings	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection	DisallowExploitProtectionOverride	=	1		M	*	2016=18.10.91.2.1;2019=18.10.91.2.1;2022=18.10.92.2.1;2025=18.10.92.2.1
CIS-18.10.93.1.1	7	Windows Update: Legacy Policies: No auto-restart with logged on users for scheduled automatic updates installations	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au	NoAutoRebootWithLoggedOnUsers	=	0	0	M	*	2016=18.10.92.1.1;2019=18.10.92.1.1;2022=18.10.93.1.1;2025=18.10.93.1.1
CIS-18.10.93.2.1	7	Windows Update: Manage end user experience: Configure Automatic Updates	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au	NoAutoUpdate	=	0	0	M	*	2016=18.10.92.2.1;2019=18.10.92.2.1;2022=18.10.93.2.1;2025=18.10.93.2.1
CIS-18.10.93.2.2	7	Windows Update: Manage end user experience: Configure Automatic Updates: Scheduled install day	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\Au	ScheduledInstallDay	=	0		M	*	2016=18.10.92.2.2;2019=18.10.92.2.2;2022=18.10.93.2.2;2025=18.10.93.2.2
CIS-18.10.93.4.1.1	7	Windows Update: Manage updates offered from Windows Update: Manage preview builds (ManagePreviewBuilds)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	ManagePreviewBuilds	=	1		M	*	2016=18.10.92.4.1.1;2019=18.10.92.4.1.1;2022=18.10.93.4.1.1;2025=18.10.93.4.1.1
CIS-18.10.93.4.1.2	7	Windows Update: Manage updates offered from Windows Update: Manage preview builds (ManagePreviewBuildsPolicyValue)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	ManagePreviewBuildsPolicyValue	=	0		M	*	2016=18.10.92.4.1.2;2019=18.10.92.4.1.2;2022=18.10.93.4.1.2;2025=18.10.93.4.1.2
CIS-18.10.93.4.2.1	7	Windows Update: Manage updates offered from Windows Update: Select when Preview Builds and Feature Updates are received (DeferFeatureUpdates)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	DeferFeatureUpdates	=	1		M	*	2016=18.10.92.4.2.1;2019=18.10.92.4.2.1;2022=18.10.93.4.2.1;2025=18.10.93.4.2.1
CIS-18.10.93.4.2.2	7	Windows Update: Manage updates offered from Windows Update: Select when Preview Builds and Feature Updates are received (BranchReadinessLevel)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	BranchReadinessLevel	=	2		L	*	2016=18.10.92.4.2.2;2019=18.10.92.4.2.2;2022=18.10.93.4.2.2;2025=18.10.93.4.2.2
CIS-18.10.93.4.2.3	7	Windows Update: Manage updates offered from Windows Update: Select when Preview Builds and Feature Updates are received (DeferFeatureUpdatesPeriodInDays)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	DeferFeatureUpdatesPeriodInDays	>=	180		M	*	2016=18.10.92.4.2.3;2019=18.10.92.4.2.3;2022=18.10.93.4.2.3;2025=18.10.93.4.2.3
CIS-18.10.93.4.3.1	7	Windows Update: Manage updates offered from Windows Update: Select when Quality Updates are received (DeferQualityUpdates)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	DeferQualityUpdates	=	1		M	*	2016=18.10.92.4.3.1;2019=18.10.92.4.3.1;2022=18.10.93.4.3.1;2025=18.10.93.4.3.1
CIS-18.10.93.4.3.2	7	Windows Update: Manage updates offered from Windows Update: Select when Quality Updates are received (DeferQualityUpdatesPeriodInDays)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate	DeferQualityUpdatesPeriodInDays	=	0		M	*	2016=18.10.92.4.3.2;2019=18.10.92.4.3.2;2022=18.10.93.4.3.2;2025=18.10.93.4.3.2
'@


# DISA STIG - the automatable rules, version- and role-aware (MS vs DC).
$script:StigTable = @'
STIG-V-254269	WINDOWS FEATURES	Windows Server 2022 must not have the Fax Server role installed.	feature	Fax		=	Absent		M	*	2016=V-224850;2019=V-205678;2022=V-254269;2025=V-278015;legacy=WN22-00-000320
STIG-V-254270	WINDOWS FEATURES	Windows Server 2022 must not have the Microsoft FTP service installed unless required by the organization.	feature	Web-Ftp-Service		=	Absent		M	*	2016=V-224851;2019=V-205697;2022=V-254270;2025=V-278016;legacy=WN22-00-000330
STIG-V-254271	WINDOWS FEATURES	Windows Server 2022 must not have the Peer Name Resolution Protocol installed.	feature	PNRP		=	Absent		M	*	2016=V-224852;2019=V-205679;2022=V-254271;2025=V-278019;legacy=WN22-00-000340
STIG-V-254272	WINDOWS FEATURES	Windows Server 2022 must not have Simple TCP/IP Services installed.	feature	Simple-TCPIP		=	Absent		M	*	2016=V-224853;2019=V-205680;2022=V-254272;2025=V-278020;legacy=WN22-00-000350
STIG-V-254273	WINDOWS FEATURES	Windows Server 2022 must not have the Telnet Client installed.	feature	Telnet-Client		=	Absent		M	*	2016=V-224854;2019=V-205698;2022=V-254273;2025=V-278021;legacy=WN22-00-000360
STIG-V-254274	WINDOWS FEATURES	Windows Server 2022 must not have the TFTP Client installed.	feature	TFTP-Client		=	Absent		M	*	2016=V-224855;2019=V-205681;2022=V-254274;2025=V-278022;legacy=WN22-00-000370
STIG-V-254275	WINDOWS FEATURES	Windows Server 2022 must not the Server Message Block (SMB) v1 protocol installed.	feature	FS-SMB1		=	Absent		M	*	2016=V-224856;2019=V-205682;2022=V-254275;2025=V-278023;legacy=WN22-00-000380
STIG-V-254276	REGISTRY POLICY	Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters	SMB1	=	0		M	*	2016=V-224857;2019=V-205683;2022=V-254276;2025=V-278024;legacy=WN22-00-000390
STIG-V-254277	REGISTRY POLICY	Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10	Start	=	4		M	*	2016=V-224858;2019=V-205684;2022=V-254277;2025=V-278025;legacy=WN22-00-000400
STIG-V-254278	WINDOWS FEATURES	Windows Server 2022 must not have Windows PowerShell 2.0 installed.	feature	PowerShell-v2		=	Absent		M	*	2016=V-224859;2019=V-205685;2022=V-254278;2025=V-278026;legacy=WN22-00-000410
STIG-V-254285	ACCOUNT POLICIES	Windows Server 2022 account lockout duration must be configured to 15 minutes or greater.	accountpolicy	LockoutDuration		>=|0	15		M	*	2016=V-224866;2019=V-205795;2022=V-254285;2025=V-278033;legacy=WN22-AC-000010
STIG-V-254286	ACCOUNT POLICIES	Windows Server 2022 must have the number of allowed bad logon attempts configured to three or less.	accountpolicy	LockoutBadCount		<=!0	3		M	*	2016=V-224867;2019=V-205629;2022=V-254286;2025=V-278034;legacy=WN22-AC-000020
STIG-V-254287	ACCOUNT POLICIES	Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.	accountpolicy	ResetLockoutCount		>=	15		M	*	2016=V-224868;2019=V-205630;2022=V-254287;2025=V-278035;legacy=WN22-AC-000030
STIG-V-254288	ACCOUNT POLICIES	Windows Server 2022 password history must be configured to 24 passwords remembered.	accountpolicy	PasswordHistorySize		>=	24		M	*	2016=V-224869;2019=V-205660;2022=V-254288;2025=V-278036;legacy=WN22-AC-000040
STIG-V-254289	ACCOUNT POLICIES	Windows Server 2022 maximum password age must be configured to 60 days or less.	accountpolicy	MaximumPasswordAge		<=!0	60		M	*	2016=V-224870;2019=V-205659;2022=V-254289;2025=V-278037;legacy=WN22-AC-000050
STIG-V-254290	ACCOUNT POLICIES	Windows Server 2022 minimum password age must be configured to at least one day.	accountpolicy	MinimumPasswordAge		!=	0		M	*	2016=V-224871;2019=V-205656;2022=V-254290;2025=V-278038;legacy=WN22-AC-000060
STIG-V-254291	ACCOUNT POLICIES	Windows Server 2022 minimum password length must be configured to 14 characters.	accountpolicy	MinimumPasswordLength		>=	14		M	2016,2019,2022	2016=V-224872;2019=V-205662;2022=V-254291;legacy=WN22-AC-000070
STIG-V-254292	ACCOUNT POLICIES	Windows Server 2022 must have the built-in Windows password complexity policy enabled.	accountpolicy	PasswordComplexity		=	Enabled		M	*	2016=V-224873;2019=V-205652;2022=V-254292;2025=V-278039;legacy=WN22-AC-000080
STIG-V-254293	ACCOUNT POLICIES	Windows Server 2022 reversible password encryption must be disabled.	accountpolicy	ClearTextPassword		=	Disabled		H	*	2016=V-224874;2019=V-205653;2022=V-254293;2025=V-278040;legacy=WN22-AC-000090
STIG-V-254300	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Logon - Credential Validation successes.	auditsub	Credential Validation	Success	=	Success		M	*	2016=V-224881;2019=V-205832;2022=V-254300;2025=V-278047;legacy=WN22-AU-000070
STIG-V-254301	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Logon - Credential Validation failures.	auditsub	Credential Validation	Failure	=	Failure		M	*	2016=V-224882;2019=V-205833;2022=V-254301;2025=V-278048;legacy=WN22-AU-000080
STIG-V-254302	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Management - Other Account Management Events successes.	auditsub	Other Account Management Events	Success	=	Success		M	*	2016=V-224883;2019=V-205769;2022=V-254302;2025=V-278049;legacy=WN22-AU-000090
STIG-V-254303	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Management - Security Group Management successes.	auditsub	Security Group Management	Success	=	Success		M	*	2016=V-224884;2019=V-205625;2022=V-254303;2025=V-278050;legacy=WN22-AU-000100
STIG-V-254304	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Management - User Account Management successes.	auditsub	User Account Management	Success	=	Success		M	*	2016=V-224885;2019=V-205626;2022=V-254304;2025=V-278051;legacy=WN22-AU-000110
STIG-V-254305	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Management - User Account Management failures.	auditsub	User Account Management	Failure	=	Failure		M	*	2016=V-224886;2019=V-205627;2022=V-254305;2025=V-278052;legacy=WN22-AU-000120
STIG-V-254306	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Detailed Tracking - Plug and Play Events successes.	auditsub	Plug and Play Events	Success	=	Success		M	*	2016=V-224887;2019=V-205839;2022=V-254306;2025=V-278053;legacy=WN22-AU-000130
STIG-V-254307	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Detailed Tracking - Process Creation successes.	auditsub	Process Creation	Success	=	Success		M	*	2016=V-224888;2019=V-205770;2022=V-254307;2025=V-278054;legacy=WN22-AU-000140
STIG-V-254309	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Logon/Logoff - Account Lockout failures.	auditsub	Account Lockout	Failure	=	Failure		M	*	2016=V-224890;2019=V-205730;2022=V-254309;2025=V-278056;legacy=WN22-AU-000160
STIG-V-254310	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Logon/Logoff - Group Membership successes.	auditsub	Group Membership	Success	=	Success		M	*	2016=V-224891;2019=V-205834;2022=V-254310;2025=V-278057;legacy=WN22-AU-000170
STIG-V-254311	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit logoff successes.	auditsub	Logoff	Success	=	Success		M	*	2016=V-224892;2019=V-205838;2022=V-254311;2025=V-278058;legacy=WN22-AU-000180
STIG-V-254312	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit logon successes.	auditsub	Logon	Success	=	Success		M	*	2016=V-224893;2019=V-205634;2022=V-254312;2025=V-278059;legacy=WN22-AU-000190
STIG-V-254313	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit logon failures.	auditsub	Logon	Failure	=	Failure		M	*	2016=V-224894;2019=V-205635;2022=V-254313;2025=V-278060;legacy=WN22-AU-000200
STIG-V-254314	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Logon/Logoff - Special Logon successes.	auditsub	Special Logon	Success	=	Success		M	*	2016=V-224895;2019=V-205835;2022=V-254314;2025=V-278061;legacy=WN22-AU-000210
STIG-V-254315	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Object Access - Other Object Access Events successes.	auditsub	Other Object Access Events	Success	=	Success		M	*	2016=V-224896;2019=V-205836;2022=V-254315;2025=V-278062;legacy=WN22-AU-000220
STIG-V-254316	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Object Access - Other Object Access Events failures.	auditsub	Other Object Access Events	Failure	=	Failure		M	*	2016=V-224897;2019=V-205837;2022=V-254316;2025=V-278063;legacy=WN22-AU-000230
STIG-V-254317	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Object Access - Removable Storage successes.	auditsub	Removable Storage	Success	=	Success		M	*	2016=V-224898;2019=V-205840;2022=V-254317;2025=V-278064;legacy=WN22-AU-000240
STIG-V-254318	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Object Access - Removable Storage failures.	auditsub	Removable Storage	Failure	=	Failure		M	*	2016=V-224899;2019=V-205841;2022=V-254318;2025=V-278065;legacy=WN22-AU-000250
STIG-V-254319	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Policy Change - Audit Policy Change successes.	auditsub	Audit Policy Change	Success	=	Success		M	*	2016=V-224900;2019=V-205771;2022=V-254319;2025=V-278066;legacy=WN22-AU-000260
STIG-V-254320	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Policy Change - Audit Policy Change failures.	auditsub	Audit Policy Change	Failure	=	Failure		M	*	2016=V-224901;2019=V-205772;2022=V-254320;2025=V-278067;legacy=WN22-AU-000270
STIG-V-254321	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Policy Change - Authentication Policy Change successes.	auditsub	Authentication Policy Change	Success	=	Success		M	*	2016=V-224902;2019=V-205773;2022=V-254321;2025=V-278068;legacy=WN22-AU-000280
STIG-V-254322	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Policy Change - Authorization Policy Change successes.	auditsub	Authorization Policy Change	Success	=	Success		M	*	2016=V-224903;2019=V-205774;2022=V-254322;2025=V-278069;legacy=WN22-AU-000290
STIG-V-254323	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Privilege Use - Sensitive Privilege Use successes.	auditsub	Sensitive Privilege Use	Success	=	Success		M	*	2016=V-224904;2019=V-205775;2022=V-254323;2025=V-278070;legacy=WN22-AU-000300
STIG-V-254324	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Privilege Use - Sensitive Privilege Use failures.	auditsub	Sensitive Privilege Use	Failure	=	Failure		M	*	2016=V-224905;2019=V-205776;2022=V-254324;2025=V-278071;legacy=WN22-AU-000310
STIG-V-254325	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - IPsec Driver successes.	auditsub	IPsec Driver	Success	=	Success		M	*	2016=V-224906;2019=V-205777;2022=V-254325;2025=V-278072;legacy=WN22-AU-000320
STIG-V-254326	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - IPsec Driver failures.	auditsub	IPsec Driver	Failure	=	Failure		M	*	2016=V-224907;2019=V-205778;2022=V-254326;2025=V-278073;legacy=WN22-AU-000330
STIG-V-254327	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - Other System Events successes.	auditsub	Other System Events	Success	=	Success		M	*	2016=V-224908;2019=V-205779;2022=V-254327;2025=V-278074;legacy=WN22-AU-000340
STIG-V-254328	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - Other System Events failures.	auditsub	Other System Events	Failure	=	Failure		M	*	2016=V-224909;2019=V-205780;2022=V-254328;2025=V-278075;legacy=WN22-AU-000350
STIG-V-254329	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - Security State Change successes.	auditsub	Security State Change	Success	=	Success		M	*	2016=V-224910;2019=V-205781;2022=V-254329;2025=V-278076;legacy=WN22-AU-000360
STIG-V-254330	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - Security System Extension successes.	auditsub	Security System Extension	Success	=	Success		M	*	2016=V-224911;2019=V-205782;2022=V-254330;2025=V-278077;legacy=WN22-AU-000370
STIG-V-254331	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - System Integrity successes.	auditsub	System Integrity	Success	=	Success		M	*	2016=V-224912;2019=V-205783;2022=V-254331;2025=V-278078;legacy=WN22-AU-000380
STIG-V-254332	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit System - System Integrity failures.	auditsub	System Integrity	Failure	=	Failure		M	*	2016=V-224913;2019=V-205784;2022=V-254332;2025=V-278079;legacy=WN22-AU-000390
STIG-V-254333	REGISTRY POLICY	Windows Server 2022 must prevent the display of slide shows on the lock screen.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization	NoLockScreenSlideshow	=	1		M	*	2016=V-224914;2019=V-205686;2022=V-254333;2025=V-278080;legacy=WN22-CC-000010
STIG-V-254334	REGISTRY POLICY	Windows Server 2022 must have WDigest Authentication disabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest	UseLogonCredential	=	0		M	2016,2019,2022	2016=V-224915;2019=V-205687;2022=V-254334;legacy=WN22-CC-000020
STIG-V-254335	REGISTRY POLICY	Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters	DisableIPSourceRouting	=	2		L	*	2016=V-224916;2019=V-205858;2022=V-254335;2025=V-278082;legacy=WN22-CC-000030
STIG-V-254336	REGISTRY POLICY	Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters	DisableIPSourceRouting	=	2		L	*	2016=V-224917;2019=V-205859;2022=V-254336;2025=V-278083;legacy=WN22-CC-000040
STIG-V-254337	REGISTRY POLICY	Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters	EnableICMPRedirect	=	0		L	*	2016=V-224918;2019=V-205860;2022=V-254337;2025=V-278084;legacy=WN22-CC-000050
STIG-V-254338	REGISTRY POLICY	Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters	NoNameReleaseOnDemand	=	1		L	2016,2019,2022	2016=V-224919;2019=V-205819;2022=V-254338;legacy=WN22-CC-000060
STIG-V-254339	REGISTRY POLICY	Windows Server 2022 insecure logons to an SMB server must be disabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation	AllowInsecureGuestAuth	=	0		M	*	2016=V-224920;2019=V-205861;2022=V-254339;2025=V-278086;legacy=WN22-CC-000070
STIG-V-224921	REGISTRY POLICY	Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\NETLOGON	=	RequireMutualAuthentication=1,RequireIntegrity=1		M	2016	2016=V-224921;legacy=WN16-CC-000090
STIG-V-224921#2	REGISTRY POLICY	Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\SYSVOL	=	RequireMutualAuthentication=1,RequireIntegrity=1		M	2016	2016=V-224921;legacy=WN16-CC-000090
STIG-V-254341	REGISTRY POLICY	Windows Server 2022 command line data must be included in process creation events.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit	ProcessCreationIncludeCmdLine_Enabled	=	1		M	*	2016=V-224922;2019=V-205638;2022=V-254341;2025=V-278088;legacy=WN22-CC-000090
STIG-V-254343	REGISTRY POLICY	Windows Server 2022 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	EnableVirtualizationBasedSecurity	=	1		M	*	2016=V-224923;2019=V-205864;2022=V-254343;2025=V-278090;legacy=WN22-CC-000110
STIG-V-254343#2	REGISTRY POLICY	Windows Server 2022 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	RequirePlatformSecurityFeatures	in	1,3		M	*	2016=V-224923;2019=V-205864;2022=V-254343;2025=V-278090;legacy=WN22-CC-000110
STIG-V-254344	REGISTRY POLICY	Windows Server 2022 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.	reg	HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch	DriverLoadPolicy	in|absent	1,3,8		M	*	2016=V-224924;2019=V-205865;2022=V-254344;2025=V-278091;legacy=WN22-CC-000130
STIG-V-254345	REGISTRY POLICY	Windows Server 2022 group policy objects must be reprocessed even if they have not changed.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}	NoGPOListChanges	=	0		M	*	2016=V-224925;2019=V-205866;2022=V-254345;2025=V-278092;legacy=WN22-CC-000140
STIG-V-254346	REGISTRY POLICY	Windows Server 2022 downloading print driver packages over HTTP must be turned off.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers	DisableWebPnPDownload	=	1		M	*	2016=V-224926;2019=V-205688;2022=V-254346;2025=V-278093;legacy=WN22-CC-000150
STIG-V-254347	REGISTRY POLICY	Windows Server 2022 printing over HTTP must be turned off.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers	DisableHTTPPrinting	=	1		M	*	2016=V-224927;2019=V-205689;2022=V-254347;2025=V-278094;legacy=WN22-CC-000160
STIG-V-254348	REGISTRY POLICY	Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	DontDisplayNetworkSelectionUI	=	1		M	*	2016=V-224928;2019=V-205690;2022=V-254348;2025=V-278095;legacy=WN22-CC-000170
STIG-V-254349	REGISTRY POLICY	Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery).	reg	HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51	DCSettingIndex	=	1		M	*	2016=V-224929;2019=V-205867;2022=V-254349;2025=V-278096;legacy=WN22-CC-000180
STIG-V-254350	REGISTRY POLICY	Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in).	reg	HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51	ACSettingIndex	=	1		M	*	2016=V-224930;2019=V-205868;2022=V-254350;2025=V-278097;legacy=WN22-CC-000190
STIG-V-254351	REGISTRY POLICY	Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat	DisableInventory	=	1		L	*	2016=V-224931;2019=V-205691;2022=V-254351;2025=V-278098;legacy=WN22-CC-000200
STIG-V-254352	REGISTRY POLICY	Windows Server 2022 Autoplay must be turned off for nonvolume devices.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoAutoplayfornonVolume	=	1		H	*	2016=V-224932;2019=V-205804;2022=V-254352;2025=V-278099;legacy=WN22-CC-000210
STIG-V-254353	REGISTRY POLICY	Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoAutorun	=	1		H	*	2016=V-224933;2019=V-205805;2022=V-254353;2025=V-278100;legacy=WN22-CC-000220
STIG-V-254354	REGISTRY POLICY	Windows Server 2022 AutoPlay must be disabled for all drives.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer	NoDriveTypeAutoRun	=	255		H	2016,2019,2022	2016=V-224934;2019=V-205806;2022=V-254354;legacy=WN22-CC-000230
STIG-V-254355	REGISTRY POLICY	Windows Server 2022 administrator accounts must not be enumerated during elevation.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI	EnumerateAdministrators	=	0		M	*	2016=V-224935;2019=V-205714;2022=V-254355;2025=V-278102;legacy=WN22-CC-000240
STIG-V-205869	REGISTRY POLICY	Windows Telemetry must be configured to Security or Basic.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection	AllowTelemetry	in	0,1		M	2016,2019	2016=V-224936;2019=V-205869;legacy=WN16-CC-000290
STIG-V-254358	REGISTRY POLICY	Windows Server 2022 Application event log size must be configured to 32768 KB or greater.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application	MaxSize	>=	32768		M	*	2016=V-224937;2019=V-205796;2022=V-254358;2025=V-278105;legacy=WN22-CC-000270
STIG-V-278106	REGISTRY POLICY	The Security event log size must be configured to 196608 KB or greater.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security	MaxSize	>=	196608		M	2016,2025	2016=V-224938;2025=V-278106;legacy=WN16-CC-000310
STIG-V-254360	REGISTRY POLICY	Windows Server 2022 System event log size must be configured to 32768 KB or greater.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System	MaxSize	>=	32768		M	*	2016=V-224939;2019=V-205798;2022=V-254360;2025=V-278107;legacy=WN22-CC-000290
STIG-V-254361	REGISTRY POLICY	Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	EnableSmartScreen	=	1		M	*	2016=V-224940;2019=V-205692;2022=V-254361;2025=V-278108;legacy=WN22-CC-000300
STIG-V-278109	REGISTRY POLICY	Explorer Data Execution Prevention must be enabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoDataExecutionPrevention	in|absent	0		M	2016,2025	2016=V-224941;2025=V-278109;legacy=WN16-CC-000340
STIG-V-278110	REGISTRY POLICY	Turning off File Explorer heap termination on corruption must be disabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoHeapTerminationOnCorruption	in|absent	0		L	2016,2025	2016=V-224942;2025=V-278110;legacy=WN16-CC-000350
STIG-V-278111	REGISTRY POLICY	File Explorer shell protocol must run in protected mode.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	PreXPSP2ShellProtocolBehavior	in|absent	0		M	2016,2025	2016=V-224943;2025=V-278111;legacy=WN16-CC-000360
STIG-V-254365	REGISTRY POLICY	Windows Server 2022 must not save passwords in the Remote Desktop Client.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	DisablePasswordSaving	=	1		M	*	2016=V-224944;2019=V-205808;2022=V-254365;2025=V-278112;legacy=WN22-CC-000340
STIG-V-254366	REGISTRY POLICY	Windows Server 2022 Remote Desktop Services must prevent drive redirection.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fDisableCdm	=	1		M	*	2016=V-224945;2019=V-205722;2022=V-254366;2025=V-278113;legacy=WN22-CC-000350
STIG-V-254367	REGISTRY POLICY	Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fPromptForPassword	=	1		M	*	2016=V-224946;2019=V-205809;2022=V-254367;2025=V-278114;legacy=WN22-CC-000360
STIG-V-254368	REGISTRY POLICY	Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	fEncryptRPCTraffic	=	1		M	*	2016=V-224947;2019=V-205636;2022=V-254368;2025=V-278115;legacy=WN22-CC-000370
STIG-V-254369	REGISTRY POLICY	Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services	MinEncryptionLevel	=	3		M	*	2016=V-224948;2019=V-205637;2022=V-254369;2025=V-278116;legacy=WN22-CC-000380
STIG-V-254370	REGISTRY POLICY	Windows Server 2022 must prevent attachments from being downloaded from RSS feeds.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds	DisableEnclosureDownload	=	1		M	*	2016=V-224949;2019=V-205873;2022=V-254370;2025=V-278117;legacy=WN22-CC-000390
STIG-V-278118	REGISTRY POLICY	Basic authentication for RSS feeds over HTTP must not be used.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds	AllowBasicAuthInClear	in|absent	0		M	2016,2025	2016=V-224951;2025=V-278118;legacy=WN16-CC-000430
STIG-V-254372	REGISTRY POLICY	Windows Server 2022 must prevent Indexing of encrypted files.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search	AllowIndexingEncryptedStoresOrItems	=	0		M	*	2016=V-224952;2019=V-205694;2022=V-254372;2025=V-278119;legacy=WN22-CC-000410
STIG-V-254373	REGISTRY POLICY	Windows Server 2022 must prevent users from changing installation options.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer	EnableUserControl	=	0		M	*	2016=V-224953;2019=V-205801;2022=V-254373;2025=V-278120;legacy=WN22-CC-000420
STIG-V-254374	REGISTRY POLICY	Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer	AlwaysInstallElevated	=	0		H	*	2016=V-224954;2019=V-205802;2022=V-254374;2025=V-278121;legacy=WN22-CC-000430
STIG-V-278122	REGISTRY POLICY	Users must be notified if a web-based program attempts to install software.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer	SafeForScripting	in|absent	0		M	2016,2025	2016=V-224955;2025=V-278122;legacy=WN16-CC-000470
STIG-V-254376	REGISTRY POLICY	Windows Server 2022 must disable automatically signing in the last interactive user after a system-initiated restart.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	DisableAutomaticRestartSignOn	=	1		M	*	2016=V-224956;2019=V-205925;2022=V-254376;2025=V-278123;legacy=WN22-CC-000450
STIG-V-254377	REGISTRY POLICY	Windows Server 2022 PowerShell script block logging must be enabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging	EnableScriptBlockLogging	=	1		M	*	2016=V-224957;2019=V-205639;2022=V-254377;2025=V-278124;legacy=WN22-CC-000460
STIG-V-254378	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client	AllowBasic	=	0		H	*	2016=V-224958;2019=V-205711;2022=V-254378;2025=V-278125;legacy=WN22-CC-000470
STIG-V-254379	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client	AllowUnencryptedTraffic	=	0		M	*	2016=V-224959;2019=V-205816;2022=V-254379;2025=V-278126;legacy=WN22-CC-000480
STIG-V-254380	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client	AllowDigest	=	0		M	*	2016=V-224960;2019=V-205712;2022=V-254380;2025=V-278127;legacy=WN22-CC-000490
STIG-V-254381	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service	AllowBasic	=	0		H	*	2016=V-224961;2019=V-205713;2022=V-254381;2025=V-278128;legacy=WN22-CC-000500
STIG-V-254382	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service	AllowUnencryptedTraffic	=	0		M	*	2016=V-224962;2019=V-205817;2022=V-254382;2025=V-278129;legacy=WN22-CC-000510
STIG-V-254383	REGISTRY POLICY	Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service	DisableRunAs	=	1		M	*	2016=V-224963;2019=V-205810;2022=V-254383;2025=V-278130;legacy=WN22-CC-000520
STIG-V-254407	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit Account Management - Computer Account Management successes.	auditsub	Computer Account Management	Success	=	Success		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224986;2019=V-205628;2022=V-254407;2025=V-278154;legacy=WN22-DC-000230
STIG-V-254408	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit DS Access - Directory Service Access successes.	auditsub	Directory Service Access	Success	=	Success		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224987;2019=V-205791;2022=V-254408;2025=V-278155;legacy=WN22-DC-000240
STIG-V-254409	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit DS Access - Directory Service Access failures.	auditsub	Directory Service Access	Failure	=	Failure		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224988;2019=V-205792;2022=V-254409;2025=V-278156;legacy=WN22-DC-000250
STIG-V-254410	ADVANCED AUDIT POLICY	Windows Server 2022 must be configured to audit DS Access - Directory Service Changes successes.	auditsub	Directory Service Changes	Success	=	Success		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224989;2019=V-205793;2022=V-254410;2025=V-278157;legacy=WN22-DC-000260
STIG-V-254416	REGISTRY POLICY	Windows Server 2022 domain controllers must require LDAP access signing.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters	LDAPServerIntegrity	=	2		M	2016:DC,2022:DC,2025:DC	2016=V-224995;2022=V-254416;2025=V-278163;legacy=WN22-DC-000320
STIG-V-254417	REGISTRY POLICY	Windows Server 2022 domain controllers must be configured to allow reset of machine account passwords.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	RefusePasswordChange	=	0		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224996;2019=V-205876;2022=V-254417;2025=V-278164;legacy=WN22-DC-000330
STIG-V-254419	USER RIGHTS ASSIGNMENT	Windows Server 2022 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers.	userright	SeMachineAccountPrivilege		=	Administrators		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224998;2019=V-205744;2022=V-254419;2025=V-278166;legacy=WN22-DC-000350
STIG-V-254420	USER RIGHTS ASSIGNMENT	Windows Server 2022 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers.	userright	SeRemoteInteractiveLogonRight		=	Administrators		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224999;2019=V-205666;2022=V-254420;2025=V-278167;legacy=WN22-DC-000360
STIG-V-254421	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.	userright	SeDenyNetworkLogonRight		=	Guests		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225000;2019=V-205667;2022=V-254421;2025=V-278168;legacy=WN22-DC-000370
STIG-V-254422	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.	userright	SeDenyBatchLogonRight		=	Guests		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225001;2019=V-205668;2022=V-254422;2025=V-278169;legacy=WN22-DC-000380
STIG-V-254423	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.	userright	SeDenyServiceLogonRight		=			M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225002;2019=V-205669;2022=V-254423;2025=V-278170;legacy=WN22-DC-000390
STIG-V-254424	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.	userright	SeDenyInteractiveLogonRight		=	Guests		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225003;2019=V-205670;2022=V-254424;2025=V-278171;legacy=WN22-DC-000400
STIG-V-254425	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.	userright	SeDenyRemoteInteractiveLogonRight		=	Guests		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225004;2019=V-205732;2022=V-254425;2025=V-278174;legacy=WN22-DC-000410
STIG-V-254426	USER RIGHTS ASSIGNMENT	Windows Server 2022 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.	userright	SeEnableDelegationPrivilege		=	Administrators		M	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-225005;2019=V-205745;2022=V-254426;2025=V-278175;legacy=WN22-DC-000420
STIG-V-254429	REGISTRY POLICY	Windows Server 2022 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LocalAccountTokenFilterPolicy	=	0		M	2016:MS,2019:MS,2022:MS	2016=V-225008;2019=V-205715;2022=V-254429;legacy=WN22-MS-000020
STIG-V-254430	REGISTRY POLICY	Windows Server 2022 local users on domain-joined member servers must not be enumerated.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\System	EnumerateLocalUsers	=	0		M	2016:MS,2019:MS,2022:MS,2025:MS	2016=V-225009;2019=V-205696;2022=V-254430;2025=V-278179;legacy=WN22-MS-000030
STIG-V-254431	REGISTRY POLICY	Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc	RestrictRemoteClients	=	1		M	2016:MS,2019:MS,2022:MS	2016=V-225010;2019=V-205814;2022=V-254431;legacy=WN22-MS-000040
STIG-V-254432	REGISTRY POLICY	Windows Server 2022 must limit the caching of logon credentials to four or less on domain-joined member servers.	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon	CachedLogonsCount	<=	4		M	2016:MS,2019:MS,2022:MS	2016=V-225011;2019=V-205906;2022=V-254432;legacy=WN22-MS-000050
STIG-V-254441	REGISTRY POLICY	Windows Server 2022 must be running Credential Guard on domain-joined member servers.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	LsaCfgFlags	=	1		H	2016:MS,2019:MS,2022:MS,2025:MS	2016=V-225012;2019=V-205907;2022=V-254441;2025=V-278190;legacy=WN22-MS-000140
STIG-V-254433	REGISTRY POLICY	Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	RestrictRemoteSAM	=	O:BAG:BAD:(A;;RC;;;BA)		M	2016:MS,2019:MS,2022:MS,2025:MS	2016=V-225013;2019=V-205747;2022=V-254433;2025=V-278182;legacy=WN22-MS-000060
STIG-V-254434	USER RIGHTS ASSIGNMENT	Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone or nondomain-joined systems.	userright	SeNetworkLogonRight		=	Administrators,Authenticated Users		M	2016:MS,2019:MS,2022:MS	2016=V-225014;2019=V-205671;2022=V-254434;legacy=WN22-MS-000070
STIG-V-254435	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems.	userright	SeDenyNetworkLogonRight		in	Enterprise Admins,Domain Admins,(Local account and member of Administrators group,Local account),Guests		M	2016:MS,2019:MS,2022:MS	2016=V-225015;2019=V-205672;2022=V-254435;legacy=WN22-MS-000080
STIG-V-254436	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.	userright	SeDenyBatchLogonRight		=	Enterprise Admins,Domain Admins,Guests		M	2016:MS,2019:MS,2022:MS	2016=V-225016;2019=V-205673;2022=V-254436;legacy=WN22-MS-000090
STIG-V-254437	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.	userright	SeDenyServiceLogonRight		=	Enterprise Admins,Domain Admins		M	2016:MS,2019:MS,2022:MS	2016=V-225017;2019=V-205674;2022=V-254437;legacy=WN22-MS-000100
STIG-V-254438	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.	userright	SeDenyInteractiveLogonRight		=	Enterprise Admins,Domain Admins,Guests		M	2016:MS,2019:MS,2022:MS	2016=V-225018;2019=V-205675;2022=V-254438;legacy=WN22-MS-000110
STIG-V-254439	USER RIGHTS ASSIGNMENT	Windows Server 2022 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems.	userright	SeDenyRemoteInteractiveLogonRight		=	Enterprise Admins,Domain Admins,Local account,Guests		M	2016:MS,2019:MS,2022:MS	2016=V-225019;2019=V-205733;2022=V-254439;legacy=WN22-MS-000120
STIG-V-254440	USER RIGHTS ASSIGNMENT	Windows Server 2022 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone or nondomain-joined systems.	userright	SeEnableDelegationPrivilege		=			M	2016:MS,2019:MS,2022:MS,2025:MS	2016=V-225020;2019=V-205748;2022=V-254440;2025=V-278189;legacy=WN22-MS-000130
STIG-V-254445	SECURITY OPTIONS	Windows Server 2022 must have the built-in guest account disabled.	secopt	Accounts: Guest account status		=	Disabled		M	*	2016=V-225024;2019=V-205709;2022=V-254445;2025=V-278195;legacy=WN22-SO-000010
STIG-V-254446	REGISTRY POLICY	Windows Server 2022 must prevent local accounts with blank passwords from being used from the network.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	LimitBlankPasswordUse	=	1		H	*	2016=V-225025;2019=V-205908;2022=V-254446;2025=V-278196;legacy=WN22-SO-000020
STIG-V-254447	SECURITY OPTIONS	Windows Server 2022 built-in administrator account must be renamed.	secopt	Accounts: Rename administrator account		!=	Administrator		M	*	2016=V-225026;2019=V-205909;2022=V-254447;2025=V-278197;legacy=WN22-SO-000030
STIG-V-254448	SECURITY OPTIONS	Windows Server 2022 built-in guest account must be renamed.	secopt	Accounts: Rename guest account		!=	Guest		M	*	2016=V-225027;2019=V-205910;2022=V-254448;2025=V-278198;legacy=WN22-SO-000040
STIG-V-254449	REGISTRY POLICY	Windows Server 2022 must force audit policy subcategory settings to override audit policy category settings.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	SCENoApplyLegacyAuditPolicy	=	1		M	*	2016=V-225028;2019=V-205644;2022=V-254449;2025=V-278199;legacy=WN22-SO-000050
STIG-V-254450	REGISTRY POLICY	Windows Server 2022 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	RequireSignOrSeal	=	1		M	*	2016=V-225029;2019=V-205821;2022=V-254450;2025=V-278200;legacy=WN22-SO-000060
STIG-V-254451	REGISTRY POLICY	Windows Server 2022 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	SealSecureChannel	=	1		M	*	2016=V-225030;2019=V-205822;2022=V-254451;2025=V-278201;legacy=WN22-SO-000070
STIG-V-254452	REGISTRY POLICY	Windows Server 2022 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	SignSecureChannel	=	1		M	*	2016=V-225031;2019=V-205823;2022=V-254452;2025=V-278202;legacy=WN22-SO-000080
STIG-V-254453	REGISTRY POLICY	Windows Server 2022 computer account password must not be prevented from being reset.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	DisablePasswordChange	=	0		M	*	2016=V-225032;2019=V-205815;2022=V-254453;2025=V-278203;legacy=WN22-SO-000090
STIG-V-254454	REGISTRY POLICY	Windows Server 2022 maximum age for machine account passwords must be configured to 30 days or less.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	MaximumPasswordAge	<=!0	30		M	*	2016=V-225033;2019=V-205911;2022=V-254454;2025=V-278204;legacy=WN22-SO-000100
STIG-V-254455	REGISTRY POLICY	Windows Server 2022 must be configured to require a strong session key.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters	RequireStrongKey	=	1		M	*	2016=V-225034;2019=V-205824;2022=V-254455;2025=V-278205;legacy=WN22-SO-000110
STIG-V-254456	REGISTRY POLICY	Windows Server 2022 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	InactivityTimeoutSecs	<=!0	900		M	*	2016=V-225035;2019=V-205633;2022=V-254456;2025=V-278206;legacy=WN22-SO-000120
STIG-V-254458	REGISTRY POLICY	Windows Server 2022 title for legal banner dialog box must be configured with the appropriate text.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LegalNoticeCaption	in	DoD Notice and Consent Banner,US Department of Defense Warning Statement		L	2016,2019,2022	2016=V-225037;2019=V-205632;2022=V-254458;legacy=WN22-SO-000140
STIG-V-254459	REGISTRY POLICY	Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation.	reg	HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon	scremoveoption	in	1,2		M	*	2016=V-225038;2019=V-205912;2022=V-254459;2025=V-278209;legacy=WN22-SO-000150
STIG-V-254460	REGISTRY POLICY	Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters	RequireSecuritySignature	=	1		M	*	2016=V-225039;2019=V-205825;2022=V-254460;2025=V-278210;legacy=WN22-SO-000160
STIG-V-254461	REGISTRY POLICY	Windows Server 2022 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters	EnableSecuritySignature	=	1		M	*	2016=V-225040;2019=V-205826;2022=V-254461;2025=V-278211;legacy=WN22-SO-000170
STIG-V-254462	REGISTRY POLICY	Windows Server 2022 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters	EnablePlainTextPassword	=	0		M	2016,2019,2022	2016=V-225041;2019=V-205655;2022=V-254462;legacy=WN22-SO-000180
STIG-V-254463	REGISTRY POLICY	Windows Server 2022 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters	RequireSecuritySignature	=	1		M	*	2016=V-225042;2019=V-205827;2022=V-254463;2025=V-278213;legacy=WN22-SO-000190
STIG-V-254464	REGISTRY POLICY	Windows Server 2022 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters	EnableSecuritySignature	=	1		M	*	2016=V-225043;2019=V-205828;2022=V-254464;2025=V-278214;legacy=WN22-SO-000200
STIG-V-254465	SECURITY OPTIONS	Windows Server 2022 must not allow anonymous SID/Name translation.	secopt	Network access: Allow anonymous SID/Name translation		=	Disabled		H	*	2016=V-225044;2019=V-205913;2022=V-254465;2025=V-278215;legacy=WN22-SO-000210
STIG-V-254466	REGISTRY POLICY	Windows Server 2022 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	RestrictAnonymousSAM	=	1		H	*	2016=V-225045;2019=V-205914;2022=V-254466;2025=V-278216;legacy=WN22-SO-000220
STIG-V-254467	REGISTRY POLICY	Windows Server 2022 must not allow anonymous enumeration of shares.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	RestrictAnonymous	=	1		H	*	2016=V-225046;2019=V-205724;2022=V-254467;2025=V-278217;legacy=WN22-SO-000230
STIG-V-254468	REGISTRY POLICY	Windows Server 2022 must be configured to prevent anonymous users from having the same permissions as the Everyone group.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	EveryoneIncludesAnonymous	=	0		M	*	2016=V-225047;2019=V-205915;2022=V-254468;2025=V-278218;legacy=WN22-SO-000240
STIG-V-254469	REGISTRY POLICY	Windows Server 2022 must restrict anonymous access to Named Pipes and Shares.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters	RestrictNullSessAccess	=	1		H	*	2016=V-225048;2019=V-205725;2022=V-254469;2025=V-278219;legacy=WN22-SO-000250
STIG-V-254470	REGISTRY POLICY	Windows Server 2022 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\LSA	UseMachineId	=	1		M	*	2016=V-225049;2019=V-205916;2022=V-254470;2025=V-278220;legacy=WN22-SO-000260
STIG-V-254471	REGISTRY POLICY	Windows Server 2022 must prevent NTLM from falling back to a Null session.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0	allownullsessionfallback	=	0		M	*	2016=V-225050;2019=V-205917;2022=V-254471;2025=V-278221;legacy=WN22-SO-000270
STIG-V-254472	REGISTRY POLICY	Windows Server 2022 must prevent PKU2U authentication using online identities.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u	AllowOnlineID	=	0		M	*	2016=V-225051;2019=V-205918;2022=V-254472;2025=V-278222;legacy=WN22-SO-000280
STIG-V-254473	REGISTRY POLICY	Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	SupportedEncryptionTypes	=	2147483640		M	*	2016=V-225052;2019=V-205708;2022=V-254473;2025=V-278223;legacy=WN22-SO-000290
STIG-V-254474	REGISTRY POLICY	Windows Server 2022 must be configured to prevent the storage of the LAN Manager hash of passwords.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	NoLMHash	=	1		H	2016,2019,2022	2016=V-225053;2019=V-205654;2022=V-254474;legacy=WN22-SO-000300
STIG-V-254475	REGISTRY POLICY	Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa	LmCompatibilityLevel	=	5		H	*	2016=V-225054;2019=V-205919;2022=V-254475;2025=V-278225;legacy=WN22-SO-000310
STIG-V-254476	REGISTRY POLICY	Windows Server 2022 must be configured to at least negotiate signing for LDAP client signing.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\LDAP	LDAPClientIntegrity	=	1		M	*	2016=V-225055;2019=V-205920;2022=V-254476;2025=V-278226;legacy=WN22-SO-000320
STIG-V-254477	REGISTRY POLICY	Windows Server 2022 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0	NTLMMinClientSec	=	537395200		M	*	2016=V-225056;2019=V-205921;2022=V-254477;2025=V-278227;legacy=WN22-SO-000330
STIG-V-254478	REGISTRY POLICY	Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0	NTLMMinServerSec	=	537395200		M	*	2016=V-225057;2019=V-205922;2022=V-254478;2025=V-278228;legacy=WN22-SO-000340
STIG-V-254479	REGISTRY POLICY	Windows Server 2022 users must be required to enter a password to access private keys stored on the computer.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Cryptography	ForceKeyProtection	=	2		M	*	2016=V-225058;2019=V-205651;2022=V-254479;2025=V-278229;legacy=WN22-SO-000350
STIG-V-254480	REGISTRY POLICY	Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy	Enabled	=	1		M	*	2016=V-225059;2019=V-205842;2022=V-254480;2025=V-278230;legacy=WN22-SO-000360
STIG-V-254481	REGISTRY POLICY	Windows Server 2022 default permissions of global system objects must be strengthened.	reg	HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager	ProtectionMode	=	1		L	*	2016=V-225060;2019=V-205923;2022=V-254481;2025=V-278231;legacy=WN22-SO-000370
STIG-V-254482	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	FilterAdministratorToken	=	1		M	*	2016=V-225061;2019=V-205811;2022=V-254482;2025=V-278232;legacy=WN22-SO-000380
STIG-V-254483	REGISTRY POLICY	Windows Server 2022 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableUIADesktopToggle	=	0		M	*	2016=V-225062;2019=V-205716;2022=V-254483;2025=V-278233;legacy=WN22-SO-000390
STIG-V-254484	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	ConsentPromptBehaviorAdmin	in	1,2		M	2016,2019,2022	2016=V-225063;2019=V-205717;2022=V-254484;legacy=WN22-SO-000400
STIG-V-254485	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	ConsentPromptBehaviorUser	=	0		M	*	2016=V-225064;2019=V-205812;2022=V-254485;2025=V-278235;legacy=WN22-SO-000410
STIG-V-254486	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must be configured to detect application installations and prompt for elevation.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableInstallerDetection	=	1		M	*	2016=V-225065;2019=V-205718;2022=V-254486;2025=V-278236;legacy=WN22-SO-000420
STIG-V-254487	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableSecureUIAPaths	=	1		M	*	2016=V-225066;2019=V-205719;2022=V-254487;2025=V-278237;legacy=WN22-SO-000430
STIG-V-254488	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableLUA	=	1		M	*	2016=V-225067;2019=V-205813;2022=V-254488;2025=V-278238;legacy=WN22-SO-000440
STIG-V-254489	REGISTRY POLICY	Windows Server 2022 User Account Control (UAC) must virtualize file and registry write failures to per-user locations.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	EnableVirtualization	=	1		M	*	2016=V-225068;2019=V-205720;2022=V-254489;2025=V-278239;legacy=WN22-SO-000450
STIG-V-278240	REGISTRY POLICY	Zone information must be preserved when saving attachments.	reguser	SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments	SaveZoneInformation	in|absent	2		M	2016,2025	2016=V-225069;2025=V-278240;legacy=WN16-UC-000030
STIG-V-254491	USER RIGHTS ASSIGNMENT	Windows Server 2022 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.	userright	SeTrustedCredManAccessPrivilege		=			M	*	2016=V-225070;2019=V-205749;2022=V-254491;2025=V-278241;legacy=WN22-UR-000010
STIG-V-254492	USER RIGHTS ASSIGNMENT	Windows Server 2022 Act as part of the operating system user right must not be assigned to any groups or accounts.	userright	SeTcbPrivilege		=			H	*	2016=V-225071;2019=V-205750;2022=V-254492;2025=V-278242;legacy=WN22-UR-000020
STIG-V-254493	USER RIGHTS ASSIGNMENT	Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group.	userright	SeInteractiveLogonRight		=	Administrators		M	*	2016=V-225072;2019=V-205676;2022=V-254493;2025=V-278243;legacy=WN22-UR-000030
STIG-V-254494	USER RIGHTS ASSIGNMENT	Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group.	userright	SeBackupPrivilege		=	Administrators		M	*	2016=V-225073;2019=V-205751;2022=V-254494;2025=V-278244;legacy=WN22-UR-000040
STIG-V-254495	USER RIGHTS ASSIGNMENT	Windows Server 2022 create a pagefile user right must only be assigned to the Administrators group.	userright	SeCreatePagefilePrivilege		=	Administrators		M	*	2016=V-225074;2019=V-205752;2022=V-254495;2025=V-278245;legacy=WN22-UR-000050
STIG-V-254497	USER RIGHTS ASSIGNMENT	Windows Server 2022 create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.	userright	SeCreateGlobalPrivilege		=	Administrators,Service,Local Service,Network Service		M	2016,2019,2022	2016=V-225076;2019=V-205754;2022=V-254497;legacy=WN22-UR-000070
STIG-V-254498	USER RIGHTS ASSIGNMENT	Windows Server 2022 create permanent shared objects user right must not be assigned to any groups or accounts.	userright	SeCreatePermanentPrivilege		=			M	*	2016=V-225077;2019=V-205755;2022=V-254498;2025=V-278248;legacy=WN22-UR-000080
STIG-V-254499	USER RIGHTS ASSIGNMENT	Windows Server 2022 create symbolic links user right must only be assigned to the Administrators group.	userright	SeCreateSymbolicLinkPrivilege		in	Administrators,NT Virtual Machine\\Virtual Machines,Administrators		M	2016:MS,2019,2022	2016=V-225078;2019=V-205756;2022=V-254499;legacy=WN22-UR-000090
STIG-V-278249	USER RIGHTS ASSIGNMENT	The Create symbolic links user right must only be assigned to the Administrators group.	userright	SeCreateSymbolicLinkPrivilege		=	Administrators		M	2016:DC,2025	2016=V-225078;2025=V-278249;legacy=WN16-UR-000120
STIG-V-254500	USER RIGHTS ASSIGNMENT	Windows Server 2022 debug programs user right must only be assigned to the Administrators group.	userright	SeDebugPrivilege		=	Administrators		H	*	2016=V-225079;2019=V-205757;2022=V-254500;2025=V-278250;legacy=WN22-UR-000100
STIG-V-254501	USER RIGHTS ASSIGNMENT	Windows Server 2022 force shutdown from a remote system user right must only be assigned to the Administrators group.	userright	SeRemoteShutdownPrivilege		=	Administrators		M	*	2016=V-225080;2019=V-205758;2022=V-254501;2025=V-278251;legacy=WN22-UR-000110
STIG-V-254502	USER RIGHTS ASSIGNMENT	Windows Server 2022 generate security audits user right must only be assigned to Local Service and Network Service.	userright	SeAuditPrivilege		=	Local Service,Network Service		M	2016,2019,2022	2016=V-225081;2019=V-205759;2022=V-254502;legacy=WN22-UR-000120
STIG-V-254503	USER RIGHTS ASSIGNMENT	Windows Server 2022 impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.	userright	SeImpersonatePrivilege		=	Administrators,Service,Local Service,Network Service		M	2016,2019,2022	2016=V-225082;2019=V-205760;2022=V-254503;legacy=WN22-UR-000130
STIG-V-254504	USER RIGHTS ASSIGNMENT	Windows Server 2022 increase scheduling priority: user right must only be assigned to the Administrators group.	userright	SeIncreaseBasePriorityPrivilege		=	Administrators		M	*	2016=V-225083;2019=V-205761;2022=V-254504;2025=V-278254;legacy=WN22-UR-000140
STIG-V-254505	USER RIGHTS ASSIGNMENT	Windows Server 2022 load and unload device drivers user right must only be assigned to the Administrators group.	userright	SeLoadDriverPrivilege		=	Administrators		M	*	2016=V-225084;2019=V-205762;2022=V-254505;2025=V-278255;legacy=WN22-UR-000150
STIG-V-254506	USER RIGHTS ASSIGNMENT	Windows Server 2022 lock pages in memory user right must not be assigned to any groups or accounts.	userright	SeLockMemoryPrivilege		=			M	*	2016=V-225085;2019=V-205763;2022=V-254506;2025=V-278256;legacy=WN22-UR-000160
STIG-V-254507	USER RIGHTS ASSIGNMENT	Windows Server 2022 manage auditing and security log user right must only be assigned to the Administrators group.	userright	SeSecurityPrivilege		=	Administrators		M	*	2016=V-225086;2019=V-205643;2022=V-254507;2025=V-278257;legacy=WN22-UR-000170
STIG-V-254508	USER RIGHTS ASSIGNMENT	Windows Server 2022 modify firmware environment values user right must only be assigned to the Administrators group.	userright	SeSystemEnvironmentPrivilege		=	Administrators		M	*	2016=V-225087;2019=V-205764;2022=V-254508;2025=V-278258;legacy=WN22-UR-000180
STIG-V-254509	USER RIGHTS ASSIGNMENT	Windows Server 2022 perform volume maintenance tasks user right must only be assigned to the Administrators group.	userright	SeManageVolumePrivilege		=	Administrators		M	*	2016=V-225088;2019=V-205765;2022=V-254509;2025=V-278259;legacy=WN22-UR-000190
STIG-V-254510	USER RIGHTS ASSIGNMENT	Windows Server 2022 profile single process user right must only be assigned to the Administrators group.	userright	SeProfileSingleProcessPrivilege		=	Administrators		M	*	2016=V-225089;2019=V-205766;2022=V-254510;2025=V-278260;legacy=WN22-UR-000200
STIG-V-254496	USER RIGHTS ASSIGNMENT	Windows Server 2022 create a token object user right must not be assigned to any groups or accounts.	userright	SeCreateTokenPrivilege		=			H	*	2016=V-225091;2019=V-205753;2022=V-254496;2025=V-278246;legacy=WN22-UR-000060
STIG-V-254511	USER RIGHTS ASSIGNMENT	Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group.	userright	SeRestorePrivilege		=	Administrators		M	*	2016=V-225092;2019=V-205767;2022=V-254511;2025=V-278261;legacy=WN22-UR-000210
STIG-V-254512	USER RIGHTS ASSIGNMENT	Windows Server 2022 take ownership of files or other objects user right must only be assigned to the Administrators group.	userright	SeTakeOwnershipPrivilege		=	Administrators		M	*	2016=V-225093;2019=V-205768;2022=V-254512;2025=V-278262;legacy=WN22-UR-000220
STIG-V-236000	REGISTRY POLICY	The Windows Explorer Preview pane must be disabled for Windows Server 2016.	reguser	SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoPreviewPane	=	1		M	2016	2016=V-236000;legacy=WN16-CC-000421
STIG-V-236000#2	REGISTRY POLICY	The Windows Explorer Preview pane must be disabled for Windows Server 2016.	reguser	SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	NoReadingPane	=	1		M	2016	2016=V-236000;legacy=WN16-CC-000421
STIG-V-254384	REGISTRY POLICY	Windows Server 2022 must have PowerShell Transcription enabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription	EnableTranscripting	=	1		M	*	2016=V-257502;2019=V-257503;2022=V-254384;2025=V-278131;legacy=WN22-CC-000530
STIG-V-254418	USER RIGHTS ASSIGNMENT	Windows Server 2022 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.	userright	SeNetworkLogonRight		=	Administrators,Authenticated Users,Enterprise Domain Controllers		M	2019:DC,2022:DC	2019=V-205665;2022=V-254418;legacy=WN22-DC-000340
STIG-V-254371	REGISTRY POLICY	Windows Server 2022 must disable Basic authentication for RSS feeds over HTTP.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds	AllowBasicAuthInClear	=	0		M	2019,2022	2019=V-205693;2022=V-254371;legacy=WN22-CC-000400
STIG-V-254359	REGISTRY POLICY	The Windows Server 2022 security event log size must be configured to a value that holds at least one week's worth of audit records.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security	MaxSize	>=	1234569216		M	2019,2022	2019=V-205797;2022=V-254359;legacy=WN22-CC-000280
STIG-V-205820	SECURITY OPTIONS	Windows Server 2019 domain controllers must require LDAP access signing.	secopt	Domain_controller_LDAP_server_signing_requirements		=	Require Signing		M	2019:DC	2019=V-205820;legacy=WN19-DC-000320
STIG-V-254362	REGISTRY POLICY	Windows Server 2022 Explorer Data Execution Prevention must be enabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoDataExecutionPrevention	=	0		M	2019,2022	2019=V-205830;2022=V-254362;legacy=WN22-CC-000310
STIG-V-254340	REGISTRY POLICY	Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\NETLOGON	=	RequireMutualAuthentication=1, RequireIntegrity=1		M	2019,2022,2025	2019=V-205862;2022=V-254340;2025=V-278087;legacy=WN22-CC-000080
STIG-V-254340#2	REGISTRY POLICY	Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\SYSVOL	=	RequireMutualAuthentication=1, RequireIntegrity=1		M	2019,2022,2025	2019=V-205862;2022=V-254340;2025=V-278087;legacy=WN22-CC-000080
STIG-V-254342	REGISTRY POLICY	Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation	AllowProtectedCreds	=	1		M	2019,2022,2025	2019=V-205863;2022=V-254342;2025=V-278089;legacy=WN22-CC-000100
STIG-V-254357	REGISTRY POLICY	Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization	DODownloadMode	in	0,1,2,99,100		L	2019,2022	2019=V-205870;2022=V-254357;legacy=WN22-CC-000260
STIG-V-254363	REGISTRY POLICY	Windows Server 2022 Turning off File Explorer heap termination on corruption must be disabled.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer	NoHeapTerminationOnCorruption	=	0		L	2019,2022	2019=V-205871;2022=V-254363;legacy=WN22-CC-000320
STIG-V-254364	REGISTRY POLICY	Windows Server 2022 File Explorer shell protocol must run in protected mode.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer	PreXPSP2ShellProtocolBehavior	=	0		M	2019,2022	2019=V-205872;2022=V-254364;legacy=WN22-CC-000330
STIG-V-254375	REGISTRY POLICY	Windows Server 2022 users must be notified if a web-based program attempts to install software.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer	SafeForScripting	=	0		M	2019,2022	2019=V-205874;2022=V-254375;legacy=WN22-CC-000440
STIG-V-254490	REGISTRY POLICY	Windows Server 2022 must preserve zone information when saving attachments.	reguser	SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments	SaveZoneInformation	=	2		M	2019,2022	2019=V-205924;2022=V-254490;legacy=WN22-UC-000010
STIG-V-271426	REGISTRY POLICY	Windows Server 2022 must be configured for certificate-based authentication for domain controllers.	reg	HKLM:\SYSTEM\CurrentControlSet\Services\Kdc	StrongCertificateBindingEnforcement	in	1,2		M	2019:DC,2022:DC,2025:DC	2019=V-271428;2022=V-271426;2025=V-278172;legacy=WN22-DC-000405
STIG-V-254356	REGISTRY POLICY	Windows Server 2022 Diagnostic Data must be configured to send "required diagnostic data" or "optional diagnostic data".	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection	AllowTelemetry	=	1		M	2022	2022=V-254356;legacy=WN22-CC-000250
STIG-V-278055	ADVANCED AUDIT POLICY	Windows Server 2025 must be configured to audit Logon/Logoff - Account Lockout successes.	auditsub	Account Lockout	Success	=	Success		M	2025	2025=V-278055;legacy=WN25-AU-000150
STIG-V-278103	REGISTRY POLICY	Windows Server 2025 Telemetry must be configured to limit diagnostic data sent to Microsoft.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection	AllowTelemetry	=			M	2025	2025=V-278103;legacy=WN25-CC-000250
STIG-V-278104	REGISTRY POLICY	Windows Server 2025 Windows Update must not obtain updates from other PCs on the internet.	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization	DODownloadMode	=	0		L	2025	2025=V-278104;legacy=WN25-CC-000260
STIG-V-278158	ADVANCED AUDIT POLICY	Windows Server 2025 must be configured to audit DS Access - Directory Service Changes failures.	auditsub	Directory Service Changes	Failure	=	Failure		M	2025:DC	2025=V-278158;legacy=WN25-DC-000270
STIG-V-278165	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.	userright	SeNetworkLogonRight		=	Administrators.,Authenticated Users.,Enterprise Domain Controllers		M	2025:DC	2025=V-278165;legacy=WN25-DC-000340
STIG-V-278183	USER RIGHTS ASSIGNMENT	Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and stand-alone or nondomain-joined systems.	userright	SeNetworkLogonRight		=	Administrators.,Authenticated Users		M	2025:MS	2025=V-278183;legacy=WN25-MS-000070
STIG-V-278184	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Deny access to this computer from the network" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems.	userright	SeDenyNetworkLogonRight		in	Enterprise Admins.,Domain Admins.,(Local account and member of Administrators group,Local account),Guests.		M	2025:MS	2025=V-278184;legacy=WN25-MS-000080
STIG-V-278185	USER RIGHTS ASSIGNMENT	Windows Server 2025 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.	userright	SeDenyBatchLogonRight		=	Enterprise Admins.,Domain Admins.,Guests		M	2025:MS	2025=V-278185;legacy=WN25-MS-000090
STIG-V-278186	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Deny log on as a service" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.	userright	SeDenyServiceLogonRight		=	Enterprise Admins.,Domain Admins		M	2025:MS	2025=V-278186;legacy=WN25-MS-000100
STIG-V-278187	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Deny log on locally" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.	userright	SeDenyInteractiveLogonRight		=	Enterprise Admins.,Domain Admins.,Guests		M	2025:MS	2025=V-278187;legacy=WN25-MS-000110
STIG-V-278188	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Deny log on through Remote Desktop Services" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems.	userright	SeDenyRemoteInteractiveLogonRight		=	Enterprise Admins.,Domain Admins.,Local account .,Guests		M	2025:MS	2025=V-278188;legacy=WN25-MS-000120
STIG-V-278208	REGISTRY POLICY	Windows Server 2025 title for legal banner dialog box must be configured with the appropriate text.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LegalNoticeCaption	=	See message title options below		L	2025	2025=V-278208;legacy=WN25-SO-000140
STIG-V-278234	REGISTRY POLICY	Windows Server 2025 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop.	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	ConsentPromptBehaviorAdmin	=	2		M	2025	2025=V-278234;legacy=WN25-SO-000400
STIG-V-278247	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.	userright	SeCreateGlobalPrivilege		=	Administrators.,Service.,Local Service.,Network Service		M	2025	2025=V-278247;legacy=WN25-UR-000070
STIG-V-278252	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Generate security audits" user right must only be assigned to Local Service and Network Service.	userright	SeAuditPrivilege		=	Local Service.,Network Service		M	2025	2025=V-278252;legacy=WN25-UR-000120
STIG-V-278253	USER RIGHTS ASSIGNMENT	The Windows Server 2025 "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service.	userright	SeImpersonatePrivilege		=	Administrators.,Service.,Local Service.,Network Service		M	2025	2025=V-278253;legacy=WN25-UR-000130
'@


# DISA STIG - rules that need a human. Emitted as INFO only with -IncludeManual,
# so a STIG checklist can be completed without pretending they were tested.
$script:StigManualTable = @'
STIG-V-254238	MANUAL REVIEW	Windows Server 2022 must have orphaned security identifiers (SIDs) removed from user rights.	manual	Manual		manual	ManualRule		M	*	2016=V-224819;2019=V-205624;2022=V-254238;2025=V-277985;legacy=WN22-00-000450
STIG-V-254244	POLICY DOCUMENTATION	Windows Server 2022 PKI certificates associated with user accounts must be issued by a DoD PKI or an approved External Certificate Authority (ECA).	manual	Document		manual	DocumentRule		H	*	2016=V-224825;2019=V-205677;2022=V-254244;2025=V-277982;legacy=WN22-DC-000300
STIG-V-254247	ADVANCED AUDIT POLICY	Windows Server 2022 local volumes must use a format that supports NTFS attributes.	manual	audit setting		manual	AuditSettingRule		H	*	2016=V-224828;2019=V-205663;2022=V-254247;2025=V-277997;legacy=WN22-00-000130
STIG-V-254251	PERMISSIONS	Windows Server 2022 permissions for the system drive root directory (usually C:\) must conform to minimum requirements.	manual	%SystemDrive%\		manual	PermissionRule		M	*	2016=V-224832;2019=V-205734;2022=V-254251;2025=V-277998;legacy=WN22-00-000140
STIG-V-254252	PERMISSIONS	Windows Server 2022 permissions for program file directories must conform to minimum requirements.	manual	%ProgramFiles(x86)%		manual	PermissionRule		M	*	2016=V-224833;2019=V-205735;2022=V-254252;2025=V-277999;legacy=WN22-00-000150
STIG-V-254252#2	PERMISSIONS	Windows Server 2022 permissions for program file directories must conform to minimum requirements.	manual	%ProgramFiles%		manual	PermissionRule		M	*	2016=V-224833;2019=V-205735;2022=V-254252;2025=V-277999;legacy=WN22-00-000150
STIG-V-254253	PERMISSIONS	Windows Server 2022 permissions for the Windows installation directory must conform to minimum requirements.	manual	%windir%		manual	PermissionRule		M	*	2016=V-224834;2019=V-205736;2022=V-254253;2025=V-278000;legacy=WN22-00-000160
STIG-V-254254	PERMISSIONS	Windows Server 2022 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.	manual	HKLM:\SECURITY		manual	PermissionRule		M	*	2016=V-224835;2019=V-205737;2022=V-254254;2025=V-278001;legacy=WN22-00-000170
STIG-V-254254#2	PERMISSIONS	Windows Server 2022 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.	manual	HKLM:\SOFTWARE		manual	PermissionRule		M	*	2016=V-224835;2019=V-205737;2022=V-254254;2025=V-278001;legacy=WN22-00-000170
STIG-V-254254#3	PERMISSIONS	Windows Server 2022 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.	manual	HKLM:\SYSTEM		manual	PermissionRule		M	*	2016=V-224835;2019=V-205737;2022=V-254254;2025=V-278001;legacy=WN22-00-000170
STIG-V-254296	PERMISSIONS	Windows Server 2022 permissions for the Application event log must prevent access by nonprivileged accounts.	manual	%windir%\SYSTEM32\WINEVT\LOGS\Application.evtx		manual	PermissionRule		M	*	2016=V-224877;2019=V-205640;2022=V-254296;2025=V-278043;legacy=WN22-AU-000030
STIG-V-254297	PERMISSIONS	Windows Server 2022 permissions for the Security event log must prevent access by nonprivileged accounts.	manual	%windir%\SYSTEM32\WINEVT\LOGS\Security.evtx		manual	PermissionRule		M	*	2016=V-224878;2019=V-205641;2022=V-254297;2025=V-278044;legacy=WN22-AU-000040
STIG-V-254298	PERMISSIONS	Windows Server 2022 permissions for the System event log must prevent access by nonprivileged accounts.	manual	%windir%\SYSTEM32\WINEVT\LOGS\System.evtx		manual	PermissionRule		M	*	2016=V-224879;2019=V-205642;2022=V-254298;2025=V-278045;legacy=WN22-AU-000050
STIG-V-254299	PERMISSIONS	Windows Server 2022 Event Viewer must be protected from unauthorized modification and deletion.	manual	%windir%\SYSTEM32\eventvwr.exe		manual	PermissionRule		M	*	2016=V-224880;2019=V-205731;2022=V-254299;2025=V-278046;legacy=WN22-AU-000060
STIG-V-254392	PERMISSIONS	Windows Server 2022 Active Directory SYSVOL directory must have the proper access control permissions.	manual	%windir%\sysvol		manual	PermissionRule		H	2016:DC,2019:DC,2022:DC,2025:DC	2016=V-224971;2019=V-205740;2022=V-254392;2025=V-278139;legacy=WN22-DC-000080
STIG-V-254442	ROOT CERTIFICATES	Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DoD Root CA 3 certificate is present		M	2016,2019,2022	2016=V-225021;2019=V-205648;2022=V-254442;legacy=WN22-PK-000010
STIG-V-254442#2	ROOT CERTIFICATES	Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DoD Root CA 4 certificate is present		M	2016,2019,2022	2016=V-225021;2019=V-205648;2022=V-254442;legacy=WN22-PK-000010
STIG-V-254442#3	ROOT CERTIFICATES	Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DoD Root CA 5 certificate is present		M	2016,2019,2022	2016=V-225021;2019=V-205648;2022=V-254442;legacy=WN22-PK-000010
STIG-V-254442#4	ROOT CERTIFICATES	Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DoD Root CA 6 certificate is present		M	2016,2019,2022	2016=V-225021;2019=V-205648;2022=V-254442;legacy=WN22-PK-000010
STIG-V-254443	ROOT CERTIFICATES	Windows Server 2022 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	location for DoD Interoperability Root CA 2 certificate is present		M	2016,2019,2022	2016=V-225022;2019=V-205649;2022=V-254443;legacy=WN22-PK-000020
STIG-V-205650	ROOT CERTIFICATES	The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	location for US DoD CCEB Interoperability Root CA 2 certificate is present		M	2016,2019	2016=V-225023;2019=V-205650;legacy=WN16-PK-000030
STIG-V-254457	REGISTRY POLICY	Windows Server 2022 required legal notice must be configured to display before console logon.	manual	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	LegalNoticeText	manual	{0} is set to the required legal notice before logon		M	*	2016=V-225036;2019=V-205631;2022=V-254457;2025=V-278207;legacy=WN22-SO-000130
STIG-V-254248	SYSTEM SERVICES	Windows Server 2022 must use an antivirus program.	manual	service		manual	ServiceName/StartupType is populated with correct AntiVirus service information		M	2019,2022	2019=V-205850;2022=V-254248;legacy=WN22-00-000110
STIG-V-254265	SYSTEM SERVICES	Windows Server 2022 must have a host-based firewall installed and enabled.	manual	service		manual	ServiceName/StartupType is populated with correct Firewall service information		M	2019,2022	2019=V-214936;2022=V-254265;legacy=WN22-00-000280
STIG-V-254391	PERMISSIONS	Windows Server 2022 permissions on the Active Directory data files must only allow System and Administrators access.	manual	%windir%\NTDS\*.*		manual	PermissionRule		H	2022:DC,2025:DC	2022=V-254391;2025=V-278138;legacy=WN22-DC-000070
STIG-V-278002	PERMISSIONS	Windows Server 2025 nonadministrative accounts or groups must only have print permissions on printer shares.	manual	permissions		manual	PermissionRule		L	2025	2025=V-278002;legacy=WN25-00-000180
STIG-V-278192	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DOD Root CA 2 certificate is present		M	2025	2025=V-278192;legacy=WN25-PK-000010
STIG-V-278192#2	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DOD Root CA 3 certificate is present		M	2025	2025=V-278192;legacy=WN25-PK-000010
STIG-V-278192#3	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DOD Root CA 4 certificate is present		M	2025	2025=V-278192;legacy=WN25-PK-000010
STIG-V-278192#4	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.	manual	root certificate		manual	location for DOD Root CA 5 certificate is present		M	2025	2025=V-278192;legacy=WN25-PK-000010
STIG-V-278193	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	location for DOD Interoperability Root CA 2 certificate is present		M	2025	2025=V-278193;legacy=WN25-PK-000020
STIG-V-278193#2	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	location for DOD Interoperability Root CA 1 certificate is present		M	2025	2025=V-278193;legacy=WN25-PK-000020
STIG-V-278193#3	ROOT CERTIFICATES	Windows Server 2025 must have the DOD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	RootCertificateRule		M	2025	2025=V-278193;legacy=WN25-PK-000020
STIG-V-278194	ROOT CERTIFICATES	Windows Server 2025 must have the US DOD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.	manual	root certificate		manual	location for US DOD CCEB Interoperability Root CA 2 certificate is present		M	2025	2025=V-278194;legacy=WN25-PK-000030
'@


# Microsoft Security Baseline - only the settings CIS does not already assert
# identically. Rows marked "differs-from-CIS" are where the two disagree on the
# value, which is exactly what an auditor needs to see rather than have hidden.
$script:BaselineTable = @'
MSB-LockoutBadCount	MS SECURITY BASELINE: ACCOUNT POLICIES	Account lockout threshold	accountpolicy	LockoutBadCount		<=	10	Never	L	2022	MSFT baseline;differs-from-CIS
MSB-LockoutBadCount#2	MS SECURITY BASELINE: ACCOUNT POLICIES	Account lockout threshold	accountpolicy	LockoutBadCount		<=	3	Never	L	2025	MSFT baseline;differs-from-CIS
MSB-EnableNetbios	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: NETWORK	DNS Client: Configure NetBIOS settings	reg	HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient	EnableNetbios	=	0		M	2025	MSFT baseline;differs-from-CIS
MSB-MinSmb2Dialect	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: NETWORK	Lanman Server: Mandate the minimum version of SMB	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanServer	MinSmb2Dialect	=	768		M	2025	MSFT baseline;differs-from-CIS
MSB-MinSmb2Dialect#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: NETWORK	Lanman Workstation: Mandate the minimum version of SMB	reg	HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation	MinSmb2Dialect	=	768		M	2025	MSFT baseline;differs-from-CIS
MSB-NETLOGON	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: NETWORK	Network Provider: Hardened UNC Paths (NETLOGON)	reg	HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\NETLOGON	=	RequireMutualAuthentication=1,RequireIntegrity=1		M	2022,2025	MSFT baseline;differs-from-CIS
MSB-SYSVOL	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: NETWORK	Network Provider: Hardened UNC Paths (SYSVOL)	reg	HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths	\\*\SYSVOL	=	RequireMutualAuthentication=1, RequireIntegrity=1		M	2022,2025	MSFT baseline;differs-from-CIS
MSB-ForceKerberosForRpc	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: PRINTERS	Configure RPC listener settings (ForceKerberosForRpc)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	ForceKerberosForRpc	=	0		M	2025	MSFT baseline;differs-from-CIS
MSB-RpcAuthentication	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: PRINTERS	Configure RPC connection settings (RpcAuthentication)	reg	HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC	RpcAuthentication	=	1		M	2025	MSFT baseline;differs-from-CIS
MSB-AllowCustomSSPsAPs	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Local Security Authority: Allow Custom SSPs and APs to be loaded into LSASS	reg	HKLM:\Software\Policies\Microsoft\Windows\System	AllowCustomSSPsAPs	=	1		M	2025:MS	MSFT baseline;differs-from-CIS
MSB-Enabled	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Configure the behavior of the sudo command	reg	HKLM:\Software\Policies\Microsoft\Windows\Sudo	Enabled	=	0		M	2025	MSFT baseline
MSB-PKINITHashAlgorithmConfigura	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	KDC: Configure hash algorithms for certificate logon	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters	PKINITHashAlgorithmConfigurationEnabled	=	1		M	2025	MSFT baseline
MSB-PKINITHashAlgorithmConfigura#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Kerberos: Configure hash algorithms for certificate logon	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	PKINITHashAlgorithmConfigurationEnabled	=	1		M	2025	MSFT baseline
MSB-PKINITSHA1	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	KDC: Configure hash algorithms for certificate logon (SHA-1)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters	PKINITSHA1	=	1		M	2025	MSFT baseline
MSB-PKINITSHA1#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Kerberos: Configure hash algorithms for certificate logon (SHA-1)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	PKINITSHA1	=	1		M	2025	MSFT baseline
MSB-PKINITSHA256	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	KDC: Configure hash algorithms for certificate logon (SHA-256)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters	PKINITSHA256	=	3		M	2025	MSFT baseline
MSB-PKINITSHA256#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Kerberos: Configure hash algorithms for certificate logon (SHA-256)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	PKINITSHA256	=	3		M	2025	MSFT baseline
MSB-PKINITSHA384	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	KDC: Configure hash algorithms for certificate logon (SHA-384)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters	PKINITSHA384	=	3		M	2025	MSFT baseline
MSB-PKINITSHA384#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Kerberos: Configure hash algorithms for certificate logon (SHA-384)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	PKINITSHA384	=	3		M	2025	MSFT baseline
MSB-PKINITSHA512	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	KDC: Configure hash algorithms for certificate logon (SHA-512)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters	PKINITSHA512	=	3		M	2025	MSFT baseline
MSB-PKINITSHA512#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Kerberos: Configure hash algorithms for certificate logon (SHA-512)	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	PKINITSHA512	=	3		M	2025	MSFT baseline
MSB-RequirePlatformSecurityFeatu	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Device Guard: Select Platform Security Level (Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard	RequirePlatformSecurityFeatures	=	1		M	2022,2025	MSFT baseline;differs-from-CIS
MSB-SamNGCKeyROCAValidation	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: SYSTEM	Security Account Manager: Configure validation of ROCA-vulnerable WHfB keys during authentication	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\SAM	SamNGCKeyROCAValidation	=	2		M	2025:DC	MSFT baseline;differs-from-CIS
MSB-01443614cd74433ab99e2ecdc07b	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	01443614-cd74-433a-b99e-2ecdc07bfc25	=	0	0	L	2022	MSFT baseline
MSB-01443614cd74433ab99e2ecdc07b#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion	asr	01443614-cd74-433a-b99e-2ecdc07bfc25		=	0	0	L	2022	MSFT baseline
MSB-1001	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Download signed ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1001	=	3		M	2022,2025	MSFT baseline
MSB-1001#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Download signed ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1001	=	3		M	2022,2025	MSFT baseline
MSB-1004	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Download unsigned ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1004	=	3		M	2022,2025	MSFT baseline
MSB-1004#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Download unsigned ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1004	=	3		M	2022,2025	MSFT baseline
MSB-1200	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Run ActiveX controls and plugins	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1200	=	3		M	2022,2025	MSFT baseline
MSB-1201	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Initialize and script ActiveX controls not marked as safe	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1201	=	3		M	2022,2025	MSFT baseline
MSB-1201#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Intranet Zone: Initialize and script ActiveX controls not marked as safe	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1	1201	=	3		M	2022,2025	MSFT baseline
MSB-1201#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Initialize and script ActiveX controls not marked as safe	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1201	=	3		M	2022,2025	MSFT baseline
MSB-1201#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Trusted Sites Zone: Initialize and script ActiveX controls not marked as safe	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2	1201	=	3		M	2022,2025	MSFT baseline
MSB-1206	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow scripting of Internet Explorer WebBrowser controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1206	=	3		M	2022,2025	MSFT baseline
MSB-1206#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow scripting of Internet Explorer WebBrowser controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1206	=	3		M	2022,2025	MSFT baseline
MSB-1209	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow scriptlets	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1209	=	3		M	2022,2025	MSFT baseline
MSB-1209#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow scriptlets	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1209	=	3		M	2022,2025	MSFT baseline
MSB-120b	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow only approved domains to use ActiveX controls without prompt	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	120b	=	3		M	2022,2025	MSFT baseline
MSB-120b#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow only approved domains to use ActiveX controls without prompt	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	120b	=	3		M	2022,2025	MSFT baseline
MSB-120c	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow only approved domains to use the TDC ActiveX control	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	120c	=	3		M	2022,2025	MSFT baseline
MSB-120c#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow only approved domains to use the TDC ActiveX control	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	120c	=	3		M	2022,2025	MSFT baseline
MSB-1400	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow active scripting	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1400	=	3		M	2022,2025	MSFT baseline
MSB-1402	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Scripting of Java applets	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1402	=	3		M	2022,2025	MSFT baseline
MSB-1405	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Script ActiveX controls marked safe for scripting	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1405	=	3		M	2022,2025	MSFT baseline
MSB-1406	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Access data sources across domains	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1406	=	3		M	2022,2025	MSFT baseline
MSB-1406#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Access data sources across domains	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1406	=	3		M	2022,2025	MSFT baseline
MSB-1407	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow cut, copy or paste operations from the clipboard via script	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1407	=	3		M	2022,2025	MSFT baseline
MSB-1407#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow cut, copy or paste operations from the clipboard via script	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1407	=	3		M	2022,2025	MSFT baseline
MSB-1409	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Turn on Cross-Site Scripting Filter	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1409	=	0		M	2022,2025	MSFT baseline
MSB-1409#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Turn on Cross-Site Scripting Filter	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1409	=	0		M	2022,2025	MSFT baseline
MSB-140C	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow VBScript to run in Internet Explorer	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	140C	=	3		M	2022,2025	MSFT baseline
MSB-140C#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow VBScript to run in Internet Explorer	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	140C	=	3		M	2022,2025	MSFT baseline
MSB-1606	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Userdata persistence	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1606	=	3		M	2022,2025	MSFT baseline
MSB-1606#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Userdata persistence	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1606	=	3		M	2022,2025	MSFT baseline
MSB-1607	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Navigate windows and frames across different domains	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1607	=	3		M	2022,2025	MSFT baseline
MSB-1607#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Navigate windows and frames across different domains	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1607	=	3		M	2022,2025	MSFT baseline
MSB-1608	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow META REFRESH	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1608	=	3		M	2022,2025	MSFT baseline
MSB-160A	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Include local path when user is uploading files to a server	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	160A	=	3		M	2022,2025	MSFT baseline
MSB-160A#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Include local path when user is uploading files to a server	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	160A	=	3		M	2022,2025	MSFT baseline
MSB-1802	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow drag and drop or copy and paste files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1802	=	3		M	2022,2025	MSFT baseline
MSB-1802#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow drag and drop or copy and paste files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1802	=	3		M	2022,2025	MSFT baseline
MSB-1803	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow file downloads	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1803	=	3		M	2022,2025	MSFT baseline
MSB-1804	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Launching applications and files in an IFRAME	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1804	=	3		M	2022,2025	MSFT baseline
MSB-1804#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Launching applications and files in an IFRAME	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1804	=	3		M	2022,2025	MSFT baseline
MSB-1806	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Show security warning for potentially unsafe files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1806	=	1		M	2022,2025	MSFT baseline
MSB-1806#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Show security warning for potentially unsafe files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1806	=	3		M	2022,2025	MSFT baseline
MSB-1809	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Use Pop-up Blocker	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1809	=	0		M	2022,2025	MSFT baseline
MSB-1809#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Use Pop-up Blocker	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1809	=	0		M	2022,2025	MSFT baseline
MSB-1A00	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Logon options	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1A00	=	65536		M	2022,2025	MSFT baseline
MSB-1A00#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Logon options	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1A00	=	196608		M	2022,2025	MSFT baseline
MSB-1C00	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Intranet Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1	1C00	=	65536		M	2022,2025	MSFT baseline
MSB-1C00#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Local Machine Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Intranet Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#5	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Local Machine Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#6	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Restricted Sites Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#7	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Trusted Sites Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#8	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	1C00	=	0		M	2022,2025	MSFT baseline
MSB-1C00#9	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Trusted Sites Zone: Java permissions	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2	1C00	=	65536		M	2022,2025	MSFT baseline
MSB-2000	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow binary and script behaviors	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2000	=	3		M	2022,2025	MSFT baseline
MSB-2001	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Run .NET Framework-reliant components signed with Authenticode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2001	=	3		M	2022,2025	MSFT baseline
MSB-2001#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Run .NET Framework-reliant components signed with Authenticode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2001	=	3		M	2022,2025	MSFT baseline
MSB-2004	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Run .NET Framework-reliant components not signed with Authenticode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2004	=	3		M	2022,2025	MSFT baseline
MSB-2004#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Run .NET Framework-reliant components not signed with Authenticode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2004	=	3		M	2022,2025	MSFT baseline
MSB-2101	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Web sites in less privileged Web content zones can navigate into this zone	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2101	=	3		M	2022,2025	MSFT baseline
MSB-2101#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Web sites in less privileged Web content zones can navigate into this zone	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2101	=	3		M	2022,2025	MSFT baseline
MSB-2102	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow script-initiated windows without size or position constraints	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2102	=	3		M	2022,2025	MSFT baseline
MSB-2102#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow script-initiated windows without size or position constraints	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2102	=	3		M	2022,2025	MSFT baseline
MSB-2103	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow updates to status bar via script	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2103	=	3		M	2022,2025	MSFT baseline
MSB-2103#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow updates to status bar via script	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2103	=	3		M	2022,2025	MSFT baseline
MSB-2200	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Automatic prompting for file downloads	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2200	=	3		M	2022,2025	MSFT baseline
MSB-2200#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Automatic prompting for file downloads	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2200	=	3		M	2022,2025	MSFT baseline
MSB-2301	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Turn on SmartScreen Filter scan	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2301	=	0		M	2022,2025	MSFT baseline
MSB-2301#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Internet Zone: Turn on SmartScreen Filter scan	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3	2301	=	0		M	2022,2025	MSFT baseline
MSB-2301#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Locked-Down Restricted Sites Zone: Turn on SmartScreen Filter scan	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4	2301	=	0		M	2022,2025	MSFT baseline
MSB-2301#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Turn on SmartScreen Filter scan	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2301	=	0		M	2022,2025	MSFT baseline
MSB-2402	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Allow loading of XAML files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2402	=	3		M	2022,2025	MSFT baseline
MSB-2402#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Allow loading of XAML files	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2402	=	3		M	2022,2025	MSFT baseline
MSB-2500	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Turn on Protected Mode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2500	=	0		M	2022,2025	MSFT baseline
MSB-2500#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Turn on Protected Mode	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2500	=	0		M	2022,2025	MSFT baseline
MSB-2708	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Enable dragging of content from different domains within a window	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2708	=	3		M	2022,2025	MSFT baseline
MSB-2708#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Enable dragging of content from different domains within a window	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2708	=	3		M	2022,2025	MSFT baseline
MSB-2709	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Enable dragging of content from different domains across windows	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	2709	=	3		M	2022,2025	MSFT baseline
MSB-2709#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Enable dragging of content from different domains across windows	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	2709	=	3		M	2022,2025	MSFT baseline
MSB-270C	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Internet Zone: Don't run antimalware programs against ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3	270C	=	0		M	2022,2025	MSFT baseline
MSB-270C#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Intranet Zone: Don't run antimalware programs against ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1	270C	=	0		M	2022,2025	MSFT baseline
MSB-270C#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Local Machine Zone: Don't run antimalware programs against ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0	270C	=	0		M	2022,2025	MSFT baseline
MSB-270C#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Restricted Sites Zone: Don't run antimalware programs against ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4	270C	=	0		M	2022,2025	MSFT baseline
MSB-270C#5	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Trusted Sites Zone: Don't run antimalware programs against ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2	270C	=	0		M	2022,2025	MSFT baseline
MSB-AllowNetworkProtectionOnWinS	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: Network Protection: This settings controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection	AllowNetworkProtectionOnWinServer	=	1	0	M	2025	MSFT baseline
MSB-AllowWindowsInkWorkspace	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Windows Ink Workspace: Allow Windows Ink Workspace	reg	HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace	AllowWindowsInkWorkspace	=	1	1	L	2022	MSFT baseline;differs-from-CIS
MSB-BlockNonAdminActiveXInstall	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Prevent per-user installation of ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX	BlockNonAdminActiveXInstall	=	1		M	2022,2025	MSFT baseline
MSB-CertificateRevocation	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Check for server certificate revocation	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	CertificateRevocation	=	1		M	2022,2025	MSFT baseline
MSB-CheckExeSignatures	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Check for signatures on downloaded programs	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Download	CheckExeSignatures	=	yes		M	2022,2025	MSFT baseline
MSB-DisableBlockAtFirstSeen	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: MAPS: Configure the 'Block at First Sight' feature	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet	DisableBlockAtFirstSeen	>=	0		M	2022,2025	MSFT baseline
MSB-DisableEPMCompat	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main	DisableEPMCompat	=	1		M	2022,2025	MSFT baseline
MSB-DisableInternetExplorerLaunc	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Disable Internet Explorer 11 Launch Via COM Automation	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main	DisableInternetExplorerLaunchViaCOM	=	1		M	2025	MSFT baseline
MSB-DisableSecuritySettingsCheck	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Turn off the Security Settings Check feature	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Security	DisableSecuritySettingsCheck	=	0		M	2022,2025	MSFT baseline
MSB-EnableDynamicSignatureDroppe	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Reporting: Configure whether to report Dynamic Signature dropped events	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting	EnableDynamicSignatureDroppedEventReporting	=	1		M	2025	MSFT baseline
MSB-EnableSSL3Fallback	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Allow fallback to SSL 3.0 (Internet Explorer)	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	EnableSSL3Fallback	=	0		M	2022,2025	MSFT baseline
MSB-EnableScriptBlockInvocationL	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Windows PowerShell: Turn on PowerShell Script Block Logging (Invocation)	reg	HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging	EnableScriptBlockInvocationLogging	=	0	0	L	2022,2025	MSFT baseline
MSB-EnabledV9	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Prevent managing SmartScreen Filter	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter	EnabledV9	=	1		M	2022,2025	MSFT baseline
MSB-EngineRing	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Select the channel for Microsoft Defender monthly engine updates	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	EngineRing	=	5		M	2025	MSFT baseline
MSB-HideExclusionsFromLocalAdmin	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Control whether or not exclusions are visible to Local Admins	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	HideExclusionsFromLocalAdmins	=	1		M	2025	MSFT baseline
MSB-Isolation	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Turn on Enhanced Protected Mode	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main	Isolation	=	PMEM		M	2022,2025	MSFT baseline
MSB-Isolation64Bit	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main	Isolation64Bit	=	1		M	2022,2025	MSFT baseline
MSB-MpCloudBlockLevel	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: MpEngine: Select cloud protection level	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine	MpCloudBlockLevel	>=	2	0	M	2022,2025	MSFT baseline
MSB-NoCrashDetection	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Turn off Crash Detection	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions	NoCrashDetection	=	1		M	2022,2025	MSFT baseline
MSB-OnlyUseAXISForActiveXInstall	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Specify use of ActiveX Installer Service for installation of ActiveX controls	reg	HKLM:\Software\Policies\Microsoft\Windows\AxInstaller	OnlyUseAXISForActiveXInstall	=	1		M	2022,2025	MSFT baseline
MSB-PUAProtection	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Configure detection for potentially unwanted applications	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	PUAProtection	>=	1	0	M	2022,2025	MSFT baseline;differs-from-CIS
MSB-PlatformRing	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Select the channel for Microsoft Defender monthly platform updates	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	PlatformRing	=	5		M	2025	MSFT baseline
MSB-PreventIgnoreCertErrors	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Prevent ignoring certificate errors	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	PreventIgnoreCertErrors	=	1		M	2022,2025	MSFT baseline
MSB-PreventOverride	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Prevent bypassing SmartScreen Filter warnings	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter	PreventOverride	=	1		M	2022,2025	MSFT baseline
MSB-PreventOverrideAppRepUnknown	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the Internet	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter	PreventOverrideAppRepUnknown	=	1		M	2022,2025	MSFT baseline
MSB-Reserved	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Consistent Mime Handling: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Mime Sniffing Safety Feature: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: MK Protocol Security Restriction: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Notification bar: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#5	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Protection From Zone Elevation: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#6	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict ActiveX Install: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#7	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict File Download: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-Reserved#8	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Scripted Window Security Restrictions: Internet Explorer Processes (Reserved)	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS	(Reserved)	=	1		M	2022,2025	MSFT baseline
MSB-RunInvalidSignatures	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Allow software to run or install even if the signature is invalid	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Download	RunInvalidSignatures	=	0		M	2022,2025	MSFT baseline
MSB-RunThisTimeEnabled	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Add-on Management: Remove 'Run this time' button for outdated ActiveX controls in Internet Explorer	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext	RunThisTimeEnabled	=	0		M	2022,2025	MSFT baseline
MSB-SecureProtocols	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Advanced Page: Turn off encryption support	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	SecureProtocols	=	2560		M	2022,2025	MSFT baseline
MSB-SecurityHKLMonly	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Zones: Use only machine settings	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	Security_HKLM_only	=	1		M	2022,2025	MSFT baseline
MSB-Securityoptionsedit	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Zones: Do not allow users to change policies	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	Security_options_edit	=	1		M	2022,2025	MSFT baseline
MSB-Securityzonesmapedit	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Zones: Do not allow users to add/delete sites	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	Security_zones_map_edit	=	1		M	2022,2025	MSFT baseline
MSB-SignaturesRing	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Select the channel for Microsoft Defender daily security intelligence updates	reg	HKLM:\Software\Policies\Microsoft\Windows Defender	SignaturesRing	=	5		M	2025	MSFT baseline
MSB-SpynetReporting	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: MAPS: Join Microsoft MAPS	reg	HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet	SpynetReporting	=	2	0	M	2022,2025	MSFT baseline;differs-from-CIS
MSB-SubmitSamplesConsent	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: MAPS: Send file samples when further analysis is required	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet	SubmitSamplesConsent	=	1		M	2022,2025	MSFT baseline
MSB-UNCAsIntranet	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Intranet Sites: Include all network paths (UNCs)	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap	UNCAsIntranet	=	0		M	2022,2025	MSFT baseline
MSB-VersionCheckEnabled	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Add-on Management: Turn off blocking of outdated ActiveX controls for Internet Explorer	reg	HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext	VersionCheckEnabled	=	1		M	2022,2025	MSFT baseline
MSB-WarnOnBadCertRecving	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Internet Control Panel: Security Page: Turn on certificate address mismatch warning	reg	HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings	WarnOnBadCertRecving	=	1		M	2022,2025	MSFT baseline
MSB-a8f5898e1dc849a9987885004b8a	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Webshell creation for Servers (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	a8f5898e-1dc8-49a9-9878-85004b8a61e6	=	1	0	M	2025	MSFT baseline
MSB-a8f5898e1dc849a9987885004b8a#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block Webshell creation for Servers	asr	a8f5898e-1dc8-49a9-9878-85004b8a61e6		=	1	0	M	2025	MSFT baseline
MSB-c1db55abc21a4637bb3fa1256810	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Use advanced protection against ransomware (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	c1db55ab-c21a-4637-bb3f-a12568109d35	=	1	0	M	2022,2025	MSFT baseline
MSB-c1db55abc21a4637bb3fa1256810#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Use advanced protection against ransomware	asr	c1db55ab-c21a-4637-bb3f-a12568109d35		=	1	0	M	2022,2025	MSFT baseline
MSB-d1e49aac8f564280b9ba993a6d77	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block process creations originating from PSExec and WMI commands (Policy)	reg	HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\rules	d1e49aac-8f56-4280-b9ba-993a6d77406c	=	0	0	L	2022	MSFT baseline
MSB-d1e49aac8f564280b9ba993a6d77#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Microsoft Defender Antivirus: Microsoft Defender Exploit Guard: ASR: Block process creations originating from PSExec and WMI commands	asr	d1e49aac-8f56-4280-b9ba-993a6d77406c		=	0	0	L	2022	MSFT baseline
MSB-explorerexe	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Consistent Mime Handling: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Mime Sniffing Safety Feature: Internet Explorer Processes explore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: MK Protocol Security Restriction: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Notification bar: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#5	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Protection From Zone Elevation: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#6	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict ActiveX Install: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#7	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict File Download: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-explorerexe#8	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Scripted Window Security Restrictions: Internet Explorer Processes explorer.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS	explorer.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Consistent Mime Handling: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#2	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Mime Sniffing Safety Feature: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#3	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: MK Protocol Security Restriction: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#4	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Notification bar: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#5	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Protection From Zone Elevation: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#6	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict ActiveX Install: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#7	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Restrict File Download: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-iexploreexe#8	MS SECURITY BASELINE: ADMINISTRATIVE TEMPLATES: WINDOWS COMPONENTS	Internet Explorer: Security Features: Scripted Window Security Restrictions: Internet Explorer Processes iexplore.exe	reg	HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS	iexplore.exe	=	1		M	2022,2025	MSFT baseline
MSB-0CCE922F69AE11D9BED350505450	MS SECURITY BASELINE: ADVANCED AUDIT POLICY CONFIGURATION	Audit Policy Change	auditpol	{0CCE922F-69AE-11D9-BED3-505054503030}		=	Success and Failure	Success	L	2025	MSFT baseline;differs-from-CIS
MSB-0CCE923F69AE11D9BED350505450	MS SECURITY BASELINE: ADVANCED AUDIT POLICY CONFIGURATION	Credential Validation	auditpol	{0CCE923F-69AE-11D9-BED3-505054503030}		contains	Failure	No Auditing	L	2022:DC,2025:DC	MSFT baseline;differs-from-CIS
MSB-0CCE924069AE11D9BED350505450	MS SECURITY BASELINE: ADVANCED AUDIT POLICY CONFIGURATION	Kerberos Service Ticket Operations	auditpol	{0CCE9240-69AE-11D9-BED3-505054503030}		contains	Failure	Success	L	2022:DC,2025:DC	MSFT baseline;differs-from-CIS
MSB-InactivityTimeoutSecs	MS SECURITY BASELINE: SECURITY OPTIONS	Interactive logon: Machine inactivity limit	reg	HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System	InactivityTimeoutSecs	=	900	900	L	2022,2025	MSFT baseline;differs-from-CIS
MSB-RestrictSendingNTLMTraffic	MS SECURITY BASELINE: SECURITY OPTIONS	Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers	reg	HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0	RestrictSendingNTLMTraffic	=	1	0	M	2025	MSFT baseline;differs-from-CIS
MSB-SeDenyNetworkLogonRight	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Deny access to this computer from the network	userright	SeDenyNetworkLogonRight		=	NT AUTHORITY\Local account and member of Administrators group	COMPUTERNAME\Guest	M	2022:MS,2025:MS	MSFT baseline;differs-from-CIS
MSB-SeDenyRemoteInteractiveLogon	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Deny log on through Remote Desktop Services	userright	SeDenyRemoteInteractiveLogonRight		=	NT AUTHORITY\Local account		M	2022:MS	MSFT baseline;differs-from-CIS
MSB-SeDenyRemoteInteractiveLogon#2	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Deny log on through Remote Desktop Services	userright	SeDenyRemoteInteractiveLogonRight		=	NT AUTHORITY\Local account and member of Administrators group;BUILTIN\Guests		M	2025:MS	MSFT baseline;differs-from-CIS
MSB-SeImpersonatePrivilege	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Impersonate a client after authentication	userright	SeImpersonatePrivilege		=	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE;RESTRICTED SERVICES\PrintSpoolerService	NT AUTHORITY\SERVICE;BUILTIN\Administrators;NT AUTHORITY\NETWORK SERVICE;NT AUTHORITY\LOCAL SERVICE	M	2025	MSFT baseline;differs-from-CIS
MSB-SeInteractiveLogonRight	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Allow log on locally	userright	SeInteractiveLogonRight		=	NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS;BUILTIN\Administrators	BUILTIN\Backup Operators;BUILTIN\Users;BUILTIN\Administrators;COMPUTERNAME\Guest	M	2025:DC	MSFT baseline;differs-from-CIS
MSB-SeNetworkLogonRight	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Access this computer from the network	userright	SeNetworkLogonRight		=	NT AUTHORITY\Authenticated Users;BUILTIN\Administrators	BUILTIN\Backup Operators;BUILTIN\Users;BUILTIN\Administrators;Everyone	M	2022:MS,2025:MS	MSFT baseline;differs-from-CIS
MSB-SeSecurityPrivilege	MS SECURITY BASELINE: USER RIGHTS ASSIGNMENT	Manage auditing and security log	userright	SeSecurityPrivilege		=		BUILTIN\Administrators	M	2025:DC	MSFT baseline;differs-from-CIS
MSB-DefaultOutboundAction	MS SECURITY BASELINE: WINDOWS FIREWALL	Outbound Connections (Domain Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile	DefaultOutboundAction	=	0	0	M	2022,2025	MSFT baseline
MSB-DefaultOutboundAction#2	MS SECURITY BASELINE: WINDOWS FIREWALL	Outbound Connections (Private Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile	DefaultOutboundAction	=	0	0	M	2022,2025	MSFT baseline
MSB-DefaultOutboundAction#3	MS SECURITY BASELINE: WINDOWS FIREWALL	Outbound Connections (Public Profile, Policy)	reg	HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile	DefaultOutboundAction	=	0	0	M	2022,2025	MSFT baseline
'@


# =============================================================================
#  POSTURE / BUILT-IN HARDENING SCANNER
#
#  The Windows counterpart of RHELGuard's embedded Lynis-equivalent, using the
#  same category codes so reports from the two tools line up:
#  AUTH BOOT CRYP INSE KRNL LOGG MALW PKGS SCHD SHLL STRG TIME TOOL USERS HRDN
#
#  These are posture observations rather than benchmark line items: they catch
#  the things that are wrong in practice but that no single CIS or STIG rule
#  asserts on its own.
# =============================================================================

# Convenience wrapper for the many "one registry value, one verdict" checks.
function Add-WgRegCheck {
    param(
        [string] $Id, [string] $Title, [string] $Category,
        [string] $Path, [string] $Item,
        [string] $Operator = '=', [string] $Expected,
        [string] $Severity = 'Medium',
        [string] $IfAbsent = 'FAIL',      # FAIL | WARN | PASS | INFO
        [string] $AbsentNote = '',
        [string] $Framework = 'POSTURE'
    )
    $actual = Get-WgRegValue $Path $Item
    $rem    = Get-WgRemediation -Method 'reg' -Target $Path -Item $Item `
                  -Operator $Operator -Expected $Expected -Category $Category
    $expText = Format-WgExpectation $Operator $Expected

    if ($null -eq $actual) {
        $note = if ($AbsentNote) { $AbsentNote } else { "Not configured; expected $expText." }
        Add-WgResult -Status $IfAbsent -Id $Id -Title $Title -Category $Category `
            -Framework $Framework -Severity $Severity -Description $note `
            -Remediation $(if ($IfAbsent -eq 'PASS' -or $IfAbsent -eq 'INFO') { '' } else { $rem })
        return
    }
    $ok = Test-WgCompare -Operator $Operator -Actual $actual -Expected $Expected
    Add-WgResult -Status $(if ($ok) { 'PASS' } else { if ($Severity -eq 'Low') { 'WARN' } else { 'FAIL' } }) `
        -Id $Id -Title $Title -Category $Category -Framework $Framework -Severity $Severity `
        -Remediation $(if ($ok) { '' } else { $rem }) `
        -Description $(if ($ok) { "$Item is $actual, as required." }
                       else { "$Item is $actual; expected $expText." })
}

function Invoke-WgPostureChecks {

    # ── AUTH: authentication and credential exposure ─────────────────────────
    Write-WgBanner 'POSTURE - AUTH: credentials & authentication' @(
        'https://itm4n.github.io/lsass-runasppl/'
        'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'
    )

    Add-WgRegCheck -Id 'HRD-AUTH-1' -Title 'WDigest does not cache plaintext credentials' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Item 'UseLogonCredential' -Expected '0' -IfAbsent 'PASS' `
        -AbsentNote ('UseLogonCredential is not set. Windows Server 2012 R2 and later ' +
                     'default to not caching plaintext credentials, so this is safe; ' +
                     'setting it to 0 explicitly prevents a rollback.')

    Add-WgRegCheck -Id 'HRD-AUTH-2' -Title 'LSA runs as a protected process (RunAsPPL)' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Item 'RunAsPPL' `
        -Operator 'in' -Expected '1,2' `
        -AbsentNote ('RunAsPPL is not set, so LSASS is not protected. Credential ' +
                     'dumping tools read LSASS memory directly.')

    Add-WgRegCheck -Id 'HRD-AUTH-3' -Title 'LM password hashes are not stored' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Item 'NoLMHash' -Expected '1' `
        -IfAbsent 'PASS' -AbsentNote 'NoLMHash is not set; Windows has defaulted to 1 since Vista.'

    Add-WgRegCheck -Id 'HRD-AUTH-4' -Title 'LAN Manager authentication level refuses LM and NTLM' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Item 'LmCompatibilityLevel' `
        -Operator '>=' -Expected '5'

    # Cached domain logons are a credential-theft target on servers, which do
    # not need offline logon the way laptops do.
    $cached = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
    if ($null -eq $cached) {
        Add-WgResult -Status 'WARN' -Id 'HRD-AUTH-5' -Title 'Cached interactive logon count' `
            -Category 'AUTH' -Severity 'Low' `
            -Description 'CachedLogonsCount is not set; the Windows default is 10 cached logons.' `
            -Remediation (Get-WgRemediation -Method 'reg' `
                -Target 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
                -Item 'CachedLogonsCount' -Operator '<=' -Expected '4' -Category 'AUTH')
    } else {
        $n = 0; [void][int]::TryParse("$cached", [ref] $n)
        Add-WgResult -Status $(if ($n -le 4) { 'PASS' } else { 'WARN' }) -Id 'HRD-AUTH-5' `
            -Title 'Cached interactive logon count' -Category 'AUTH' -Severity 'Low' `
            -Description "CachedLogonsCount is $n (CIS allows up to 4 on servers)." `
            -Remediation $(if ($n -le 4) { '' } else {
                "Set CachedLogonsCount to 4 or lower (0 on domain controllers)." })
    }

    # Autologon stores the password in the clear in the registry.
    $autoLogon = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    $defaultPw = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
    if ("$autoLogon" -eq '1' -or $null -ne $defaultPw) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-AUTH-6' -Title 'Automatic logon is configured' `
            -Category 'AUTH' -Severity 'High' `
            -Description ('Automatic logon is enabled or a DefaultPassword value is present. ' +
                          'The password is stored unencrypted and is readable by any local user.') `
            -Remediation ('Remove-ItemProperty -Path ' +
                          "'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' " +
                          "-Name DefaultPassword,AutoAdminLogon -Force")
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-AUTH-6' -Title 'Automatic logon is not configured' `
            -Category 'AUTH' -Severity 'High' `
            -Description 'No AutoAdminLogon or stored DefaultPassword was found.'
    }

    # LAPS removes the shared-local-admin-password problem entirely.
    $lapsNew = Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
    $lapsOld = (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS')
    if ($lapsNew -or $lapsOld) {
        Add-WgResult -Status 'PASS' -Id 'HRD-AUTH-7' -Title 'Local administrator password management (LAPS)' `
            -Category 'AUTH' -Severity 'Medium' `
            -Description ('LAPS policy is present (' +
                          $(if ($lapsNew) { 'Windows LAPS' } else { 'legacy Microsoft LAPS' }) + ').')
    } else {
        Add-WgResult -Status 'WARN' -Id 'HRD-AUTH-7' -Title 'Local administrator password management (LAPS)' `
            -Category 'AUTH' -Severity 'Medium' `
            -Description ('No LAPS policy found. Without it, local administrator passwords ' +
                          'are typically shared across hosts, which turns one compromise into many.') `
            -Remediation 'Deploy Windows LAPS (built in from Server 2019 with April 2023 updates)'
    }

    # ── UAC ──────────────────────────────────────────────────────────────────
    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Add-WgRegCheck -Id 'HRD-AUTH-8' -Title 'User Account Control is enabled' `
        -Category 'AUTH' -Severity 'High' -Path $uacPath -Item 'EnableLUA' -Expected '1' `
        -AbsentNote 'EnableLUA is not set; UAC may be disabled.'
    Add-WgRegCheck -Id 'HRD-AUTH-9' -Title 'UAC prompts administrators on the secure desktop' `
        -Category 'AUTH' -Severity 'Medium' -Path $uacPath -Item 'PromptOnSecureDesktop' -Expected '1'
    Add-WgRegCheck -Id 'HRD-AUTH-10' -Title 'UAC applies to the built-in Administrator account' `
        -Category 'AUTH' -Severity 'Medium' -Path $uacPath -Item 'FilterAdministratorToken' -Expected '1'
    Add-WgRegCheck -Id 'HRD-AUTH-11' -Title 'Anonymous enumeration of SAM accounts is restricted' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Item 'RestrictAnonymousSAM' -Expected '1'
    Add-WgRegCheck -Id 'HRD-AUTH-12' -Title 'Anonymous users are not granted Everyone permissions' `
        -Category 'AUTH' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Item 'EveryoneIncludesAnonymous' -Expected '0' `
        -IfAbsent 'PASS' -AbsentNote 'Not set; the Windows default of 0 is compliant.'

    # ── USERS: local account hygiene ─────────────────────────────────────────
    Write-WgBanner 'POSTURE - USERS: local account hygiene' @(
        'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview'
    )

    $locals = Get-WgWmi -Class Win32_UserAccount -Filter "LocalAccount=True"
    if ($locals) {
        $neverExpire = @($locals | Where-Object { $_.PasswordExpires -eq $false -and $_.Disabled -eq $false })
        if ($neverExpire.Count -gt 0) {
            Add-WgResult -Status 'WARN' -Id 'HRD-USERS-1' -Title 'Enabled local accounts with non-expiring passwords' `
                -Category 'USERS' -Severity 'Medium' `
                -Description ("$($neverExpire.Count) enabled local account(s) have a password that never expires: " +
                              (($neverExpire | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', ') + '.') `
                -Remediation 'Set-LocalUser -Name <name> -PasswordNeverExpires $false'
        } else {
            Add-WgResult -Status 'PASS' -Id 'HRD-USERS-1' -Title 'Enabled local accounts with non-expiring passwords' `
                -Category 'USERS' -Severity 'Medium' `
                -Description 'No enabled local account has a non-expiring password.'
        }

        $noPwReq = @($locals | Where-Object { $_.PasswordRequired -eq $false -and $_.Disabled -eq $false })
        if ($noPwReq.Count -gt 0) {
            Add-WgResult -Status 'FAIL' -Id 'HRD-USERS-2' -Title 'Enabled local accounts that do not require a password' `
                -Category 'USERS' -Severity 'High' `
                -Description ("$($noPwReq.Count) enabled local account(s) do not require a password: " +
                              (($noPwReq | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', ') + '.') `
                -Remediation 'Set-LocalUser -Name <name> -PasswordRequired $true, or disable the account'
        } else {
            Add-WgResult -Status 'PASS' -Id 'HRD-USERS-2' -Title 'Enabled local accounts that do not require a password' `
                -Category 'USERS' -Severity 'High' `
                -Description 'Every enabled local account requires a password.'
        }

        Add-WgResult -Status 'INFO' -Id 'HRD-USERS-3' -Title 'Local account inventory' `
            -Category 'USERS' -Severity 'Low' `
            -Description ("$(@($locals).Count) local account(s), of which " +
                          "$(@($locals | Where-Object { -not $_.Disabled }).Count) are enabled.")
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-USERS-1' -Title 'Local account hygiene' `
            -Category 'USERS' -Severity 'Medium' `
            -Description 'Win32_UserAccount could not be enumerated on this host.'
    }

    # Membership of the local Administrators group, read through ADSI so it
    # works without the LocalAccounts module and without a domain lookup.
    try {
        $grp = [ADSI] "WinNT://./Administrators,group"
        $members = @($grp.psbase.Invoke('Members') | ForEach-Object {
            try { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) } catch { }
        } | Where-Object { $_ })
        $status = if ($members.Count -le 3) { 'PASS' } elseif ($members.Count -le 6) { 'WARN' } else { 'FAIL' }
        Add-WgResult -Status $status -Id 'HRD-USERS-4' -Title 'Local Administrators group membership' `
            -Category 'USERS' -Severity 'Medium' `
            -Description ("The local Administrators group has $($members.Count) member(s): " +
                          (($members | Select-Object -First 10) -join ', ') + '.') `
            -Remediation $(if ($status -eq 'PASS') { '' } else {
                'Review membership; keep local administrator rights to the minimum set of accounts and groups.' })
    } catch {
        Add-WgResult -Status 'SKIP' -Id 'HRD-USERS-4' -Title 'Local Administrators group membership' `
            -Category 'USERS' -Severity 'Medium' -Description 'The Administrators group could not be enumerated.'
    }

    # ── BOOT: platform integrity ─────────────────────────────────────────────
    Write-WgBanner 'POSTURE - BOOT: platform & boot integrity' @(
        'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot'
    )

    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        $sb = $null
        try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
        if ($null -eq $sb) {
            Add-WgResult -Status 'WARN' -Id 'HRD-BOOT-1' -Title 'Secure Boot' -Category 'BOOT' `
                -Severity 'Medium' `
                -Description ('Secure Boot state could not be read. This is expected on a ' +
                              'legacy BIOS/CSM system, which cannot offer Secure Boot at all.') `
                -Remediation 'Convert the system disk to GPT/UEFI (MBR2GPT) and enable Secure Boot in firmware'
        } else {
            Add-WgResult -Status $(if ($sb) { 'PASS' } else { 'FAIL' }) -Id 'HRD-BOOT-1' `
                -Title 'Secure Boot' -Category 'BOOT' -Severity 'Medium' `
                -Description "Secure Boot is $(if ($sb) { 'enabled' } else { 'disabled' })." `
                -Remediation $(if ($sb) { '' } else { 'Enable Secure Boot in the UEFI firmware settings' })
        }
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-BOOT-1' -Title 'Secure Boot' -Category 'BOOT' `
            -Severity 'Medium' -Description 'Confirm-SecureBootUEFI is not available on this Windows version.'
    }

    $tpm = Get-WgWmi -Class Win32_Tpm -Namespace 'root\cimv2\security\microsofttpm'
    if ($tpm) {
        $ready = ($tpm.IsEnabled_InitialValue -eq $true -and $tpm.IsActivated_InitialValue -eq $true)
        Add-WgResult -Status $(if ($ready) { 'PASS' } else { 'WARN' }) -Id 'HRD-BOOT-2' `
            -Title 'TPM present and ready' -Category 'BOOT' -Severity 'Medium' `
            -Description ("TPM found (spec $($tpm.SpecVersion)); enabled=$($tpm.IsEnabled_InitialValue), " +
                          "activated=$($tpm.IsActivated_InitialValue).") `
            -Remediation $(if ($ready) { '' } else { 'Enable and activate the TPM in firmware' })
    } else {
        Add-WgResult -Status 'WARN' -Id 'HRD-BOOT-2' -Title 'TPM present and ready' -Category 'BOOT' `
            -Severity 'Medium' `
            -Description ('No TPM was detected. BitLocker without a TPM, Credential Guard and ' +
                          'measured boot all depend on one.') `
            -Remediation 'Provision a TPM 2.0 (or enable the firmware TPM / PTT / fTPM)'
    }

    Add-WgRegCheck -Id 'HRD-BOOT-3' -Title 'Early Launch Antimalware boot-start driver policy' `
        -Category 'BOOT' -Severity 'Medium' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Item 'DriverLoadPolicy' `
        -Operator 'in' -Expected '1,3,8' -IfAbsent 'WARN' `
        -AbsentNote ('DriverLoadPolicy is not set; the Windows default (3) still blocks ' +
                     'known-bad boot drivers. Set it explicitly to lock the behaviour in.')

    if (Test-WgNeedsAdmin 'HRD-BOOT-4' 'Boot configuration (NX, test signing, kernel debug)' 'BOOT') {
        $bcd = & bcdedit.exe /enum '{current}' 2>$null | Out-String
        if ($bcd -and $bcd.Trim()) {
            $issues = @()
            if ($bcd -match '(?im)^\s*nx\s+(\S+)') {
                $nx = $Matches[1]
                if ($nx -notmatch 'AlwaysOn|OptOut') { $issues += "nx is '$nx' (should be OptOut or AlwaysOn)" }
            }
            if ($bcd -match '(?im)^\s*testsigning\s+Yes') { $issues += 'test signing is enabled (unsigned drivers can load)' }
            if ($bcd -match '(?im)^\s*debug\s+Yes')       { $issues += 'kernel debugging is enabled' }
            if ($bcd -match '(?im)^\s*integrityservices\s+Disable') { $issues += 'integrity services are disabled' }

            if ($issues.Count -gt 0) {
                Add-WgResult -Status 'FAIL' -Id 'HRD-BOOT-4' `
                    -Title 'Boot configuration (NX, test signing, kernel debug)' -Category 'BOOT' `
                    -Severity 'High' -Description ('Boot configuration weakens kernel protection: ' +
                                                   ($issues -join '; ') + '.') `
                    -Remediation 'bcdedit /set nx OptOut ; bcdedit /set testsigning off ; bcdedit /debug off'
            } else {
                Add-WgResult -Status 'PASS' -Id 'HRD-BOOT-4' `
                    -Title 'Boot configuration (NX, test signing, kernel debug)' -Category 'BOOT' `
                    -Severity 'High' `
                    -Description 'NX is enforced; test signing and kernel debugging are off.'
            }
        } else {
            Add-WgResult -Status 'SKIP' -Id 'HRD-BOOT-4' `
                -Title 'Boot configuration (NX, test signing, kernel debug)' -Category 'BOOT' `
                -Severity 'High' -Description 'bcdedit produced no output on this host.'
        }
    }

    # ── CRYP: TLS, cipher suites, FIPS ───────────────────────────────────────
    Write-WgBanner 'POSTURE - CRYP: protocols & cipher suites' @(
        'https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings'
        'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls'
    )

    $schannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    $weakProtos = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
    $i = 0
    foreach ($proto in $weakProtos) {
        $i++
        foreach ($role in @('Server', 'Client')) {
            $p = "$schannel\Protocols\$proto\$role"
            $enabled   = Get-WgRegValue $p 'Enabled'
            $disabledD = Get-WgRegValue $p 'DisabledByDefault'
            $id = "HRD-CRYP-$i-$($role.Substring(0,1))"
            $t  = "$proto ($role) is disabled"

            if ("$enabled" -eq '0') {
                Add-WgResult -Status 'PASS' -Id $id -Title $t -Category 'CRYP' -Severity 'High' `
                    -Description "$proto $role is explicitly disabled (Enabled = 0)."
            } elseif ($null -eq $enabled -and "$disabledD" -eq '1') {
                Add-WgResult -Status 'WARN' -Id $id -Title $t -Category 'CRYP' -Severity 'High' `
                    -Description ("$proto $role is off by default (DisabledByDefault = 1) but not " +
                                  'hard-disabled, so an application can still negotiate it.') `
                    -Remediation ("New-Item -Path '$p' -Force | Out-Null; New-ItemProperty -Path '$p' " +
                                  "-Name Enabled -PropertyType DWord -Value 0 -Force")
            } elseif ($null -eq $enabled) {
                Add-WgResult -Status 'FAIL' -Id $id -Title $t -Category 'CRYP' -Severity 'High' `
                    -Description "$proto $role is not disabled; no SCHANNEL override is present." `
                    -Remediation ("New-Item -Path '$p' -Force | Out-Null; New-ItemProperty -Path '$p' " +
                                  "-Name Enabled -PropertyType DWord -Value 0 -Force; New-ItemProperty " +
                                  "-Path '$p' -Name DisabledByDefault -PropertyType DWord -Value 1 -Force")
            } else {
                Add-WgResult -Status 'FAIL' -Id $id -Title $t -Category 'CRYP' -Severity 'High' `
                    -Description "$proto $role is explicitly enabled (Enabled = $enabled)." `
                    -Remediation ("Set-ItemProperty -Path '$p' -Name Enabled -Value 0")
            }
        }
    }

    # TLS 1.2 must stay available, or disabling the weak protocols breaks the host
    $tls12 = Get-WgRegValue "$schannel\Protocols\TLS 1.2\Server" 'Enabled'
    Add-WgResult -Status $(if ($null -eq $tls12 -or "$tls12" -ne '0') { 'PASS' } else { 'FAIL' }) `
        -Id 'HRD-CRYP-5' -Title 'TLS 1.2 (Server) remains enabled' -Category 'CRYP' -Severity 'High' `
        -Description $(if ($null -eq $tls12) { 'TLS 1.2 is enabled by default (no override present).' }
                       elseif ("$tls12" -ne '0') { "TLS 1.2 is enabled (Enabled = $tls12)." }
                       else { 'TLS 1.2 is explicitly DISABLED, which leaves no secure protocol available.' }) `
        -Remediation $(if ($null -eq $tls12 -or "$tls12" -ne '0') { '' } else {
            "Set-ItemProperty -Path '$schannel\Protocols\TLS 1.2\Server' -Name Enabled -Value 1" })

    $weakCiphers = @('RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'DES 56/56', 'NULL')
    $cipherBad = @()
    $cipherOk  = @()
    foreach ($c in $weakCiphers) {
        $v = Get-WgRegValue "$schannel\Ciphers\$c" 'Enabled'
        if ("$v" -eq '0') { $cipherOk += $c } else { $cipherBad += $c }
    }
    if ($cipherBad.Count -gt 0) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-CRYP-6' -Title 'Weak SCHANNEL ciphers are disabled' `
            -Category 'CRYP' -Severity 'High' `
            -Description ("$($cipherBad.Count) of $($weakCiphers.Count) weak cipher(s) are not " +
                          "explicitly disabled: $($cipherBad -join ', ').") `
            -Remediation ("For each: New-Item -Path '$schannel\Ciphers\<cipher>' -Force; " +
                          'New-ItemProperty -Path ... -Name Enabled -PropertyType DWord -Value 0 -Force')
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-CRYP-6' -Title 'Weak SCHANNEL ciphers are disabled' `
            -Category 'CRYP' -Severity 'High' `
            -Description 'RC4, single DES and NULL ciphers are all explicitly disabled.'
    }

    Add-WgRegCheck -Id 'HRD-CRYP-7' -Title 'Triple DES is disabled' -Category 'CRYP' -Severity 'Medium' `
        -Path "$schannel\Ciphers\Triple DES 168" -Item 'Enabled' -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote '3DES is not explicitly disabled; it is a 64-bit block cipher and is deprecated.'

    Add-WgRegCheck -Id 'HRD-CRYP-8' -Title 'MD5 hashing is disabled in SCHANNEL' -Category 'CRYP' `
        -Severity 'Medium' -Path "$schannel\Hashes\MD5" -Item 'Enabled' -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote 'MD5 is not explicitly disabled for SCHANNEL.'

    $fips = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' 'Enabled'
    Add-WgResult -Status $(if ("$fips" -eq '1') { 'PASS' } else { 'INFO' }) -Id 'HRD-CRYP-9' `
        -Title 'FIPS 140 algorithm policy' -Category 'CRYP' -Severity 'Low' `
        -Description $(if ("$fips" -eq '1') { 'FIPS mode is enabled.' } else {
            ('FIPS mode is not enabled. This is only required where policy mandates ' +
             'FIPS 140-validated cryptography; it is reported for information.') })

    foreach ($net in @(
        @{ Id = 'HRD-CRYP-10'; Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; Label = '64-bit' },
        @{ Id = 'HRD-CRYP-11'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Label = '32-bit' })) {
        Add-WgRegCheck -Id $net.Id -Title ".NET Framework 4.x uses strong crypto ($($net.Label))" `
            -Category 'CRYP' -Severity 'Medium' -Path $net.Path -Item 'SchUseStrongCrypto' -Expected '1' `
            -IfAbsent 'WARN' `
            -AbsentNote ('SchUseStrongCrypto is not set, so .NET applications may still negotiate ' +
                         'TLS 1.0 regardless of the SCHANNEL settings.')
    }

    # ── KRNL: exploit mitigations and kernel protection ──────────────────────
    Write-WgBanner 'POSTURE - KRNL: kernel & exploit mitigations' @(
        'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        'https://itm4n.github.io/printnightmare-exploitation/'
    )

    $dg = Get-WgWmi -Class Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    if ($dg) {
        $running = @($dg.SecurityServicesRunning)
        $vbs     = "$($dg.VirtualizationBasedSecurityStatus)"
        Add-WgResult -Status $(if ($vbs -eq '2') { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-1' `
            -Title 'Virtualization-based security (VBS) is running' -Category 'KRNL' -Severity 'Medium' `
            -Description ("VBS status is $vbs (2 = running). Security services running: " +
                          $(if ($running.Count) { $running -join ', ' } else { 'none' }) + '.') `
            -Remediation $(if ($vbs -eq '2') { '' } else {
                'Enable VBS: Device Guard policy plus hypervisor support in firmware' })

        Add-WgResult -Status $(if ($running -contains 1) { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-2' `
            -Title 'Credential Guard is running' -Category 'KRNL' -Severity 'Medium' `
            -Description $(if ($running -contains 1) { 'Credential Guard is running.' } else {
                'Credential Guard is not running; domain credentials are not isolated from LSASS.' }) `
            -Remediation $(if ($running -contains 1) { '' } else {
                'Enable Credential Guard via Device Guard policy (requires VBS and Secure Boot)' })

        Add-WgResult -Status $(if ($running -contains 2) { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-3' `
            -Title 'Hypervisor-enforced code integrity (HVCI) is running' -Category 'KRNL' `
            -Severity 'Medium' `
            -Description $(if ($running -contains 2) { 'HVCI is running.' } else {
                'HVCI is not running; unsigned or malicious kernel code is not blocked by the hypervisor.' }) `
            -Remediation $(if ($running -contains 2) { '' } else {
                'Enable Memory Integrity / HVCI via Device Guard policy' })
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-KRNL-1' -Title 'Virtualization-based security (VBS)' `
            -Category 'KRNL' -Severity 'Medium' `
            -Description 'Win32_DeviceGuard is not present (Windows Server 2016 and later only).'
    }

    Add-WgRegCheck -Id 'HRD-KRNL-4' -Title 'SEHOP (structured exception handling overwrite protection)' `
        -Category 'KRNL' -Severity 'Medium' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
        -Item 'DisableExceptionChainValidation' -Expected '0' -IfAbsent 'PASS' `
        -AbsentNote 'Not set; SEHOP is enabled by default on Windows Server 2012 and later.'

    Add-WgRegCheck -Id 'HRD-KRNL-5' -Title 'Mandatory ASLR (image randomisation)' -Category 'KRNL' `
        -Severity 'Low' -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Item 'MoveImages' -Operator '!=' -Expected '0' -IfAbsent 'PASS' `
        -AbsentNote 'MoveImages is not set; ASLR applies to opted-in images by default.'

    Add-WgRegCheck -Id 'HRD-KRNL-6' -Title 'Kernel DMA protection (external DMA under lock)' `
        -Category 'KRNL' -Severity 'Medium' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity' -Item 'AllowDmaUnderLock' `
        -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote ('AllowDmaUnderLock is not set. On a host with external PCIe or Thunderbolt ' +
                     'ports, a DMA-capable device can read memory while the console is locked.')

    Add-WgRegCheck -Id 'HRD-KRNL-7' -Title 'Point and Print driver installation restricted to administrators' `
        -Category 'KRNL' -Severity 'High' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' `
        -Item 'RestrictDriverInstallationToAdministrators' -Expected '1' `
        -AbsentNote ('Not set. This is the PrintNightmare (CVE-2021-34527) mitigation: without it ' +
                     'a non-administrator can install a printer driver and run code as SYSTEM.')

    # ── Signing: SMB and LDAP ────────────────────────────────────────────────
    Write-WgBanner 'POSTURE - HRDN: SMB & LDAP signing' @(
        'https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102'
        'https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-f7bc2dc0'
    )

    Add-WgRegCheck -Id 'HRD-HRDN-1' -Title 'SMB server requires packet signing' -Category 'HRDN' `
        -Severity 'High' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
        -Item 'RequireSecuritySignature' -Expected '1'
    Add-WgRegCheck -Id 'HRD-HRDN-2' -Title 'SMB client requires packet signing' -Category 'HRDN' `
        -Severity 'High' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Item 'RequireSecuritySignature' -Expected '1'
    Add-WgRegCheck -Id 'HRD-HRDN-3' -Title 'LDAP client signing is required' -Category 'HRDN' `
        -Severity 'High' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' `
        -Item 'LDAPClientIntegrity' -Expected '2' `
        -AbsentNote ('LDAPClientIntegrity is not set; the default (1 = negotiate) allows an ' +
                     'unsigned LDAP bind, which is relay-able.')

    if ($script:IsDC) {
        Add-WgRegCheck -Id 'HRD-HRDN-4' -Title 'Domain controller requires LDAP server signing' `
            -Category 'HRDN' -Severity 'High' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Item 'LDAPServerIntegrity' -Expected '2'
        Add-WgRegCheck -Id 'HRD-HRDN-5' -Title 'Domain controller enforces LDAP channel binding' `
            -Category 'HRDN' -Severity 'High' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Item 'LdapEnforceChannelBinding' -Expected '2'
    }

    Add-WgRegCheck -Id 'HRD-HRDN-6' -Title 'Null session pipes are not configured' -Category 'HRDN' `
        -Severity 'Medium' -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
        -Item 'NullSessionPipes' -Expected '' -IfAbsent 'PASS' `
        -AbsentNote 'No NullSessionPipes value is present, so no pipe allows anonymous access.'
    Add-WgRegCheck -Id 'HRD-HRDN-7' -Title 'Anonymous access to named pipes and shares is restricted' `
        -Category 'HRDN' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
        -Item 'RestrictNullSessAccess' -Expected '1'

    # ── INSE: insecure services and legacy protocols ─────────────────────────
    Write-WgBanner 'POSTURE - INSE: insecure services & legacy protocols' @(
        'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
        'https://luemmelsec.github.io/Relaying-101/'
    )

    $smb1Reg  = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    $mrxsmb10 = Get-WgServiceStart 'mrxsmb10'
    $feat     = Get-WgFeatures
    $smb1Feat = if ($feat.ContainsKey('fs-smb1')) { $feat['fs-smb1'] } else { $null }
    $smb1Off  = ("$smb1Reg" -eq '0') -or ($mrxsmb10 -eq 'Disabled') -or ($smb1Feat -eq $false)
    Add-WgResult -Status $(if ($smb1Off) { 'PASS' } else { 'FAIL' }) -Id 'HRD-INSE-1' `
        -Title 'SMBv1 is disabled' -Category 'INSE' -Severity 'High' `
        -Description ("SMB1 registry value = $(if ($null -eq $smb1Reg) { '(absent)' } else { $smb1Reg }); " +
                      "mrxsmb10 start type = $(if ($mrxsmb10) { $mrxsmb10 } else { 'not installed' }); " +
                      "FS-SMB1 feature installed = $(if ($null -eq $smb1Feat) { 'unknown' } else { $smb1Feat }).") `
        -Remediation $(if ($smb1Off) { '' } else {
            'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, or Uninstall-WindowsFeature FS-SMB1 -Remove' })

    $psv2 = $null
    if ($feat.ContainsKey('powershell-v2')) { $psv2 = $feat['powershell-v2'] }
    if ($psv2 -eq $true) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-INSE-2' -Title 'PowerShell 2.0 engine is not installed' `
            -Category 'INSE' -Severity 'High' `
            -Description ('The PowerShell 2.0 engine is installed. It bypasses script block ' +
                          'logging, AMSI and constrained language mode, so it is a standard ' +
                          'downgrade target.') `
            -Remediation 'Uninstall-WindowsFeature PowerShell-v2'
    } elseif ($psv2 -eq $false) {
        Add-WgResult -Status 'PASS' -Id 'HRD-INSE-2' -Title 'PowerShell 2.0 engine is not installed' `
            -Category 'INSE' -Severity 'High' -Description 'The PowerShell 2.0 engine is not installed.'
    } else {
        Add-WgResult -Status 'INFO' -Id 'HRD-INSE-2' -Title 'PowerShell 2.0 engine is not installed' `
            -Category 'INSE' -Severity 'High' `
            -Description 'The PowerShell 2.0 feature state could not be determined on this SKU.'
    }

    # Services that should not be running on a hardened server
    $riskyServices = @(
        @{ Name = 'TlntSvr';     Label = 'Telnet Server';            Sev = 'High' }
        @{ Name = 'FTPSVC';      Label = 'FTP Server (IIS)';         Sev = 'Medium' }
        @{ Name = 'SNMP';        Label = 'SNMP Service';             Sev = 'Medium' }
        @{ Name = 'RemoteRegistry'; Label = 'Remote Registry';       Sev = 'Medium' }
        @{ Name = 'SharedAccess'; Label = 'Internet Connection Sharing'; Sev = 'Medium' }
        @{ Name = 'SSDPSRV';     Label = 'SSDP Discovery';           Sev = 'Low' }
        @{ Name = 'upnphost';    Label = 'UPnP Device Host';         Sev = 'Medium' }
        @{ Name = 'WMPNetworkSvc'; Label = 'Windows Media Player Network Sharing'; Sev = 'Low' }
        @{ Name = 'RasMan';      Label = 'Remote Access Connection Manager'; Sev = 'Low' }
        @{ Name = 'SessionEnv';  Label = 'Remote Desktop Configuration'; Sev = 'Low' }
        @{ Name = 'Browser';     Label = 'Computer Browser (legacy)'; Sev = 'Low' }
        @{ Name = 'LxssManager'; Label = 'Windows Subsystem for Linux'; Sev = 'Medium' }
    )
    $n = 2
    foreach ($svc in $riskyServices) {
        $n++
        $start = Get-WgServiceStart $svc.Name
        $id    = "HRD-INSE-$n"
        $t     = "$($svc.Label) is not enabled"
        if ($null -eq $start) {
            Add-WgResult -Status 'PASS' -Id $id -Title $t -Category 'INSE' -Severity $svc.Sev `
                -Description "$($svc.Label) ($($svc.Name)) is not installed."
        } elseif ($start -eq 'Disabled') {
            Add-WgResult -Status 'PASS' -Id $id -Title $t -Category 'INSE' -Severity $svc.Sev `
                -Description "$($svc.Label) ($($svc.Name)) is installed but disabled."
        } else {
            $running = Test-WgServiceRunning $svc.Name
            Add-WgResult -Status $(if ($svc.Sev -eq 'Low') { 'WARN' } else { 'FAIL' }) -Id $id `
                -Title $t -Category 'INSE' -Severity $svc.Sev `
                -Description ("$($svc.Label) ($($svc.Name)) start type is $start" +
                              $(if ($running) { ' and it is running' } else { '' }) + '.') `
                -Remediation "Set-Service -Name $($svc.Name) -StartupType Disabled; Stop-Service $($svc.Name)"
        }
    }

    # Print Spooler: a running spooler is the PrintNightmare attack surface, but
    # it is legitimately required on a print server, so this is a warning.
    $spooler = Get-WgServiceStart 'Spooler'
    if ($spooler -and $spooler -ne 'Disabled') {
        Add-WgResult -Status 'WARN' -Id 'HRD-INSE-20' -Title 'Print Spooler service' -Category 'INSE' `
            -Severity 'Medium' `
            -Description ("The Print Spooler is enabled (start type $spooler). Unless this host is a " +
                          'print server, disabling it removes a long-running class of ' +
                          'local-privilege-escalation and RCE bugs.') `
            -Remediation 'Set-Service -Name Spooler -StartupType Disabled; Stop-Service Spooler'
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-INSE-20' -Title 'Print Spooler service' -Category 'INSE' `
            -Severity 'Medium' -Description 'The Print Spooler is disabled or not installed.'
    }

    Add-WgRegCheck -Id 'HRD-INSE-21' -Title 'LLMNR (multicast name resolution) is disabled' `
        -Category 'INSE' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Item 'EnableMulticast' `
        -Expected '0' `
        -AbsentNote ('LLMNR is not disabled. It is trivially spoofable on a local network and is ' +
                     'the usual first step in an NTLM relay chain.')

    Add-WgRegCheck -Id 'HRD-INSE-22' -Title 'mDNS is disabled' -Category 'INSE' -Severity 'Low' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Item 'EnableMDNS' `
        -Expected '0' -IfAbsent 'WARN' -AbsentNote 'EnableMDNS is not set to 0; mDNS responds to multicast name queries.'

    Add-WgRegCheck -Id 'HRD-INSE-23' -Title 'WPAD auto-detection is disabled' -Category 'INSE' `
        -Severity 'Medium' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' `
        -Item 'EnableActiveProbing' -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote 'Active probing is not disabled; WPAD discovery can be hijacked to supply a rogue proxy.'

    # NetBIOS over TCP/IP, per interface
    $nbtRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    try {
        $ifs = @(Get-ChildItem -LiteralPath $nbtRoot -ErrorAction Stop)
        $nbtOn = @($ifs | Where-Object { "$(Get-WgRegValue $_.PSPath 'NetbiosOptions')" -ne '2' })
        if ($ifs.Count -eq 0) {
            Add-WgResult -Status 'INFO' -Id 'HRD-INSE-24' -Title 'NetBIOS over TCP/IP is disabled' `
                -Category 'INSE' -Severity 'Medium' -Description 'No NetBT interfaces were found.'
        } elseif ($nbtOn.Count -eq 0) {
            Add-WgResult -Status 'PASS' -Id 'HRD-INSE-24' -Title 'NetBIOS over TCP/IP is disabled' `
                -Category 'INSE' -Severity 'Medium' `
                -Description "NetBIOS over TCP/IP is disabled on all $($ifs.Count) interface(s)."
        } else {
            Add-WgResult -Status 'FAIL' -Id 'HRD-INSE-24' -Title 'NetBIOS over TCP/IP is disabled' `
                -Category 'INSE' -Severity 'Medium' `
                -Description ("NetBIOS over TCP/IP is still enabled on $($nbtOn.Count) of " +
                              "$($ifs.Count) interface(s). NBT-NS is spoofable and is used for NTLM relay.") `
                -Remediation ("Set NetbiosOptions to 2 under $nbtRoot\<interface>, " +
                              'or clear "Enable NetBIOS over TCP/IP" on each adapter')
        }
    } catch {
        Add-WgResult -Status 'SKIP' -Id 'HRD-INSE-24' -Title 'NetBIOS over TCP/IP is disabled' `
            -Category 'INSE' -Severity 'Medium' -Description 'NetBT interface configuration could not be read.'
    }

    Add-WgRegCheck -Id 'HRD-INSE-25' -Title 'AlwaysInstallElevated is not enabled (machine)' `
        -Category 'INSE' -Severity 'High' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Item 'AlwaysInstallElevated' `
        -Expected '0' -IfAbsent 'PASS' `
        -AbsentNote 'Not set, so MSI packages do not install with elevated privileges.'

    # WinRM transport security
    $winrmSvc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    Add-WgRegCheck -Id 'HRD-INSE-26' -Title 'WinRM service does not allow unencrypted traffic' `
        -Category 'INSE' -Severity 'High' -Path $winrmSvc -Item 'AllowUnencryptedTraffic' `
        -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote 'Not set by policy; verify that WinRM is not configured to allow unencrypted traffic.'
    Add-WgRegCheck -Id 'HRD-INSE-27' -Title 'WinRM service does not allow Basic authentication' `
        -Category 'INSE' -Severity 'High' -Path $winrmSvc -Item 'AllowBasic' -Expected '0' `
        -IfAbsent 'WARN' -AbsentNote 'Not set by policy; Basic authentication sends credentials with no protection beyond the transport.'

    # RDP, where it is enabled
    $denyTs = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ("$denyTs" -eq '0') {
        $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        Add-WgRegCheck -Id 'HRD-INSE-28' -Title 'RDP requires Network Level Authentication' `
            -Category 'INSE' -Severity 'High' -Path $rdp -Item 'UserAuthentication' -Expected '1' `
            -AbsentNote 'NLA is not enforced; RDP will accept a session before the user authenticates.'
        Add-WgRegCheck -Id 'HRD-INSE-29' -Title 'RDP uses TLS as its security layer' -Category 'INSE' `
            -Severity 'High' -Path $rdp -Item 'SecurityLayer' -Expected '2' `
            -AbsentNote 'SecurityLayer is not set to 2 (TLS); RDP may fall back to the legacy RDP protocol.'
        Add-WgRegCheck -Id 'HRD-INSE-30' -Title 'RDP uses high encryption' -Category 'INSE' `
            -Severity 'Medium' -Path $rdp -Item 'MinEncryptionLevel' -Operator '>=' -Expected '3'
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-INSE-28' -Title 'Remote Desktop is disabled' `
            -Category 'INSE' -Severity 'High' `
            -Description 'fDenyTSConnections is not 0, so inbound Remote Desktop is disabled.'
    }

    # ── MALW: anti-malware ───────────────────────────────────────────────────
    Write-WgBanner 'POSTURE - MALW: anti-malware' @(
        'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction'
    )

    $mp = $null
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }
    }
    if ($mp) {
        Add-WgResult -Status $(if ($mp.RealTimeProtectionEnabled) { 'PASS' } else { 'FAIL' }) `
            -Id 'HRD-MALW-1' -Title 'Defender real-time protection is enabled' -Category 'MALW' `
            -Severity 'High' `
            -Description "RealTimeProtectionEnabled = $($mp.RealTimeProtectionEnabled)." `
            -Remediation $(if ($mp.RealTimeProtectionEnabled) { '' } else {
                'Set-MpPreference -DisableRealtimeMonitoring $false' })

        Add-WgResult -Status $(if ($mp.AntivirusEnabled) { 'PASS' } else { 'FAIL' }) -Id 'HRD-MALW-2' `
            -Title 'Defender antivirus engine is enabled' -Category 'MALW' -Severity 'High' `
            -Description ("AntivirusEnabled = $($mp.AntivirusEnabled); engine " +
                          "$($mp.AMEngineVersion); AMServiceEnabled = $($mp.AMServiceEnabled).")

        if ($null -ne $mp.IsTamperProtected) {
            Add-WgResult -Status $(if ($mp.IsTamperProtected) { 'PASS' } else { 'WARN' }) `
                -Id 'HRD-MALW-3' -Title 'Defender tamper protection is enabled' -Category 'MALW' `
                -Severity 'Medium' -Description "IsTamperProtected = $($mp.IsTamperProtected)." `
                -Remediation $(if ($mp.IsTamperProtected) { '' } else {
                    'Enable tamper protection via Microsoft Defender for Endpoint or Intune' })
        }

        # Signature age is the single most important Defender metric in an
        # air-gapped enclave, where definitions do not update themselves.
        if ($mp.AntivirusSignatureLastUpdated) {
            $age = [int] ((Get-Date) - [datetime] $mp.AntivirusSignatureLastUpdated).TotalDays
            $st  = if ($age -le $script:MaxSigAge) { 'PASS' } elseif ($age -le ($script:MaxSigAge * 4)) { 'WARN' } else { 'FAIL' }
            Add-WgResult -Status $st -Id 'HRD-MALW-4' -Title 'Defender signature age' -Category 'MALW' `
                -Severity 'High' `
                -Description ("Signatures were last updated $age day(s) ago (version " +
                              "$($mp.AntivirusSignatureVersion)); the threshold is " +
                              "$($script:MaxSigAge) day(s).") `
                -Remediation $(if ($st -eq 'PASS') { '' } else {
                    'Update-MpSignature, or import the offline signature package (mpam-fe.exe) on an air-gapped host' })
        }
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-MALW-1' -Title 'Microsoft Defender status' -Category 'MALW' `
            -Severity 'High' `
            -Description ('Get-MpComputerStatus is unavailable. Defender may not be installed, ' +
                          'or a third-party product has replaced it.')
    }

    # Registered AV products, so a third-party agent is not reported as "no AV"
    $av = Get-WgWmi -Class AntiVirusProduct -Namespace 'root\SecurityCenter2'
    if ($av) {
        Add-WgResult -Status 'INFO' -Id 'HRD-MALW-5' -Title 'Registered anti-malware products' `
            -Category 'MALW' -Severity 'Low' `
            -Description ('Security Center reports: ' +
                          ((@($av) | ForEach-Object { "$($_.displayName)" }) -join ', ') + '.')
    }

    $pref = Get-WgMpPreference
    if ($pref) {
        $exCount = (@($pref.ExclusionPath).Count + @($pref.ExclusionProcess).Count +
                    @($pref.ExclusionExtension).Count)
        Add-WgResult -Status $(if ($exCount -eq 0) { 'PASS' } elseif ($exCount -le 10) { 'INFO' } else { 'WARN' }) `
            -Id 'HRD-MALW-6' -Title 'Defender exclusion count' -Category 'MALW' -Severity 'Medium' `
            -Description ("$exCount Defender exclusion(s) are configured (paths, processes and " +
                          'extensions combined). Every exclusion is a blind spot, and attackers ' +
                          'read them to choose where to stage.') `
            -Remediation $(if ($exCount -le 10) { '' } else { 'Review and trim the Defender exclusion list' })

        Add-WgResult -Status $(if ("$($pref.EnableControlledFolderAccess)" -eq '1') { 'PASS' } else { 'WARN' }) `
            -Id 'HRD-MALW-7' -Title 'Controlled folder access' -Category 'MALW' -Severity 'Low' `
            -Description "EnableControlledFolderAccess = $($pref.EnableControlledFolderAccess) (1 = enabled)." `
            -Remediation $(if ("$($pref.EnableControlledFolderAccess)" -eq '1') { '' } else {
                'Set-MpPreference -EnableControlledFolderAccess Enabled' })

        Add-WgResult -Status $(if ("$($pref.PUAProtection)" -eq '1') { 'PASS' } else { 'WARN' }) `
            -Id 'HRD-MALW-8' -Title 'Potentially unwanted application (PUA) protection' -Category 'MALW' `
            -Severity 'Low' -Description "PUAProtection = $($pref.PUAProtection) (1 = block)." `
            -Remediation $(if ("$($pref.PUAProtection)" -eq '1') { '' } else {
                'Set-MpPreference -PUAProtection Enabled' })
    }

    # ── LOGG: audit and logging ──────────────────────────────────────────────
    Write-WgBanner 'POSTURE - LOGG: audit & logging' @(
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor'
    )

    $psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Add-WgRegCheck -Id 'HRD-LOGG-1' -Title 'PowerShell script block logging is enabled' `
        -Category 'LOGG' -Severity 'Medium' -Path "$psPol\ScriptBlockLogging" `
        -Item 'EnableScriptBlockLogging' -Expected '1' `
        -AbsentNote ('Script block logging is off, so PowerShell attack tooling leaves no ' +
                     'record of what it executed.')
    Add-WgRegCheck -Id 'HRD-LOGG-2' -Title 'PowerShell module logging is enabled' -Category 'LOGG' `
        -Severity 'Low' -Path "$psPol\ModuleLogging" -Item 'EnableModuleLogging' -Expected '1'
    Add-WgRegCheck -Id 'HRD-LOGG-3' -Title 'PowerShell transcription is enabled' -Category 'LOGG' `
        -Severity 'Low' -Path "$psPol\Transcription" -Item 'EnableTranscripting' -Expected '1'
    Add-WgRegCheck -Id 'HRD-LOGG-4' -Title 'Process creation events include the command line' `
        -Category 'LOGG' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Item 'ProcessCreationIncludeCmdLine_Enabled' -Expected '1' `
        -AbsentNote ('Command lines are not recorded in 4688 events, which removes most of the ' +
                     'investigative value of process auditing.')

    foreach ($log in @(
        @{ Name = 'Application'; Id = 'HRD-LOGG-5' }
        @{ Name = 'Security';    Id = 'HRD-LOGG-6'; Min = 196608 }
        @{ Name = 'System';      Id = 'HRD-LOGG-7' })) {
        $min = if ($log.Min) { $log.Min } else { 32768 }
        Add-WgRegCheck -Id $log.Id -Title "$($log.Name) event log retention size" -Category 'LOGG' `
            -Severity 'Low' -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$($log.Name)" `
            -Item 'MaxSize' -Operator '>=' -Expected "$min" `
            -AbsentNote ("MaxSize is not set by policy for the $($log.Name) log; the default of " +
                         '20480 KB wraps quickly on a busy server and loses evidence.')
    }

    # Audit subcategory coverage, as a single summary rather than 60 rows
    if ($script:IsAdmin) {
        $apol = Get-WgAuditPol
        if ($apol -and $apol.Count -gt 0) {
            $subs = @($apol.Keys | Where-Object { $_ -like '{*}' })
            $none = @($subs | Where-Object { "$($apol[$_])" -match 'No Auditing' })
            $pct  = if ($subs.Count) { [int] ((($subs.Count - $none.Count) / $subs.Count) * 100) } else { 0 }
            Add-WgResult -Status $(if ($pct -ge 80) { 'PASS' } elseif ($pct -ge 50) { 'WARN' } else { 'FAIL' }) `
                -Id 'HRD-LOGG-8' -Title 'Advanced audit policy coverage' -Category 'LOGG' -Severity 'Medium' `
                -Description ("$($subs.Count - $none.Count) of $($subs.Count) audit subcategories " +
                              "are auditing something ($pct%); $($none.Count) are set to No Auditing.") `
                -Remediation $(if ($pct -ge 80) { '' } else {
                    'Apply the advanced audit policy from the CIS or STIG baseline (see the CIS/STIG findings in this report)' })
        }
    } else {
        [void] (Test-WgNeedsAdmin 'HRD-LOGG-8' 'Advanced audit policy coverage' 'LOGG')
    }

    $wef = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' '1'
    Add-WgResult -Status $(if ($wef) { 'PASS' } else { 'WARN' }) -Id 'HRD-LOGG-9' `
        -Title 'Windows Event Forwarding is configured' -Category 'LOGG' -Severity 'Low' `
        -Description $(if ($wef) { "A WEF subscription manager is configured." } else {
            ('No Windows Event Forwarding subscription manager is configured. Logs that stay ' +
             'only on the host are lost when the host is compromised or rebuilt.') }) `
        -Remediation $(if ($wef) { '' } else { 'Configure a WEF subscription manager pointing at an internal collector' })

    $sysmon = Get-WgServiceStart 'Sysmon'
    if (-not $sysmon) { $sysmon = Get-WgServiceStart 'Sysmon64' }
    Add-WgResult -Status $(if ($sysmon) { 'PASS' } else { 'INFO' }) -Id 'HRD-LOGG-10' `
        -Title 'Sysmon is installed' -Category 'LOGG' -Severity 'Low' `
        -Description $(if ($sysmon) { "Sysmon is installed (start type $sysmon)." } else {
            'Sysmon is not installed. It is optional, but it is the cheapest large gain in host telemetry.' })

    # ── SHLL: shells and scripting ───────────────────────────────────────────
    Write-WgBanner 'POSTURE - SHLL: shells & scripting' @(
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy'
    )

    $lmPol = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy'
    $effective = $null
    try { $effective = (Get-ExecutionPolicy -ErrorAction Stop).ToString() } catch { }
    $good = @('AllSigned', 'RemoteSigned', 'Restricted')
    Add-WgResult -Status $(if ($effective -and $good -contains $effective) { 'PASS' } else { 'WARN' }) `
        -Id 'HRD-SHLL-1' -Title 'PowerShell execution policy' -Category 'SHLL' -Severity 'Low' `
        -Description ("The effective execution policy is '$(if ($effective) { $effective } else { 'unknown' })'" +
                      $(if ($lmPol) { " (machine policy: $lmPol)" } else { ' (not set by Group Policy)' }) +
                      '. Execution policy is not a security boundary, but Unrestricted or Bypass ' +
                      'signals that script controls were deliberately removed.') `
        -Remediation $(if ($effective -and $good -contains $effective) { '' } else {
            'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine, ideally enforced by Group Policy' })

    $wsh = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
    Add-WgResult -Status $(if ("$wsh" -eq '0') { 'PASS' } else { 'WARN' }) -Id 'HRD-SHLL-2' `
        -Title 'Windows Script Host is disabled' -Category 'SHLL' -Severity 'Medium' `
        -Description $(if ("$wsh" -eq '0') { 'Windows Script Host is disabled.' } else {
            ('Windows Script Host is enabled, so .vbs and .js files execute on double-click. ' +
             'Few servers need it, and it is a common initial-execution path.') }) `
        -Remediation $(if ("$wsh" -eq '0') { '' } else {
            "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' " +
            '-Name Enabled -PropertyType DWord -Value 0 -Force' })

    # ── STRG: storage and removable media ────────────────────────────────────
    Write-WgBanner 'POSTURE - STRG: storage & removable media' @(
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/'
    )

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $vols = $null
        try { $vols = @(Get-BitLockerVolume -ErrorAction Stop) } catch { $vols = $null }
        if ($vols) {
            $sys = @($vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' -or $_.MountPoint -eq $env:SystemDrive })
            $unenc = @($vols | Where-Object { "$($_.ProtectionStatus)" -ne 'On' -and "$($_.ProtectionStatus)" -ne '1' })
            $sysOn = ($sys.Count -gt 0 -and @($sys | Where-Object {
                "$($_.ProtectionStatus)" -eq 'On' -or "$($_.ProtectionStatus)" -eq '1' }).Count -gt 0)
            Add-WgResult -Status $(if ($sysOn) { 'PASS' } else { 'FAIL' }) -Id 'HRD-STRG-1' `
                -Title 'BitLocker protects the operating system volume' -Category 'STRG' -Severity 'High' `
                -Description ("BitLocker protection on $($env:SystemDrive) is " +
                              $(if ($sysOn) { 'on' } else { 'off' }) +
                              "; $($unenc.Count) of $($vols.Count) volume(s) are unprotected.") `
                -Remediation $(if ($sysOn) { '' } else {
                    'Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector' })
        } else {
            Add-WgResult -Status 'WARN' -Id 'HRD-STRG-1' -Title 'BitLocker protects the operating system volume' `
                -Category 'STRG' -Severity 'High' `
                -Description 'BitLocker volume status could not be read (the feature may not be installed).' `
                -Remediation 'Install-WindowsFeature BitLocker, then enable it on the system volume'
        }
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-STRG-1' -Title 'BitLocker protects the operating system volume' `
            -Category 'STRG' -Severity 'High' -Description 'The BitLocker module is not available on this host.'
    }

    $usbstor = Get-WgServiceStart 'USBSTOR'
    Add-WgResult -Status $(if ($usbstor -eq 'Disabled' -or $null -eq $usbstor) { 'PASS' } else { 'WARN' }) `
        -Id 'HRD-STRG-2' -Title 'USB mass storage driver is disabled' -Category 'STRG' -Severity 'Medium' `
        -Description ("The USBSTOR driver start type is " +
                      $(if ($usbstor) { $usbstor } else { 'not present' }) +
                      '. On a server, removable mass storage is an exfiltration and malware path.') `
        -Remediation $(if ($usbstor -eq 'Disabled' -or $null -eq $usbstor) { '' } else {
            "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -Value 4" })

    Add-WgRegCheck -Id 'HRD-STRG-3' -Title 'Autorun is disabled for all drive types' -Category 'STRG' `
        -Severity 'Medium' -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Item 'NoDriveTypeAutoRun' -Expected '255'

    # SMB shares granting access to Everyone
    try {
        $shares = @(Get-WgWmi -Class Win32_Share | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '\$$' })
        if ($shares.Count -eq 0) {
            Add-WgResult -Status 'PASS' -Id 'HRD-STRG-4' -Title 'Non-administrative SMB shares' `
                -Category 'STRG' -Severity 'Medium' `
                -Description 'The host publishes no non-administrative file shares.'
        } else {
            $open = @()
            foreach ($sh in $shares) {
                $sd = $null
                try {
                    $sec = Get-WgWmi -Class Win32_LogicalShareSecuritySetting -Filter "Name='$($sh.Name)'"
                    if ($sec) {
                        $sd = $sec.GetSecurityDescriptor().Descriptor
                        foreach ($ace in @($sd.DACL)) {
                            $tn = "$($ace.Trustee.Name)"
                            if ($tn -match '^(Everyone|ANONYMOUS LOGON|Guests?)$' -and $ace.AccessMask -band 0x2) {
                                $open += "$($sh.Name) ($tn)"
                            }
                        }
                    }
                } catch { }
            }
            if ($open.Count -gt 0) {
                Add-WgResult -Status 'FAIL' -Id 'HRD-STRG-4' -Title 'Non-administrative SMB shares' `
                    -Category 'STRG' -Severity 'High' `
                    -Description ("$($shares.Count) share(s) are published, and these grant write " +
                                  "access to a broad principal: $($open -join ', ').") `
                    -Remediation 'Replace Everyone/Guests on the share and NTFS ACLs with specific groups'
            } else {
                Add-WgResult -Status 'INFO' -Id 'HRD-STRG-4' -Title 'Non-administrative SMB shares' `
                    -Category 'STRG' -Severity 'Medium' `
                    -Description ("$($shares.Count) non-administrative share(s) published: " +
                                  ((@($shares) | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ') +
                                  '. No Everyone/Guests write ACE was found.')
            }
        }
    } catch {
        Add-WgResult -Status 'SKIP' -Id 'HRD-STRG-4' -Title 'Non-administrative SMB shares' `
            -Category 'STRG' -Severity 'Medium' -Description 'Shares could not be enumerated.'
    }

    # ── SCHD: scheduled tasks, autoruns and service paths ────────────────────
    Write-WgBanner 'POSTURE - SCHD: scheduled tasks & service paths' @(
        'https://learn.microsoft.com/en-us/windows/win32/services/service-record-list'
    )

    # Unquoted service image paths containing spaces are a classic local
    # privilege-escalation primitive.
    try {
        $svcs = @(Get-WgWmi -Class Win32_Service)
        $unquoted = @()
        foreach ($s in $svcs) {
            $p = "$($s.PathName)".Trim()
            if (-not $p -or $p.StartsWith('"')) { continue }
            $exe = $p
            if ($p -match '^(.+?\.exe)\s') { $exe = $Matches[1] }
            elseif ($p -match '^(.+?\.exe)$') { $exe = $Matches[1] }
            if ($exe -match '\s' -and $exe -notmatch '^[A-Za-z]:\\Windows\\' ) {
                $unquoted += "$($s.Name) -> $exe"
            }
        }
        if ($unquoted.Count -gt 0) {
            Add-WgResult -Status 'FAIL' -Id 'HRD-SCHD-1' -Title 'Service image paths are quoted' `
                -Category 'SCHD' -Severity 'High' `
                -Description ("$($unquoted.Count) service(s) have an unquoted path containing a space, " +
                              'which lets a writable parent directory hijack service startup: ' +
                              (($unquoted | Select-Object -First 6) -join '; ') + '.') `
                -Remediation 'Quote the ImagePath value for each affected service'
        } else {
            Add-WgResult -Status 'PASS' -Id 'HRD-SCHD-1' -Title 'Service image paths are quoted' `
                -Category 'SCHD' -Severity 'High' `
                -Description "No unquoted service path with a space was found across $($svcs.Count) service(s)."
        }
    } catch {
        Add-WgResult -Status 'SKIP' -Id 'HRD-SCHD-1' -Title 'Service image paths are quoted' `
            -Category 'SCHD' -Severity 'High' -Description 'Win32_Service could not be enumerated.'
    }

    # Autorun entries
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $autoruns = @()
    foreach ($rk in $runKeys) {
        try {
            $k = Get-Item -LiteralPath $rk -ErrorAction Stop
            foreach ($nm in $k.GetValueNames()) { if ($nm) { $autoruns += "$nm" } }
        } catch { }
    }
    Add-WgResult -Status 'INFO' -Id 'HRD-SCHD-2' -Title 'Machine-wide autorun entries' -Category 'SCHD' `
        -Severity 'Low' `
        -Description ("$($autoruns.Count) machine-wide Run/RunOnce entr(y/ies): " +
                      $(if ($autoruns.Count) { (($autoruns | Select-Object -First 12) -join ', ') } else { 'none' }) +
                      '. Review anything unfamiliar; these run with the privileges of the logging-on user.')

    # Scheduled tasks running as SYSTEM from writable locations
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $_.State -ne 'Disabled' -and $_.Principal.UserId -match 'SYSTEM|S-1-5-18' })
            $risky = @()
            foreach ($t in $tasks) {
                foreach ($a in @($t.Actions)) {
                    $ex = "$($a.Execute)"
                    if ($ex -match '(?i)\\(Users|Temp|ProgramData|Public|Downloads)\\') {
                        $risky += "$($t.TaskName) -> $ex"
                    }
                }
            }
            if ($risky.Count -gt 0) {
                Add-WgResult -Status 'WARN' -Id 'HRD-SCHD-3' -Title 'SYSTEM scheduled tasks run from user-writable paths' `
                    -Category 'SCHD' -Severity 'High' `
                    -Description ("$($risky.Count) enabled task(s) run as SYSTEM from a commonly " +
                                  'user-writable location: ' + (($risky | Select-Object -First 6) -join '; ') +
                                  '. Verify the ACLs on each target.') `
                    -Remediation 'Move the task binaries under %ProgramFiles% and restrict write access to Administrators'
            } else {
                Add-WgResult -Status 'PASS' -Id 'HRD-SCHD-3' -Title 'SYSTEM scheduled tasks run from user-writable paths' `
                    -Category 'SCHD' -Severity 'High' `
                    -Description ("None of the $($tasks.Count) enabled SYSTEM task(s) run from a " +
                                  'commonly user-writable path.')
            }
        } catch {
            Add-WgResult -Status 'SKIP' -Id 'HRD-SCHD-3' -Title 'SYSTEM scheduled tasks' -Category 'SCHD' `
                -Severity 'High' -Description 'Scheduled tasks could not be enumerated.'
        }
    }

    # ── PKGS: patch state ────────────────────────────────────────────────────
    Write-WgBanner 'POSTURE - PKGS: patch & update state'

    $qfe = @(Get-WgWmi -Class Win32_QuickFixEngineering)
    if ($qfe.Count -gt 0) {
        $dates = @()
        foreach ($q in $qfe) {
            $d = $null
            if ($q.InstalledOn -is [datetime]) { $d = $q.InstalledOn }
            elseif ("$($q.InstalledOn)") { try { $d = [datetime]::Parse("$($q.InstalledOn)") } catch { } }
            if ($d) { $dates += $d }
        }
        if ($dates.Count -gt 0) {
            $last = ($dates | Sort-Object -Descending)[0]
            $age  = [int] ((Get-Date) - $last).TotalDays
            $st   = if ($age -le $script:MaxPatchDays) { 'PASS' } elseif ($age -le ($script:MaxPatchDays * 2)) { 'WARN' } else { 'FAIL' }
            Add-WgResult -Status $st -Id 'HRD-PKGS-1' -Title 'Time since the last installed update' `
                -Category 'PKGS' -Severity 'High' `
                -Description ("The most recent update was installed $age day(s) ago, on " +
                              "$($last.ToString('yyyy-MM-dd')). $($qfe.Count) update(s) are recorded. " +
                              "The configured threshold is $($script:MaxPatchDays) day(s).") `
                -Remediation $(if ($st -eq 'PASS') { '' } else {
                    'Apply the current cumulative update (on an air-gapped host, stage the MSU from your offline WSUS or media)' })
        } else {
            Add-WgResult -Status 'INFO' -Id 'HRD-PKGS-1' -Title 'Time since the last installed update' `
                -Category 'PKGS' -Severity 'High' `
                -Description ("$($qfe.Count) update(s) are recorded, but none carried a readable " +
                              'install date (common on images built with offline servicing).')
        }
    } else {
        Add-WgResult -Status 'WARN' -Id 'HRD-PKGS-1' -Title 'Time since the last installed update' `
            -Category 'PKGS' -Severity 'High' `
            -Description 'No update history is available from Win32_QuickFixEngineering.'
    }

    $rebootKeys = @(
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; W = 'Windows Update' }
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; W = 'component servicing' }
    )
    $pending = @($rebootKeys | Where-Object { Test-Path $_.P } | ForEach-Object { $_.W })
    $pfro = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
    if ($pfro) { $pending += 'pending file rename operations' }
    Add-WgResult -Status $(if ($pending.Count -eq 0) { 'PASS' } else { 'WARN' }) -Id 'HRD-PKGS-2' `
        -Title 'No reboot is pending' -Category 'PKGS' -Severity 'Medium' `
        -Description $(if ($pending.Count -eq 0) { 'No pending-reboot marker was found.' } else {
            ('A reboot is pending (' + ($pending -join ', ') + '). Until it completes, ' +
             'some installed fixes are not active.') }) `
        -Remediation $(if ($pending.Count -eq 0) { '' } else { 'Schedule a reboot to complete servicing' })

    # ── TIME: time synchronisation ───────────────────────────────────────────
    Write-WgBanner 'POSTURE - TIME: time synchronisation' @(
        'https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top'
    )

    $w32 = Get-WgServiceStart 'W32Time'
    $w32Running = Test-WgServiceRunning 'W32Time'
    Add-WgResult -Status $(if ($w32Running) { 'PASS' } else { 'FAIL' }) -Id 'HRD-TIME-1' `
        -Title 'Windows Time service is running' -Category 'TIME' -Severity 'Medium' `
        -Description ("W32Time start type is $(if ($w32) { $w32 } else { 'not installed' }) and the " +
                      "service is $(if ($w32Running) { 'running' } else { 'not running' }). Without " +
                      'reliable time, Kerberos fails and log correlation becomes unsound.') `
        -Remediation $(if ($w32Running) { '' } else {
            'Set-Service W32Time -StartupType Automatic; Start-Service W32Time' })

    $ntpType = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
    $ntpPeer = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
    Add-WgResult -Status $(if ($ntpPeer -or "$ntpType" -eq 'NT5DS') { 'PASS' } else { 'WARN' }) `
        -Id 'HRD-TIME-2' -Title 'A time source is configured' -Category 'TIME' -Severity 'Medium' `
        -Description ("W32Time type is '$(if ($ntpType) { $ntpType } else { 'unset' })'" +
                      $(if ($ntpPeer) { " with peer list: $ntpPeer" } else { ' with no NtpServer peer list' }) + '.') `
        -Remediation $(if ($ntpPeer -or "$ntpType" -eq 'NT5DS') { '' } else {
            'w32tm /config /manualpeerlist:"<internal-ntp>" /syncfromflags:manual /update' })

    # ── TOOL: control and enforcement tooling ────────────────────────────────
    Write-WgBanner 'POSTURE - TOOL: firewall & application control' @(
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/best-practices-configuring'
    )

    $fwProfiles = @('DomainProfile', 'PrivateProfile', 'PublicProfile')
    $fwOff = @(); $fwAllowIn = @()
    foreach ($prof in $fwProfiles) {
        $base = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$prof"
        $gp   = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$prof"
        $en   = Get-WgRegValue $gp 'EnableFirewall'
        if ($null -eq $en) { $en = Get-WgRegValue $base 'EnableFirewall' }
        if ("$en" -ne '1') { $fwOff += $prof }
        $inb = Get-WgRegValue $gp 'DefaultInboundAction'
        if ($null -eq $inb) { $inb = Get-WgRegValue $base 'DefaultInboundAction' }
        if ($null -ne $inb -and "$inb" -ne '1') { $fwAllowIn += $prof }
    }
    Add-WgResult -Status $(if ($fwOff.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Id 'HRD-TOOL-1' `
        -Title 'Windows Firewall is enabled on all profiles' -Category 'TOOL' -Severity 'High' `
        -Description $(if ($fwOff.Count -eq 0) { 'All three firewall profiles are enabled.' } else {
            ('The firewall is not enabled on: ' + ($fwOff -join ', ') + '.') }) `
        -Remediation $(if ($fwOff.Count -eq 0) { '' } else {
            'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True' })

    Add-WgResult -Status $(if ($fwAllowIn.Count -eq 0) { 'PASS' } else { 'FAIL' }) -Id 'HRD-TOOL-2' `
        -Title 'Firewall default inbound action is Block' -Category 'TOOL' -Severity 'High' `
        -Description $(if ($fwAllowIn.Count -eq 0) {
            'No profile is configured to allow inbound traffic by default.' } else {
            ('These profiles allow inbound connections by default: ' + ($fwAllowIn -join ', ') + '.') }) `
        -Remediation $(if ($fwAllowIn.Count -eq 0) { '' } else {
            'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block' })

    $appLocker = $false
    try {
        $appLocker = @(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction Stop).Count -gt 0
    } catch { }
    $wdacDeployed = (Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b") -or
                    ((Test-Path "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active") -and
                     @(Get-ChildItem "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter *.cip -ErrorAction SilentlyContinue).Count -gt 0)
    if ($appLocker -or $wdacDeployed) {
        Add-WgResult -Status 'PASS' -Id 'HRD-TOOL-3' -Title 'Application control policy is deployed' `
            -Category 'TOOL' -Severity 'Medium' `
            -Description ('An application control policy is present (' +
                          (@($(if ($appLocker) { 'AppLocker' }), $(if ($wdacDeployed) { 'WDAC' }) |
                            Where-Object { $_ }) -join ' and ') + ').')
    } else {
        Add-WgResult -Status 'WARN' -Id 'HRD-TOOL-3' -Title 'Application control policy is deployed' `
            -Category 'TOOL' -Severity 'Medium' `
            -Description ('Neither an AppLocker nor a WDAC policy was found. Application control is ' +
                          'the single most effective control against untrusted code execution, and ' +
                          'a server has a small, stable software set, which makes it practical here.') `
            -Remediation 'Deploy WDAC (preferred) or AppLocker in audit mode first, then enforce'
    }

    # ── HRDN: listening surface ──────────────────────────────────────────────
    Write-WgBanner 'POSTURE - HRDN: local listening surface'

    # Read local listener state only. Nothing is probed, scanned or connected to.
    $listeners = $null
    try {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
        }
    } catch { }
    if (-not $listeners) {
        try {
            $listeners = @(& netstat.exe -an 2>$null | Select-String 'LISTENING' | ForEach-Object {
                if ("$_" -match ':(\d+)\s') { [int] $Matches[1] }
            } | Sort-Object -Unique)
        } catch { }
    }
    if ($listeners -and $listeners.Count -gt 0) {
        $notable = @{
            21 = 'FTP'; 23 = 'Telnet'; 25 = 'SMTP'; 69 = 'TFTP'; 80 = 'HTTP'; 110 = 'POP3'
            135 = 'RPC endpoint mapper'; 139 = 'NetBIOS session'; 161 = 'SNMP'; 389 = 'LDAP'
            445 = 'SMB'; 1433 = 'MSSQL'; 3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'PostgreSQL'
            5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS'
        }
        $found = @($listeners | Where-Object { $notable.ContainsKey([int] $_) } |
            ForEach-Object { "$_/$($notable[[int] $_])" })
        Add-WgResult -Status 'INFO' -Id 'HRD-HRDN-10' -Title 'Local TCP listening ports' -Category 'HRDN' `
            -Severity 'Low' `
            -Description ("$($listeners.Count) distinct TCP port(s) are listening. Recognised " +
                          "services: $(if ($found.Count) { $found -join ', ' } else { 'none' }). " +
                          'Read from local socket state only - nothing was probed or scanned.')

        $plaintext = @($listeners | Where-Object { @(21, 23, 69, 110, 143) -contains [int] $_ })
        if ($plaintext.Count -gt 0) {
            Add-WgResult -Status 'FAIL' -Id 'HRD-HRDN-11' -Title 'No plaintext legacy service is listening' `
                -Category 'HRDN' -Severity 'High' `
                -Description ('These ports carry credentials in the clear and are listening: ' +
                              ($plaintext -join ', ') + '.') `
                -Remediation 'Disable the legacy service, or replace it with a TLS-protected equivalent'
        } else {
            Add-WgResult -Status 'PASS' -Id 'HRD-HRDN-11' -Title 'No plaintext legacy service is listening' `
                -Category 'HRDN' -Severity 'High' `
                -Description 'No FTP, Telnet, TFTP, POP3 or IMAP listener was found.'
        }
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-HRDN-10' -Title 'Local TCP listening ports' -Category 'HRDN' `
            -Severity 'Low' -Description 'Listening sockets could not be enumerated on this host.'
    }
}


# =============================================================================
#  AIR-GAP ISOLATION CHECKS
#
#  A disconnected enclave fails differently from an internet-connected server.
#  The risks are egress paths nobody noticed, radios and DMA ports that bypass
#  the gap entirely, services that try to phone home, and - the one that
#  actually bites - software and signatures quietly going stale.
#
#  Every check reads local state. Nothing is resolved, fetched or probed.
# =============================================================================

# Well-known internet destinations, used to tell an internal peer from a public
# one when a hostname cannot be resolved (and must not be, on an air-gapped host).
$script:PublicPatterns = @(
    'microsoft.com', 'windowsupdate.com', 'windowsupdate.microsoft.com', 'update.microsoft.com'
    'msftncsi.com', 'msftconnecttest.com', 'microsoftonline.com', 'live.com', 'office.com'
    'office365.com', 'azure.com', 'azureedge.net', 'akamai', 'akadns.net', 'edgesuite.net'
    'digicert.com', 'verisign.com', 'symcb.com', 'globalsign', 'entrust.net', 'sectigo'
    'google.com', 'googleapis.com', 'gstatic.com', 'cloudflare.com', 'amazonaws.com'
    'ntp.org', 'time.windows.com', 'time.nist.gov', 'time.apple.com', 'cloudflare-dns.com'
    'github.com', 'githubusercontent.com', 'dropbox.com', 'onedrive.com', 'sharepoint.com'
    'bing.com', 'msedge.net', 'trafficmanager.net', 'cdn.', 'telemetry'
)

function Test-WgPrivateIp {
    param([string] $Address)
    $a = "$Address".Trim()
    if (-not $a) { return $false }
    # IPv6 private / link-local / loopback / unique-local
    if ($a -match ':') {
        return ($a -match '^(::1|fe80:|fc|fd)' -or $a -eq '::')
    }
    # Validate the shape with a regex first, so the casts below cannot throw.
    # Note: [ref] on an array element does not write back in PowerShell, so the
    # octets are built by casting rather than with int.TryParse(out).
    if ($a -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return $false }
    $b = @($a -split '\.' | ForEach-Object { [int] $_ })
    if ($b.Count -ne 4) { return $false }
    foreach ($oct in $b) { if ($oct -lt 0 -or $oct -gt 255) { return $false } }
    if ($b[0] -eq 10)  { return $true }
    if ($b[0] -eq 127) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }  # link-local
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $true }  # CGNAT
    return $false
}

function Test-WgPublicHost {
    <# $true when the host looks like an internet destination. An unresolvable
       internal name is treated as internal, which is the safe default here:
       we never resolve anything, so a false "public" verdict would be noise. #>
    param([string] $HostName)
    $h = "$HostName".Trim().ToLower() -replace '^\[|\]$', ''
    if (-not $h) { return $false }
    $h = $h -replace '^0x[0-9a-f]\.', ''        # w32time flag prefixes
    $h = ($h -split ',')[0]
    $h = ($h -split ':')[0]
    if ($h -match '^\d+\.\d+\.\d+\.\d+$') { return (-not (Test-WgPrivateIp $h)) }
    foreach ($p in $script:PublicPatterns) {
        if ($h.Contains($p)) { return $true }
    }
    return $false
}

function Get-WgUrlHost {
    param([string] $Url)
    $u = "$Url".Trim()
    if (-not $u) { return '' }
    $u = $u -replace '^[a-zA-Z]+://', ''
    $u = ($u -split '/')[0]
    if ($u.Contains('@')) { $u = ($u -split '@')[-1] }   # drop any credentials
    return (($u -split ':')[0])
}

function Invoke-WgAirgapChecks {

    # ── AIR-NET: egress paths and bridging ───────────────────────────────────
    Write-WgBanner 'AIR-GAP - NET: egress paths & bridging'

    $adapters = @(Get-WgWmi -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
    $gateways = @()
    foreach ($a in $adapters) {
        foreach ($g in @($a.DefaultIPGateway)) { if ("$g") { $gateways += "$g" } }
    }
    $gateways = @($gateways | Sort-Object -Unique)

    if ($gateways.Count -eq 0) {
        Add-WgResult -Status 'PASS' -Id 'AIR-NET-1' -Title 'No default gateway is configured' `
            -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' -Severity 'Medium' `
            -Description 'No IP-enabled adapter has a default gateway, which is what an isolated host should look like.'
    } else {
        $pub = @($gateways | Where-Object { -not (Test-WgPrivateIp $_) })
        Add-WgResult -Status $(if ($pub.Count -gt 0) { 'FAIL' } else { 'WARN' }) -Id 'AIR-NET-1' `
            -Title 'Default gateway configuration' -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' `
            -Severity $(if ($pub.Count -gt 0) { 'High' } else { 'Medium' }) `
            -Description ("Default gateway(s) configured: $($gateways -join ', ')." +
                          $(if ($pub.Count -gt 0) {
                              " $($pub.Count) of these are outside RFC1918/private space, which suggests a route off the enclave."
                            } else {
                              ' All are in private address space; confirm the gateway only reaches enclave-internal networks.'
                            })) `
            -Remediation 'Confirm the route terminates on an enclave-only firewall, or remove the default route'
    }

    $multi = @($adapters | Where-Object { @($_.IPAddress).Count -gt 0 })
    Add-WgResult -Status $(if ($multi.Count -le 1) { 'PASS' } else { 'WARN' }) -Id 'AIR-NET-2' `
        -Title 'Host is not multi-homed' -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' `
        -Severity 'Medium' `
        -Description ("$($multi.Count) IP-enabled adapter(s) are present" +
                      $(if ($multi.Count -gt 1) {
                          ': ' + ((@($multi) | ForEach-Object { "$($_.Description) [$((@($_.IPAddress)) -join ' ')]" }) -join '; ') +
                          '. A multi-homed host can bridge the enclave to another network.'
                        } else { '.' })) `
        -Remediation $(if ($multi.Count -le 1) { '' } else {
            'Confirm every adapter is enclave-internal; disable any adapter that reaches another network' })

    $ipFwd = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'IPEnableRouter'
    Add-WgResult -Status $(if ("$ipFwd" -eq '1') { 'FAIL' } else { 'PASS' }) -Id 'AIR-NET-3' `
        -Title 'IP forwarding is disabled' -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' -Severity 'High' `
        -Description $(if ("$ipFwd" -eq '1') {
            'IPEnableRouter is 1, so this host routes between its networks and can bridge the air gap.'
        } else { "IPEnableRouter is $(if ($null -eq $ipFwd) { 'not set' } else { $ipFwd }); the host does not route." }) `
        -Remediation $(if ("$ipFwd" -eq '1') {
            "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 0" } else { '' })

    foreach ($rr in @(
        @{ N = 'RemoteAccess'; L = 'Routing and Remote Access'; Id = 'AIR-NET-4' }
        @{ N = 'SharedAccess'; L = 'Internet Connection Sharing'; Id = 'AIR-NET-5' })) {
        $s = Get-WgServiceStart $rr.N
        $bad = ($s -and $s -ne 'Disabled')
        Add-WgResult -Status $(if ($bad) { 'FAIL' } else { 'PASS' }) -Id $rr.Id `
            -Title "$($rr.L) is disabled" -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' -Severity 'High' `
            -Description ("$($rr.L) ($($rr.N)) start type is " +
                          $(if ($s) { $s } else { 'not installed' }) +
                          $(if ($bad) { '. This service exists to join networks together.' } else { '.' })) `
            -Remediation $(if ($bad) { "Set-Service -Name $($rr.N) -StartupType Disabled; Stop-Service $($rr.N)" } else { '' })
    }

    # Proxy settings: a configured proxy is itself an egress path. Credentials
    # embedded in the URL are masked before they reach the report.
    $proxyFindings = @()
    $wpi = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer'
    if ($wpi) { $proxyFindings += "machine Internet Settings: $(Get-WgUrlHost $wpi)" }
    $wpad = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoConfigURL'
    if ($wpad) { $proxyFindings += "autoconfig URL host: $(Get-WgUrlHost $wpad)" }
    if ($script:IsAdmin) {
        $wh = & netsh.exe winhttp show proxy 2>$null | Out-String
        if ($wh -match '(?im)^\s*Proxy Server\(s\)\s*:\s*(\S+)') {
            $proxyFindings += "WinHTTP: $(Get-WgUrlHost $Matches[1])"
        }
    }
    if ($proxyFindings.Count -gt 0) {
        $pubProxy = @($proxyFindings | Where-Object { Test-WgPublicHost (($_ -split ': ')[-1]) })
        Add-WgResult -Status $(if ($pubProxy.Count -gt 0) { 'FAIL' } else { 'WARN' }) -Id 'AIR-NET-6' `
            -Title 'HTTP proxy configuration' -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' `
            -Severity 'Medium' `
            -Description ('A proxy is configured (' + ($proxyFindings -join '; ') +
                          '). Any credentials in the value have been masked. A proxy is an ' +
                          'egress path: confirm it only reaches enclave-internal destinations.') `
            -Remediation 'Remove the proxy, or confirm it is an enclave-internal, egress-filtered proxy'
    } else {
        Add-WgResult -Status 'PASS' -Id 'AIR-NET-6' -Title 'HTTP proxy configuration' `
            -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' -Severity 'Medium' `
            -Description 'No machine-level HTTP proxy or autoconfig URL is configured.'
    }

    # ── AIR-DNS ──────────────────────────────────────────────────────────────
    $dns = @()
    foreach ($a in $adapters) {
        foreach ($d in @($a.DNSServerSearchOrder)) { if ("$d") { $dns += "$d" } }
    }
    $dns = @($dns | Sort-Object -Unique)
    if ($dns.Count -eq 0) {
        Add-WgResult -Status 'PASS' -Id 'AIR-DNS-1' -Title 'DNS resolvers are enclave-internal' `
            -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' -Severity 'Medium' `
            -Description 'No DNS resolvers are configured.'
    } else {
        $pubDns = @($dns | Where-Object { -not (Test-WgPrivateIp $_) })
        Add-WgResult -Status $(if ($pubDns.Count -gt 0) { 'FAIL' } else { 'PASS' }) -Id 'AIR-DNS-1' `
            -Title 'DNS resolvers are enclave-internal' -Category 'AIR-GAP NETWORK' -Framework 'AIRGAP' `
            -Severity 'High' `
            -Description ("Configured resolvers: $($dns -join ', ')." +
                          $(if ($pubDns.Count -gt 0) {
                              " $($pubDns -join ', ') are public addresses. A reachable public resolver is both an egress path and a DNS-tunnel channel."
                            } else { ' All are private addresses.' })) `
            -Remediation $(if ($pubDns.Count -gt 0) { 'Point DNS at enclave-internal resolvers only' } else { '' })
    }

    # ── AIR-RF: radios ───────────────────────────────────────────────────────
    Write-WgBanner 'AIR-GAP - RF: radios & out-of-band interfaces'

    $allAdapters = @(Get-WgWmi -Class Win32_NetworkAdapter)
    $radioDefs = @(
        @{ Id = 'AIR-RF-1'; L = 'Wi-Fi';              Rx = 'wireless|wi-?fi|802\.11|wlan';        Svc = @('WlanSvc') }
        @{ Id = 'AIR-RF-2'; L = 'Bluetooth';          Rx = 'bluetooth';                            Svc = @('bthserv', 'BTAGService') }
        @{ Id = 'AIR-RF-3'; L = 'Cellular / WWAN';    Rx = 'wwan|mobile broadband|cellular|lte|modem'; Svc = @('WwanSvc') }
        @{ Id = 'AIR-RF-4'; L = 'USB tethering / RNDIS'; Rx = 'rndis|tether|usb.*(ethernet|network)'; Svc = @() }
    )
    foreach ($r in $radioDefs) {
        $hits = @($allAdapters | Where-Object {
            ("$($_.Name)" -match $r.Rx) -or ("$($_.Description)" -match $r.Rx) })
        $svcOn = @()
        foreach ($s in $r.Svc) {
            $st = Get-WgServiceStart $s
            if ($st -and $st -ne 'Disabled') { $svcOn += "$s=$st" }
        }
        $enabledHits = @($hits | Where-Object { $_.NetEnabled -eq $true })

        if ($hits.Count -eq 0 -and $svcOn.Count -eq 0) {
            Add-WgResult -Status 'PASS' -Id $r.Id -Title "$($r.L) is absent" `
                -Category 'AIR-GAP RADIO' -Framework 'AIRGAP' -Severity 'High' `
                -Description "No $($r.L) adapter and no enabled $($r.L) service were found."
        } else {
            $st = if ($enabledHits.Count -gt 0) { 'FAIL' } else { 'WARN' }
            Add-WgResult -Status $st -Id $r.Id -Title "$($r.L) is absent" `
                -Category 'AIR-GAP RADIO' -Framework 'AIRGAP' -Severity 'High' `
                -Description ("$($hits.Count) $($r.L) adapter(s) present" +
                              $(if ($enabledHits.Count -gt 0) { ", $($enabledHits.Count) of them enabled" } else { ', none enabled' }) +
                              $(if ($svcOn.Count -gt 0) { "; service(s) not disabled: $($svcOn -join ', ')" } else { '' }) +
                              $(if ($hits.Count -gt 0) {
                                  '. Devices: ' + ((@($hits) | Select-Object -First 4 | ForEach-Object { "$($_.Description)" }) -join '; ')
                                } else { '' }) +
                              ". A radio in an air-gapped host defeats the gap without touching the wiring.") `
                -Remediation ("Disable-NetAdapter on the device and disable the driver/service; " +
                              'better still, remove the hardware or block it in firmware')
        }
    }

    # ── AIR-DMA / removable media ────────────────────────────────────────────
    Write-WgBanner 'AIR-GAP - DMA & removable media' @(
        'https://www.synacktiv.com/en/publications/practical-dma-attack-on-windows-10.html'
    )

    Add-WgRegCheck -Id 'AIR-DMA-1' -Title 'DMA under lock is not permitted' `
        -Category 'AIR-GAP DMA' -Framework 'AIRGAP' -Severity 'High' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity' -Item 'AllowDmaUnderLock' `
        -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote ('AllowDmaUnderLock is not set. A Thunderbolt or external PCIe device can ' +
                     'read system memory while the console is locked - a physical bypass that ' +
                     'does not need the network at all.')

    Add-WgRegCheck -Id 'AIR-DMA-2' -Title 'New DMA devices are blocked when the host is locked' `
        -Category 'AIR-GAP DMA' -Framework 'AIRGAP' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' `
        -Item 'DenyDeviceIDs' -Expected '1' -IfAbsent 'WARN' `
        -AbsentNote 'No device installation restriction policy is configured for DMA-capable device classes.'

    Add-WgRegCheck -Id 'AIR-USB-1' -Title 'Removable disks are denied write access' `
        -Category 'AIR-GAP MEDIA' -Framework 'AIRGAP' -Severity 'High' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' `
        -Item 'Deny_Write' -Expected '1' -IfAbsent 'WARN' `
        -AbsentNote ('Removable-disk write access is not denied by policy. In an enclave, ' +
                     'removable media is the main exfiltration path and the main malware entry point.')

    # ── AIR-SVC: services that reach out on their own ────────────────────────
    Write-WgBanner 'AIR-GAP - SVC: phone-home services'

    $phoneHome = @(
        @{ Id = 'AIR-SVC-1';  N = 'DiagTrack';       L = 'Connected User Experiences and Telemetry'; Sev = 'High' }
        @{ Id = 'AIR-SVC-2';  N = 'dmwappushservice'; L = 'Device Management WAP Push';               Sev = 'Medium' }
        @{ Id = 'AIR-SVC-3';  N = 'DoSvc';            L = 'Delivery Optimization';                    Sev = 'Medium' }
        @{ Id = 'AIR-SVC-4';  N = 'WerSvc';           L = 'Windows Error Reporting';                  Sev = 'Medium' }
        @{ Id = 'AIR-SVC-5';  N = 'OneSyncSvc';       L = 'Sync Host (account cloud sync)';           Sev = 'Low' }
        @{ Id = 'AIR-SVC-6';  N = 'MapsBroker';       L = 'Downloaded Maps Manager';                  Sev = 'Low' }
        @{ Id = 'AIR-SVC-7';  N = 'RetailDemo';       L = 'Retail Demo Service';                      Sev = 'Low' }
        @{ Id = 'AIR-SVC-8';  N = 'wisvc';            L = 'Windows Insider Service';                  Sev = 'Medium' }
        @{ Id = 'AIR-SVC-9';  N = 'RemoteAssistance'; L = 'Remote Assistance';                        Sev = 'Medium' }
        @{ Id = 'AIR-SVC-10'; N = 'icssvc';           L = 'Windows Mobile Hotspot';                   Sev = 'High' }
    )
    foreach ($p in $phoneHome) {
        $s = Get-WgServiceStart $p.N
        if ($null -eq $s) {
            Add-WgResult -Status 'PASS' -Id $p.Id -Title "$($p.L) is not enabled" `
                -Category 'AIR-GAP SERVICES' -Framework 'AIRGAP' -Severity $p.Sev `
                -Description "$($p.L) ($($p.N)) is not installed."
        } elseif ($s -eq 'Disabled') {
            Add-WgResult -Status 'PASS' -Id $p.Id -Title "$($p.L) is not enabled" `
                -Category 'AIR-GAP SERVICES' -Framework 'AIRGAP' -Severity $p.Sev `
                -Description "$($p.L) ($($p.N)) is disabled."
        } else {
            Add-WgResult -Status $(if ($p.Sev -eq 'Low') { 'WARN' } else { 'FAIL' }) -Id $p.Id `
                -Title "$($p.L) is not enabled" -Category 'AIR-GAP SERVICES' -Framework 'AIRGAP' `
                -Severity $p.Sev `
                -Description ("$($p.L) ($($p.N)) start type is $s. On an isolated host this " +
                              'generates outbound attempts that will never succeed, filling logs ' +
                              'and masking real egress attempts.') `
                -Remediation "Set-Service -Name $($p.N) -StartupType Disabled; Stop-Service $($p.N)"
        }
    }

    # ── AIR-TELEM: telemetry and cloud content ───────────────────────────────
    Write-WgBanner 'AIR-GAP - TELEM: telemetry & cloud features' @(
        'https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
    )

    Add-WgRegCheck -Id 'AIR-TELEM-1' -Title 'Telemetry is set to the minimum level' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'High' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Item 'AllowTelemetry' `
        -Expected '0' `
        -AbsentNote ('AllowTelemetry is not set by policy. On Enterprise/Server SKUs 0 (Security) ' +
                     'is permitted and is the correct setting for an enclave.')

    Add-WgRegCheck -Id 'AIR-TELEM-2' -Title 'Windows Error Reporting is disabled' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Item 'Disabled' `
        -Expected '1' `
        -AbsentNote 'WER is not disabled by policy; crash reports include memory contents and are sent outbound.'

    Add-WgRegCheck -Id 'AIR-TELEM-3' -Title 'Customer Experience Improvement Program is disabled' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'Low' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Item 'CEIPEnable' -Expected '0'

    Add-WgRegCheck -Id 'AIR-TELEM-4' -Title 'Microsoft Defender cloud-delivered protection (MAPS) is off' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Item 'SpynetReporting' `
        -Expected '0' -IfAbsent 'WARN' `
        -AbsentNote ('MAPS reporting is not explicitly disabled. On a connected host cloud ' +
                     'protection is a security win and should stay on; on an isolated host it ' +
                     'cannot work and only produces outbound attempts. Decide deliberately, ' +
                     'and record a waiver if you keep it on.')

    Add-WgRegCheck -Id 'AIR-TELEM-5' -Title 'Automatic sample submission is off' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'High' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Item 'SubmitSamplesConsent' `
        -Expected '2' -IfAbsent 'WARN' `
        -AbsentNote ('Sample submission is not set to "never send". On an enclave host this would ' +
                     'attempt to upload files - potentially classified ones - off the network.')

    Add-WgRegCheck -Id 'AIR-TELEM-6' -Title 'Root certificate auto-update is disabled' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'Medium' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -Item 'DisableRootAutoUpdate' `
        -Expected '1' -IfAbsent 'WARN' `
        -AbsentNote ('Root certificate auto-update is not disabled. It will repeatedly try to ' +
                     'reach Windows Update; on an isolated host, manage the trusted root store ' +
                     'from your offline PKI instead.')

    Add-WgRegCheck -Id 'AIR-TELEM-7' -Title 'Network Connectivity Status Indicator probing is disabled' `
        -Category 'AIR-GAP TELEMETRY' -Framework 'AIRGAP' -Severity 'Low' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' `
        -Item 'NoActiveProbe' -Expected '1' -IfAbsent 'WARN' `
        -AbsentNote ('NCSI active probing is not disabled, so the host repeatedly tries to reach ' +
                     'msftconnecttest.com to decide whether it is online.')

    # ── AIR-WU: update source ────────────────────────────────────────────────
    Write-WgBanner 'AIR-GAP - WU: update source & patch currency' @(
        'https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/'
    )

    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wsus  = Get-WgRegValue $wuPol 'WUServer'
    $useWsus = Get-WgRegValue "$wuPol\AU" 'UseWUServer'
    if ($wsus) {
        $wsusHost = Get-WgUrlHost $wsus
        $isPub = Test-WgPublicHost $wsusHost
        Add-WgResult -Status $(if ($isPub) { 'FAIL' } elseif ("$useWsus" -eq '1') { 'PASS' } else { 'WARN' }) `
            -Id 'AIR-WU-1' -Title 'Updates come from an internal source' `
            -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'High' `
            -Description ("WUServer is '$wsusHost' and UseWUServer is " +
                          "$(if ($null -eq $useWsus) { 'not set' } else { $useWsus })." +
                          $(if ($isPub) { ' That destination looks like an internet host.' }
                            elseif ("$useWsus" -ne '1') { ' A WSUS server is named but not actually in use.' }
                            else { ' Updates are served from an internal WSUS.' })) `
            -Remediation $(if ($isPub -or "$useWsus" -ne '1') {
                "Point WUServer at the enclave WSUS and set UseWUServer to 1" } else { '' })
    } else {
        Add-WgResult -Status 'WARN' -Id 'AIR-WU-1' -Title 'Updates come from an internal source' `
            -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'High' `
            -Description ('No WSUS server is configured, so Windows Update targets Microsoft ' +
                          'directly. On an isolated host that means updates silently never arrive.') `
            -Remediation 'Configure an enclave WSUS, or adopt a documented offline MSU/media patching process'
    }

    Add-WgRegCheck -Id 'AIR-WU-2' -Title 'Dual scan against Windows Update is disabled' `
        -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'Medium' `
        -Path $wuPol -Item 'DisableDualScan' -Expected '1' -IfAbsent 'WARN' `
        -AbsentNote ('DisableDualScan is not set, so the host may bypass WSUS and scan Microsoft ' +
                     'Update directly for some content.')

    $doMode = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'
    Add-WgResult -Status $(if ("$doMode" -eq '0' -or "$doMode" -eq '99' -or "$doMode" -eq '100') { 'PASS' } else { 'WARN' }) `
        -Id 'AIR-WU-3' -Title 'Delivery Optimization does not peer over the internet' `
        -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'Medium' `
        -Description ("DODownloadMode is $(if ($null -eq $doMode) { 'not set (default 1 = LAN peering)' } else { $doMode })" +
                      '. Modes 2 and 3 peer beyond the local subnet, including over the internet.') `
        -Remediation $(if ("$doMode" -eq '0' -or "$doMode" -eq '99' -or "$doMode" -eq '100') { '' } else {
            "Set DODownloadMode to 0 (HTTP only) or 99 (simple) under " +
            "'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'" })

    # WSUS over cleartext HTTP is independently exploitable: an on-path attacker
    # can serve a signed-but-attacker-chosen update (pywsus / WSUSpect) and get
    # SYSTEM, regardless of whether the server itself is internal.
    $wuSrv = Get-WgRegValue $wuPol 'WUServer'
    $wuSt  = Get-WgRegValue $wuPol 'WUStatusServer'
    if (-not $wuSrv -and -not $wuSt) {
        # Still emit the row: a check that only appears on some hosts shows up as
        # a removed check in the -Baseline drift panel.
        Add-WgResult -Status 'PASS' -Id 'AIR-WU-5' `
            -Title 'WSUS is reached over HTTPS, not cleartext HTTP' -Category 'AIR-GAP UPDATES' `
            -Framework 'AIRGAP' -Severity 'High' `
            -Description ('No update server endpoint is configured, so there is no cleartext ' +
                          'WSUS channel to attack. AIR-WU-1 covers whether updates reach this ' +
                          'host at all.')
    } else {
        $plain = @(@($wuSrv, $wuSt) | Where-Object { $_ -and "$_" -match '^(?i)http://' })
        Add-WgResult -Status $(if ($plain.Count -gt 0) { 'FAIL' } else { 'PASS' }) -Id 'AIR-WU-5' `
            -Title 'WSUS is reached over HTTPS, not cleartext HTTP' -Category 'AIR-GAP UPDATES' `
            -Framework 'AIRGAP' -Severity 'High' `
            -Description $(if ($plain.Count -gt 0) {
                ('The update server is configured over cleartext HTTP: ' +
                 (($plain | ForEach-Object { Get-WgUrlHost $_ }) -join ', ') +
                 '. An attacker on the path can inject a malicious update and execute code as ' +
                 'SYSTEM, because the transport is unauthenticated even though the packages are ' +
                 'signed. An internal WSUS does not make this safe - it only narrows who can reach it.')
            } else {
                'The configured update server endpoints use HTTPS.'
            }) `
            -Remediation $(if ($plain.Count -gt 0) {
                'Reconfigure WUServer and WUStatusServer to https:// with a certificate the clients trust' } else { '' })
    }

    Add-WgRegCheck -Id 'AIR-WU-4' -Title 'Microsoft Store is disabled' `
        -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'Low' `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Item 'RemoveWindowsStore' -Expected '1' `
        -IfAbsent 'WARN' -AbsentNote 'The Store is not disabled by policy; it is an outbound content channel.'

    # Patch and signature currency - the risk that actually materialises in an
    # enclave is not egress, it is software quietly going stale.
    $qfe = @(Get-WgWmi -Class Win32_QuickFixEngineering)
    $dates = @()
    foreach ($q in $qfe) {
        $d = $null
        if ($q.InstalledOn -is [datetime]) { $d = $q.InstalledOn }
        elseif ("$($q.InstalledOn)") { try { $d = [datetime]::Parse("$($q.InstalledOn)") } catch { } }
        if ($d) { $dates += $d }
    }
    if ($dates.Count -gt 0) {
        $last = ($dates | Sort-Object -Descending)[0]
        $age  = [int] ((Get-Date) - $last).TotalDays
        $st   = if ($age -le $script:MaxPatchDays) { 'PASS' } elseif ($age -le ($script:MaxPatchDays * 2)) { 'WARN' } else { 'FAIL' }
        Add-WgResult -Status $st -Id 'AIR-PATCH-1' -Title 'Patch currency on an isolated host' `
            -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'High' `
            -Description ("The last update was installed $age day(s) ago ($($last.ToString('yyyy-MM-dd'))), " +
                          "against a threshold of $($script:MaxPatchDays) day(s). This is the " +
                          'failure mode of disconnected systems: nothing breaks, it just ages.') `
            -Remediation $(if ($st -eq 'PASS') { '' } else {
                'Stage the current cumulative update through your offline media transfer process' })
    } else {
        Add-WgResult -Status 'WARN' -Id 'AIR-PATCH-1' -Title 'Patch currency on an isolated host' `
            -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'High' `
            -Description 'No readable update install history, so patch currency cannot be confirmed.'
    }

    $mpStatus = $null
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }
    }
    if ($mpStatus -and $mpStatus.AntivirusSignatureLastUpdated) {
        $sigAge = [int] ((Get-Date) - [datetime] $mpStatus.AntivirusSignatureLastUpdated).TotalDays
        $st = if ($sigAge -le $script:MaxSigAge) { 'PASS' } elseif ($sigAge -le ($script:MaxSigAge * 4)) { 'WARN' } else { 'FAIL' }
        Add-WgResult -Status $st -Id 'AIR-PATCH-2' -Title 'Anti-malware signature currency' `
            -Category 'AIR-GAP UPDATES' -Framework 'AIRGAP' -Severity 'High' `
            -Description ("Defender signatures are $sigAge day(s) old (threshold " +
                          "$($script:MaxSigAge) day(s)). With cloud protection unavailable, " +
                          'signature freshness is the whole of the detection capability here.') `
            -Remediation $(if ($st -eq 'PASS') { '' } else {
                'Import the offline signature package (mpam-fe.exe) via your media transfer process, on a schedule' })
    }

    # ── AIR-TIME ─────────────────────────────────────────────────────────────
    $ntpPeer = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
    if ($ntpPeer) {
        $peers = @("$ntpPeer" -split '\s+' | Where-Object { $_ })
        $pubPeers = @($peers | Where-Object { Test-WgPublicHost (Get-WgUrlHost $_) })
        Add-WgResult -Status $(if ($pubPeers.Count -gt 0) { 'FAIL' } else { 'PASS' }) -Id 'AIR-TIME-1' `
            -Title 'Time sources are enclave-internal' -Category 'AIR-GAP TIME' -Framework 'AIRGAP' `
            -Severity 'Medium' `
            -Description ("Configured NTP peer(s): $($peers -join ', ')." +
                          $(if ($pubPeers.Count -gt 0) {
                              " $($pubPeers -join ', ') are public time services, which will never be reachable and leaves the clock unmanaged."
                            } else { ' All peers look internal.' })) `
            -Remediation $(if ($pubPeers.Count -gt 0) {
                'w32tm /config /manualpeerlist:"<internal-ntp>" /syncfromflags:manual /update' } else { '' })
    } else {
        $t = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
        Add-WgResult -Status $(if ("$t" -eq 'NT5DS') { 'PASS' } else { 'WARN' }) -Id 'AIR-TIME-1' `
            -Title 'Time sources are enclave-internal' -Category 'AIR-GAP TIME' -Framework 'AIRGAP' `
            -Severity 'Medium' `
            -Description ("No NtpServer peer list is set; W32Time type is " +
                          "'$(if ($t) { $t } else { 'unset' })'" +
                          $(if ("$t" -eq 'NT5DS') { ' (domain hierarchy, which is internal).' }
                            else { '. With no internal time source, clock drift goes unmanaged.' })) `
            -Remediation $(if ("$t" -eq 'NT5DS') { '' } else { 'Configure an enclave-internal NTP peer' })
    }

    # ── AIR-IPv6 transition tunnels ──────────────────────────────────────────
    Write-WgBanner 'AIR-GAP - TUNNEL: transition & remote-access tunnels'

    $tcpip6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
    $disabledComponents = Get-WgRegValue $tcpip6 'DisabledComponents'
    foreach ($tun in @(
        @{ Id = 'AIR-TUN-1'; N = 'Teredo';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'; Item = 'Teredo_State' }
        @{ Id = 'AIR-TUN-2'; N = '6to4';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'; Item = '6to4_State' }
        @{ Id = 'AIR-TUN-3'; N = 'ISATAP';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'; Item = 'ISATAP_State' })) {
        $v = Get-WgRegValue $tun.Path $tun.Item
        $ok = ("$v" -ieq 'Disabled') -or ("$v" -eq '0') -or
              ($null -ne $disabledComponents -and ([int] "$disabledComponents" -band 0x01))
        Add-WgResult -Status $(if ($ok) { 'PASS' } else { 'WARN' }) -Id $tun.Id `
            -Title "$($tun.N) IPv6 transition tunnelling is disabled" -Category 'AIR-GAP TUNNEL' `
            -Framework 'AIRGAP' -Severity 'Medium' `
            -Description ("$($tun.N) state is " +
                          "'$(if ($null -eq $v) { 'not configured' } else { $v })'" +
                          $(if ($null -ne $disabledComponents) { " (IPv6 DisabledComponents = $disabledComponents)" } else { '' }) +
                          $(if ($ok) { '.' } else {
                              ". $($tun.N) can carry IPv6 over an IPv4-only network, which is an unmonitored egress path."
                            })) `
            -Remediation $(if ($ok) { '' } else {
                "Set $($tun.Item) to 'Disabled' under '$($tun.Path)'" })
    }

    # Inbound remote-access surface, from local configuration only
    $rdpOn = ("$(Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')" -eq '0')
    $winrmOn = $false
    $winrmStart = Get-WgServiceStart 'WinRM'
    if ($winrmStart -and $winrmStart -ne 'Disabled') { $winrmOn = Test-WgServiceRunning 'WinRM' }
    $sshOn = $false
    $sshStart = Get-WgServiceStart 'sshd'
    if ($sshStart -and $sshStart -ne 'Disabled') { $sshOn = $true }

    $open = @()
    if ($rdpOn)   { $open += 'RDP' }
    if ($winrmOn) { $open += 'WinRM' }
    if ($sshOn)   { $open += 'OpenSSH server' }
    Add-WgResult -Status $(if ($open.Count -eq 0) { 'PASS' } else { 'INFO' }) -Id 'AIR-TUN-4' `
        -Title 'Inbound remote-management surface' -Category 'AIR-GAP TUNNEL' -Framework 'AIRGAP' `
        -Severity 'Medium' `
        -Description $(if ($open.Count -eq 0) {
            'No inbound remote management service (RDP, WinRM, OpenSSH) is enabled.'
        } else {
            ('Enabled inbound remote management: ' + ($open -join ', ') +
             '. Each one can be used to forward ports and tunnel traffic across the enclave ' +
             'boundary; confirm each is reachable only from inside, and that port forwarding is restricted.')
        })

    if ($sshOn) {
        $sshdCfg = Join-Path $env:ProgramData 'ssh\sshd_config'
        if (Test-Path -LiteralPath $sshdCfg) {
            $cfg = Get-Content -LiteralPath $sshdCfg -ErrorAction SilentlyContinue | Out-String
            $fwdIssues = @()
            if ($cfg -match '(?im)^\s*AllowTcpForwarding\s+yes')  { $fwdIssues += 'AllowTcpForwarding yes' }
            if ($cfg -match '(?im)^\s*GatewayPorts\s+(yes|clientspecified)') { $fwdIssues += 'GatewayPorts enabled' }
            if ($cfg -match '(?im)^\s*AllowAgentForwarding\s+yes') { $fwdIssues += 'AllowAgentForwarding yes' }
            if ($cfg -match '(?im)^\s*PermitTunnel\s+(yes|point-to-point|ethernet)') { $fwdIssues += 'PermitTunnel enabled' }
            Add-WgResult -Status $(if ($fwdIssues.Count -gt 0) { 'FAIL' } else { 'PASS' }) -Id 'AIR-TUN-5' `
                -Title 'OpenSSH server does not permit tunnelling' -Category 'AIR-GAP TUNNEL' `
                -Framework 'AIRGAP' -Severity 'High' `
                -Description $(if ($fwdIssues.Count -gt 0) {
                    ('sshd_config permits tunnelling: ' + ($fwdIssues -join ', ') +
                     '. These turn an administrative SSH session into a general-purpose ' +
                     'bridge across the air gap.')
                } else { 'sshd_config does not enable TCP, agent or tunnel forwarding.' }) `
                -Remediation $(if ($fwdIssues.Count -gt 0) {
                    'In sshd_config set AllowTcpForwarding no, GatewayPorts no, AllowAgentForwarding no, PermitTunnel no' } else { '' })
        }
    }

    # ── AIR-LOG: log forwarding destination ──────────────────────────────────
    $wefUrl = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' '1'
    if ($wefUrl) {
        $h = Get-WgUrlHost ($wefUrl -replace '.*Server=\s*', '')
        $isPub = Test-WgPublicHost $h
        Add-WgResult -Status $(if ($isPub) { 'FAIL' } else { 'PASS' }) -Id 'AIR-LOG-1' `
            -Title 'Log forwarding stays inside the enclave' -Category 'AIR-GAP LOGGING' `
            -Framework 'AIRGAP' -Severity 'High' `
            -Description ("Event forwarding targets '$h'." +
                          $(if ($isPub) { ' That looks like an internet destination, so logs would leave the enclave.' }
                            else { ' The collector appears to be internal.' })) `
            -Remediation $(if ($isPub) { 'Point the WEF subscription manager at an enclave-internal collector' } else { '' })
    } else {
        Add-WgResult -Status 'INFO' -Id 'AIR-LOG-1' -Title 'Log forwarding stays inside the enclave' `
            -Category 'AIR-GAP LOGGING' -Framework 'AIRGAP' -Severity 'Low' `
            -Description 'No Windows Event Forwarding subscription is configured, so no logs leave the host.'
    }
}


# =============================================================================
#  EXTENDED POSTURE CHECKS
#
#  Local privilege-escalation and bypass checks that no single CIS or STIG line
#  item asserts. Several are modelled on LuemmelSec's Client-Checker, which goes
#  looking for exploitable conditions rather than policy compliance - a useful
#  complement to a benchmark run.
#
#  Where the two disagree on judgement, the reasoning is in the finding text so
#  the verdict can be argued with rather than just accepted.
# =============================================================================

function Invoke-WgExtraChecks {

    # ── Pre-boot authentication: the BitLocker question that actually matters ─
    Write-WgBanner 'POSTURE - STRG: BitLocker pre-boot authentication' @(
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures'
    )

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $vols = $null
        try { $vols = @(Get-BitLockerVolume -ErrorAction Stop) } catch { $vols = $null }
        if (-not $vols) {
            if (-not $script:IsAdmin) {
                $script:Counts.PRIV_SKIP++
                Add-WgResult -Status 'SKIP' -Id 'HRD-STRG-5' -Title 'BitLocker pre-boot authentication' `
                    -Category 'STRG' -Severity 'High' `
                    -Description 'ADMINISTRATOR REQUIRED - BitLocker key protectors cannot be read unelevated.' `
                    -Remediation 'Re-run from an elevated prompt'
            } else {
                Add-WgResult -Status 'WARN' -Id 'HRD-STRG-5' -Title 'BitLocker pre-boot authentication' `
                    -Category 'STRG' -Severity 'High' `
                    -Description 'BitLocker volume information could not be read; the feature may not be installed.'
            }
        } else {
            $sysVols = @($vols | Where-Object {
                $_.VolumeType -eq 'OperatingSystem' -or $_.MountPoint -eq $env:SystemDrive })
            if ($sysVols.Count -eq 0) { $sysVols = @($vols | Select-Object -First 1) }

            foreach ($v in $sysVols) {
                $on = ("$($v.ProtectionStatus)" -eq 'On' -or "$($v.ProtectionStatus)" -eq '1')
                if (-not $on) { continue }   # HRD-STRG-1 already reports an unprotected volume

                $types = @($v.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
                # Something the user knows, or something they carry, in addition to the TPM.
                $strong = @($types | Where-Object {
                    $_ -match '^(TpmPin|TpmPinStartupKey|Pin|Password|PassPhrase)$' })
                # A USB startup key counts, but it travels with the laptop it unlocks.
                $removable = @($types | Where-Object {
                    $_ -match '^(TpmStartupKey|ExternalKey|StartupKey)$' })
                $tpmOnly = (@($types | Where-Object { $_ -eq 'Tpm' }).Count -gt 0 -and
                            $strong.Count -eq 0 -and $removable.Count -eq 0)

                $shown = if ($types.Count) { $types -join ', ' } else { '(none reported)' }

                if ($strong.Count -gt 0) {
                    Add-WgResult -Status 'PASS' -Id 'HRD-STRG-5' `
                        -Title 'BitLocker pre-boot authentication' -Category 'STRG' -Severity 'High' `
                        -Description ("$($v.MountPoint) requires pre-boot authentication. " +
                                      "Key protectors: $shown.")
                } elseif ($tpmOnly) {
                    Add-WgResult -Status 'FAIL' -Id 'HRD-STRG-5' `
                        -Title 'BitLocker pre-boot authentication' -Category 'STRG' -Severity 'High' `
                        -Description ("$($v.MountPoint) is protected by the TPM alone (protectors: $shown). " +
                                      'TPM-only BitLocker unlocks the disk before anyone authenticates, so ' +
                                      'it does not defend against an attacker with the powered-off machine: ' +
                                      'the key can be recovered by sniffing the LPC/SPI bus or via a DMA or ' +
                                      'boot-order attack. It protects against a stolen bare disk, and little else.') `
                        -Remediation ("Add-BitLockerKeyProtector -MountPoint $($v.MountPoint) " +
                                      '-TpmAndPinProtector  (and enable the "Require additional authentication ' +
                                      'at startup" policy)')
                } elseif ($removable.Count -gt 0) {
                    Add-WgResult -Status 'WARN' -Id 'HRD-STRG-5' `
                        -Title 'BitLocker pre-boot authentication' -Category 'STRG' -Severity 'High' `
                        -Description ("$($v.MountPoint) unlocks with a startup key rather than a PIN " +
                                      "(protectors: $shown). Better than TPM-only, but a USB key stored " +
                                      'with the machine it unlocks is no protection at all.') `
                        -Remediation ("Prefer a TPM+PIN protector: Add-BitLockerKeyProtector " +
                                      "-MountPoint $($v.MountPoint) -TpmAndPinProtector")
                } else {
                    Add-WgResult -Status 'WARN' -Id 'HRD-STRG-5' `
                        -Title 'BitLocker pre-boot authentication' -Category 'STRG' -Severity 'High' `
                        -Description ("$($v.MountPoint) is protected, but the protector set could not be " +
                                      "classified: $shown. Verify pre-boot authentication manually.")
                }
            }
        }
    } else {
        Add-WgResult -Status 'SKIP' -Id 'HRD-STRG-5' -Title 'BitLocker pre-boot authentication' `
            -Category 'STRG' -Severity 'High' -Description 'The BitLocker module is not available on this host.'
    }

    # ── Writable %PATH% directories: DLL search-order hijacking ──────────────
    Write-WgBanner 'POSTURE - SCHD: writable directories on the system PATH' @(
        'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order'
    )

    # Well-known SIDs rather than account names: a name comparison silently
    # finds nothing on a non-English Windows, which is the usual way this check
    # is written and the usual reason it reports a clean result on a bad host.
    $broadSids = @{
        'S-1-5-32-545' = 'Users'
        'S-1-1-0'      = 'Everyone'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-32-546' = 'Guests'
        'S-1-5-7'      = 'Anonymous Logon'
    }

    $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor
                 [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                 [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                 [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                 [System.Security.AccessControl.FileSystemRights]::Modify -bor
                 [System.Security.AccessControl.FileSystemRights]::FullControl -bor
                 [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                 [System.Security.AccessControl.FileSystemRights]::ChangePermissions

    # The machine PATH, not the process PATH: a user-scoped entry is not a
    # system-wide hijack and would produce a finding on every host.
    $machinePath = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'Path'
    if (-not $machinePath) { $machinePath = $env:Path }

    $pathBad = @(); $pathOk = 0; $pathMissing = 0
    foreach ($raw in ("$machinePath" -split ';')) {
        $folder = "$raw".Trim().Trim('"')
        if (-not $folder) { continue }
        try { $folder = [System.Environment]::ExpandEnvironmentVariables($folder) } catch { }
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { $pathMissing++; continue }
        try {
            $acl = Get-Acl -LiteralPath $folder -ErrorAction Stop
            $hits = @()
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if (-not ($ace.FileSystemRights -band $writeMask)) { continue }
                $sid = $null
                try {
                    $sid = if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                        $ace.IdentityReference.Value
                    } else {
                        $ace.IdentityReference.Translate(
                            [System.Security.Principal.SecurityIdentifier]).Value
                    }
                } catch { $sid = $null }
                if ($sid -and $broadSids.ContainsKey($sid)) { $hits += $broadSids[$sid] }
            }
            if ($hits.Count -gt 0) {
                $pathBad += ("{0} (writable by {1})" -f $folder, (($hits | Sort-Object -Unique) -join ', '))
            } else { $pathOk++ }
        } catch { }
    }

    if ($pathBad.Count -gt 0) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-SCHD-4' `
            -Title 'No system PATH directory is writable by unprivileged users' -Category 'SCHD' `
            -Severity 'High' `
            -Description ("$($pathBad.Count) of $($pathBad.Count + $pathOk) directories on the machine " +
                          'PATH grant write access to a broad group: ' +
                          (($pathBad | Select-Object -First 6) -join '; ') +
                          '. Any process that resolves a DLL by name can be made to load an attacker ' +
                          'DLL planted there, which escalates to whatever account runs that process.') `
            -Remediation 'Remove write access for Users/Everyone/Authenticated Users, or take the directory off the machine PATH'
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-SCHD-4' `
            -Title 'No system PATH directory is writable by unprivileged users' -Category 'SCHD' `
            -Severity 'High' `
            -Description ("All $pathOk readable directories on the machine PATH deny write access to " +
                          'Users, Everyone and Authenticated Users' +
                          $(if ($pathMissing) { " ($pathMissing PATH entries do not exist)" } else { '' }) + '.')
    }

    # ── Application control: deployed is not the same as enforced ────────────
    Write-WgBanner 'POSTURE - TOOL: application control enforcement' @(
        'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol'
        'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applocker-policy-use-scenarios'
    )

    $dgw = Get-WgWmi -Class Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    if ($dgw) {
        # 0 = off, 1 = audit only, 2 = enforced
        foreach ($ci in @(
            @{ Id = 'HRD-TOOL-4'; P = 'CodeIntegrityPolicyEnforcementStatus';         L = 'Kernel-mode' },
            @{ Id = 'HRD-TOOL-5'; P = 'UsermodeCodeIntegrityPolicyEnforcementStatus'; L = 'User-mode' })) {
            $v = "$($dgw.($ci.P))"
            switch ($v) {
                '2' {
                    Add-WgResult -Status 'PASS' -Id $ci.Id `
                        -Title "WDAC $($ci.L) code integrity is enforced" -Category 'TOOL' -Severity 'Medium' `
                        -Description "$($ci.P) is 2 (enforced)."
                }
                '1' {
                    Add-WgResult -Status 'WARN' -Id $ci.Id `
                        -Title "WDAC $($ci.L) code integrity is enforced" -Category 'TOOL' -Severity 'Medium' `
                        -Description ("$($ci.P) is 1 - the policy is in AUDIT mode. It logs what it would " +
                                      'have blocked and blocks nothing, so it provides visibility but no ' +
                                      'protection. This is the state a deployment gets stuck in.') `
                        -Remediation 'Remove the audit-mode option from the WDAC policy and redeploy to enforce it'
                }
                '0' {
                    Add-WgResult -Status 'WARN' -Id $ci.Id `
                        -Title "WDAC $($ci.L) code integrity is enforced" -Category 'TOOL' -Severity 'Medium' `
                        -Description "$($ci.P) is 0 - no WDAC policy is enforcing $($ci.L.ToLower()) code integrity." `
                        -Remediation 'Deploy an App Control for Business (WDAC) policy in audit mode, then enforce it'
                }
                default {
                    Add-WgResult -Status 'INFO' -Id $ci.Id `
                        -Title "WDAC $($ci.L) code integrity is enforced" -Category 'TOOL' -Severity 'Medium' `
                        -Description "$($ci.P) reported '$v', which this build does not recognise."
                }
            }
        }
    } else {
        # Emit both IDs, so a host without Device Guard still reports the same
        # check set and -Baseline does not read them as checks that disappeared.
        foreach ($ci in @(
            @{ Id = 'HRD-TOOL-4'; L = 'Kernel-mode' },
            @{ Id = 'HRD-TOOL-5'; L = 'User-mode' })) {
            Add-WgResult -Status 'SKIP' -Id $ci.Id `
                -Title "WDAC $($ci.L) code integrity is enforced" -Category 'TOOL' -Severity 'Medium' `
                -Description 'Win32_DeviceGuard is not present (Windows Server 2016 and later only).'
        }
    }

    # AppLocker: a policy with a stopped Application Identity service enforces nothing.
    $appIdStart   = Get-WgServiceStart 'AppIDSvc'
    $appIdRunning = Test-WgServiceRunning 'AppIDSvc'
    $hasAppLocker = $false
    try {
        $hasAppLocker = @(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction Stop).Count -gt 0
    } catch { }

    if ($hasAppLocker -and $appIdRunning) {
        Add-WgResult -Status 'PASS' -Id 'HRD-TOOL-6' -Title 'AppLocker policy is actually being enforced' `
            -Category 'TOOL' -Severity 'Medium' `
            -Description 'An AppLocker policy is present and the Application Identity service is running.'
    } elseif ($hasAppLocker -and -not $appIdRunning) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-TOOL-6' -Title 'AppLocker policy is actually being enforced' `
            -Category 'TOOL' -Severity 'High' `
            -Description ('An AppLocker policy is deployed, but the Application Identity service ' +
                          "(AppIDSvc) is not running (start type: $(if ($appIdStart) { $appIdStart } else { 'not installed' })). " +
                          'AppLocker rules are evaluated by that service, so the policy is enforcing ' +
                          'nothing at all - the worst case, because the host looks protected.') `
            -Remediation 'Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc (deploy via GPO so it survives a reboot)'
    } else {
        Add-WgResult -Status 'INFO' -Id 'HRD-TOOL-6' -Title 'AppLocker policy is actually being enforced' `
            -Category 'TOOL' -Severity 'Low' `
            -Description ('No AppLocker policy is present. ' +
                          'HRD-TOOL-3 reports on application control generally; WDAC is the ' +
                          'better choice on current Windows.')
    }

    # ── PowerShell language mode, judged in context ──────────────────────────
    Write-WgBanner 'POSTURE - SHLL: PowerShell language mode' @(
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes'
    )

    $lm = "$($ExecutionContext.SessionState.LanguageMode)"
    $appControlEnforced = ($hasAppLocker -and $appIdRunning) -or
                          ("$($dgw.UsermodeCodeIntegrityPolicyEnforcementStatus)" -eq '2')
    if ($lm -ne 'FullLanguage') {
        Add-WgResult -Status 'PASS' -Id 'HRD-SHLL-3' -Title 'PowerShell language mode' -Category 'SHLL' `
            -Severity 'Medium' `
            -Description ("This session runs in $lm, which blocks arbitrary .NET and Win32 calls - " +
                          'the mechanism most PowerShell tradecraft depends on.')
    } elseif ($appControlEnforced) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-SHLL-3' -Title 'PowerShell language mode' -Category 'SHLL' `
            -Severity 'High' `
            -Description ('This session runs in FullLanguage even though application control is ' +
                          'enforced on this host. Under an enforced WDAC or AppLocker policy PowerShell ' +
                          'should drop to ConstrainedLanguage, so FullLanguage means the policy does not ' +
                          'cover PowerShell and the application control can be bypassed through it.') `
            -Remediation 'Ensure the WDAC/AppLocker policy covers scripts and PowerShell, so it enters ConstrainedLanguage'
    } else {
        Add-WgResult -Status 'INFO' -Id 'HRD-SHLL-3' -Title 'PowerShell language mode' -Category 'SHLL' `
            -Severity 'Low' `
            -Description ('This session runs in FullLanguage. That is the Windows default and is not a ' +
                          'finding on its own - ConstrainedLanguage is a consequence of enforced ' +
                          'application control, not a setting to apply by itself. It is reported here ' +
                          'because it tells you PowerShell is unconstrained on this host.')
    }

    # ── Driver co-installers ─────────────────────────────────────────────────
    Write-WgBanner 'POSTURE - KRNL: driver co-installers & DMA policy' @(
        'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/registering-a-device-specific-co-installer'
        'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-dataprotection'
    )

    $coLegacy = Get-WgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer' 'DisableCoInstallers'
    $coPolicy = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings' 'DisableCoInstallers'
    $coOff = ("$coLegacy" -eq '1' -or "$coPolicy" -eq '1')
    Add-WgResult -Status $(if ($coOff) { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-8' `
        -Title 'Driver co-installers are disabled' -Category 'KRNL' -Severity 'Medium' `
        -Description $(if ($coOff) {
            'DisableCoInstallers is set, so vendor co-installers do not run during device installation.'
        } else {
            ('DisableCoInstallers is not set' +
             $(if ($null -ne $coLegacy -or $null -ne $coPolicy) {
                 " (legacy=$(if ($null -eq $coLegacy) { 'absent' } else { $coLegacy })" +
                 ", policy=$(if ($null -eq $coPolicy) { 'absent' } else { $coPolicy }))"
               } else { '' }) +
             '. A co-installer is vendor code that Plug and Play executes as SYSTEM when a device is ' +
             'attached, so plugging in hardware can run arbitrary software outside your application control.')
        }) `
        -Remediation $(if ($coOff) { '' } else {
            "New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings' " +
            '-Name DisableCoInstallers -PropertyType DWord -Value 1 -Force' })

    # The DataProtection CSP key, which is a different control from the
    # DmaSecurity\AllowDmaUnderLock value checked by HRD-KRNL-6.
    $dmaPolicy = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceLock' 'AllowDirectMemoryAccess'
    Add-WgResult -Status $(if ("$dmaPolicy" -eq '0') { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-9' `
        -Title 'Direct memory access is blocked while the host is locked' -Category 'KRNL' -Severity 'High' `
        -Description $(if ("$dmaPolicy" -eq '0') {
            'AllowDirectMemoryAccess is 0, so DMA-capable devices are blocked while the console is locked.'
        } else {
            ('AllowDirectMemoryAccess is ' +
             $(if ($null -eq $dmaPolicy) { 'not configured, which leaves the permissive default' } else { "$dmaPolicy" }) +
             '. With an external PCIe or Thunderbolt port, a DMA-capable device can read system memory - ' +
             'including BitLocker keys - without unlocking the machine. This is the DataProtection ' +
             'policy; HRD-KRNL-6 covers the separate DmaSecurity value.')
        }) `
        -Remediation $(if ("$dmaPolicy" -eq '0') { '' } else {
            "New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceLock' " +
            '-Name AllowDirectMemoryAccess -PropertyType DWord -Value 0 -Force' })

    $hvciLock = Get-WgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'LockConfiguration'
    Add-WgResult -Status $(if ("$hvciLock" -eq '1') { 'PASS' } else { 'WARN' }) -Id 'HRD-KRNL-10' `
        -Title 'HVCI configuration is locked against local changes' -Category 'KRNL' -Severity 'Medium' `
        -Description $(if ("$hvciLock" -eq '1') {
            'LockConfiguration is 1, so HVCI cannot be turned off without physical presence at the firmware.'
        } else {
            ('HVCI LockConfiguration is ' +
             $(if ($null -eq $hvciLock) { 'not set' } else { "$hvciLock" }) +
             '. Without the UEFI lock, an attacker who gains administrator rights can disable memory ' +
             'integrity with a registry write and a reboot, which removes the protection silently.')
        }) `
        -Remediation $(if ("$hvciLock" -eq '1') { '' } else {
            'Set "Virtualization Based Protection of Code Integrity" to "Enabled with UEFI lock" by Group Policy' })

    # ── AlwaysInstallElevated: exploitable only when BOTH hives are set ──────
    Write-WgBanner 'POSTURE - INSE: AlwaysInstallElevated (both hives)' @(
        'https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated'
    )

    $aieM = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieU = Get-WgRegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if ("$aieM" -eq '1' -and "$aieU" -eq '1') {
        Add-WgResult -Status 'FAIL' -Id 'HRD-INSE-31' -Title 'AlwaysInstallElevated is not exploitable' `
            -Category 'INSE' -Severity 'High' `
            -Description ('AlwaysInstallElevated is 1 in BOTH HKLM and HKCU, which is the exploitable ' +
                          'combination: any user can install an MSI of their choosing as SYSTEM. This is ' +
                          'a direct, reliable local privilege escalation.') `
            -Remediation ('Set AlwaysInstallElevated to 0 (or remove it) under ' +
                          'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer and the HKCU equivalent')
    } elseif ("$aieM" -eq '1' -or "$aieU" -eq '1') {
        Add-WgResult -Status 'WARN' -Id 'HRD-INSE-31' -Title 'AlwaysInstallElevated is not exploitable' `
            -Category 'INSE' -Severity 'Medium' `
            -Description ('AlwaysInstallElevated is set in only one hive ' +
                          "(HKLM=$(if ($null -eq $aieM) { 'absent' } else { $aieM }), " +
                          "HKCU=$(if ($null -eq $aieU) { 'absent' } else { $aieU })). " +
                          'Both are required for the privilege escalation, so this is not currently ' +
                          'exploitable - but it is one policy change away, and the HKCU value read here ' +
                          'is only that of the account running the scan.') `
            -Remediation 'Clear the remaining AlwaysInstallElevated value so the policy cannot be completed'
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-INSE-31' -Title 'AlwaysInstallElevated is not exploitable' `
            -Category 'INSE' -Severity 'High' `
            -Description 'AlwaysInstallElevated is not enabled in either HKLM or HKCU.'
    }

    # ── IPv6 binding: reported, deliberately not failed ─────────────────────
    Write-WgBanner 'POSTURE - INSE: IPv6 binding (mitm6 exposure)' @(
        'https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/'
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows'
    )

    $v6 = $null
    if (Get-Command Get-NetAdapterBinding -ErrorAction SilentlyContinue) {
        try {
            $v6 = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop)
        } catch { $v6 = $null }
    }
    if (-not $v6) {
        Add-WgResult -Status 'SKIP' -Id 'HRD-INSE-32' -Title 'IPv6 binding and mitm6 exposure' `
            -Category 'INSE' -Severity 'Low' `
            -Description ('Adapter bindings could not be enumerated (Get-NetAdapterBinding is ' +
                          'unavailable or returned nothing on this host).')
    } else {
        if ($v6) {
            $on = @($v6 | Where-Object { $_.Enabled })
            Add-WgResult -Status 'INFO' -Id 'HRD-INSE-32' -Title 'IPv6 binding and mitm6 exposure' `
                -Category 'INSE' -Severity 'Low' `
                -Description ("IPv6 is bound on $($on.Count) of $($v6.Count) adapter(s)" +
                              $(if ($on.Count) { ': ' + ((@($on) | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ') } else { '' }) +
                              '. This is reported, not failed: mitm6 abuses rogue DHCPv6/RA on the wire, ' +
                              'and Microsoft does not support disabling IPv6 - doing so breaks components ' +
                              'that assume it. Mitigate on the network with RA Guard and DHCPv6 Guard, ' +
                              'and by setting the WPAD entry to deny. Disable the binding only where you ' +
                              'have confirmed nothing on the host needs it.')
        }
    }

    # ── Recall / Windows AI ──────────────────────────────────────────────────
    Write-WgBanner 'POSTURE - STRG: Recall / Windows AI data' @(
        'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai'
        'https://support.microsoft.com/en-us/windows/privacy-and-control-over-your-recall-experience-d404f672-7647-41e5-886c-a3c59680af15'
    )

    $recallMachine = Get-WgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis'
    $hives = Get-WgUserHives
    $userUnset = @()
    foreach ($hv in $hives) {
        $v = Get-WgRegValue "$($hv.Path)\Software\Policies\Microsoft\Windows\WindowsAI" 'DisableAIDataAnalysis'
        if ("$v" -ne '1') { $userUnset += $hv.Name }
    }

    if ("$recallMachine" -eq '1') {
        Add-WgResult -Status 'PASS' -Id 'HRD-STRG-6' -Title 'Recall (Windows AI) snapshotting is disabled by policy' `
            -Category 'STRG' -Severity 'Medium' `
            -Description ('DisableAIDataAnalysis is 1 machine-wide, so Recall cannot capture screen ' +
                          'snapshots on this host.')
    } else {
        Add-WgResult -Status 'WARN' -Id 'HRD-STRG-6' -Title 'Recall (Windows AI) snapshotting is disabled by policy' `
            -Category 'STRG' -Severity 'Medium' `
            -Description ('DisableAIDataAnalysis is not set machine-wide' +
                          $(if ($userUnset.Count) { ", and is also unset for: $(($userUnset | Select-Object -First 5) -join ', ')" } else { '' }) +
                          '. Recall ships only on Copilot+ hardware and does not exist on Server, so this ' +
                          'is usually not exploitable here - but the policy is the thing that keeps it ' +
                          'that way if the image is ever reused on client hardware. Where Recall does run, ' +
                          'it writes a local, unencrypted-at-rest index of everything on screen.') `
            -Remediation ("New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' " +
                          '-Name DisableAIDataAnalysis -PropertyType DWord -Value 1 -Force')
    }

    # On-disk artefacts: proof it actually ran, regardless of current policy
    $recallHits = @()
    try {
        $userRoot = Join-Path $env:SystemDrive 'Users'
        if (Test-Path -LiteralPath $userRoot) {
            foreach ($u in @(Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue)) {
                $base = Join-Path $u.FullName 'AppData\Local\CoreAIPlatform.00\UKP'
                if (-not (Test-Path -LiteralPath $base)) { continue }
                foreach ($g in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
                    if (Test-Path -LiteralPath (Join-Path $g.FullName 'ukg.db')) {
                        $recallHits += "$($u.Name): ukg.db"
                    }
                    $img = Join-Path $g.FullName 'ImageStore'
                    if ((Test-Path -LiteralPath $img) -and
                        @(Get-ChildItem -LiteralPath $img -ErrorAction SilentlyContinue).Count -gt 0) {
                        $recallHits += "$($u.Name): ImageStore with content"
                    }
                }
            }
        }
    } catch { }

    if ($recallHits.Count -gt 0) {
        Add-WgResult -Status 'FAIL' -Id 'HRD-STRG-7' -Title 'No Recall snapshot data is present on disk' `
            -Category 'STRG' -Severity 'High' `
            -Description ("Recall artefacts were found for $($recallHits.Count) profile path(s): " +
                          (($recallHits | Select-Object -First 6) -join '; ') +
                          '. The database and image store hold plaintext-readable screen captures, ' +
                          'available to anything running as that user, so they are a credential and ' +
                          'data-exposure problem independent of whether Recall is enabled now.') `
            -Remediation ('Disable Recall by policy, then delete %LOCALAPPDATA%\CoreAIPlatform.00\UKP ' +
                          'for each affected profile')
    } else {
        Add-WgResult -Status 'PASS' -Id 'HRD-STRG-7' -Title 'No Recall snapshot data is present on disk' `
            -Category 'STRG' -Severity 'High' `
            -Description 'No Recall database or image store was found in any user profile on this host.'
    }

    # ── Installed software inventory ─────────────────────────────────────────
    Write-WgBanner 'POSTURE - PKGS: installed software inventory'

    $sw = @{}
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        try {
            foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $n = Get-WgRegValue $k.PSPath 'DisplayName'
                if (-not $n) { continue }
                $ver = Get-WgRegValue $k.PSPath 'DisplayVersion'
                $sw["$n"] = "$ver"
            }
        } catch { }
    }
    if ($sw.Count -gt 0) {
        $listed = @($sw.Keys | Sort-Object | Select-Object -First 25 |
            ForEach-Object { if ($sw[$_]) { "$_ $($sw[$_])" } else { "$_" } })
        Add-WgResult -Status 'INFO' -Id 'HRD-PKGS-3' -Title 'Installed software inventory' `
            -Category 'PKGS' -Severity 'Low' `
            -Description ("$($sw.Count) machine-wide product(s) are registered. " +
                          "First $($listed.Count) by name: " + ($listed -join '; ') +
                          '. The full list is in the CSV report. Review it for unsupported, ' +
                          'unmanaged or end-of-life software - an audit of the OS says nothing ' +
                          'about the things running on it.')
    } else {
        Add-WgResult -Status 'INFO' -Id 'HRD-PKGS-3' -Title 'Installed software inventory' `
            -Category 'PKGS' -Severity 'Low' `
            -Description 'No machine-wide installed products could be enumerated from the uninstall keys.'
    }

    # ── Domain password policy ───────────────────────────────────────────────
    # The local security policy that the account-policy benchmark rows read is
    # NOT the policy that governs domain accounts: for a domain-joined host the
    # Default Domain Policy at the DC is what applies. On a domain controller
    # that is local information. Anywhere else, reading it means talking to a
    # DC over the network, which this tool does not do unless asked, so it is
    # behind -IncludeDomainPolicy.
    if ($script:IsDC -or $script:IncludeDomainPol) {
        Write-WgBanner 'POSTURE - AUTH: domain password & lockout policy' @(
            'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy'
            'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad'
        )

        $pol = $null
        $why = ''
        try {
            if (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {
                $pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            } else {
                $why = 'the ActiveDirectory module (RSAT) is not installed'
            }
        } catch {
            $why = "the query failed: $($_.Exception.Message)"
        }

        if (-not $pol) {
            Add-WgResult -Status 'SKIP' -Id 'HRD-AUTH-13' -Title 'Domain password and lockout policy' `
                -Category 'AUTH' -Severity 'High' `
                -Description ("The Default Domain Password Policy could not be read because $why. " +
                              'The account-policy findings elsewhere in this report describe the LOCAL ' +
                              'security policy, which does not govern domain accounts.') `
                -Remediation 'Install RSAT (Install-WindowsFeature RSAT-AD-PowerShell) or run this check on a domain controller'
        } else {
            $src = if ($script:IsDC) { 'this domain controller' } else { 'the domain' }

            Add-WgResult -Status $(if ($pol.MinPasswordLength -ge 14) { 'PASS' }
                                   elseif ($pol.MinPasswordLength -ge 12) { 'WARN' } else { 'FAIL' }) `
                -Id 'HRD-AUTH-13' -Title 'Domain minimum password length' -Category 'AUTH' -Severity 'High' `
                -Description ("The Default Domain Policy on $src sets a minimum password length of " +
                              "$($pol.MinPasswordLength). CIS asks for 14 or more.") `
                -Remediation $(if ($pol.MinPasswordLength -ge 14) { '' } else {
                    'Set-ADDefaultDomainPasswordPolicy -Identity <domain> -MinPasswordLength 14' })

            Add-WgResult -Status $(if ($pol.ComplexityEnabled) { 'PASS' } else { 'FAIL' }) `
                -Id 'HRD-AUTH-14' -Title 'Domain password complexity' -Category 'AUTH' -Severity 'High' `
                -Description "ComplexityEnabled is $($pol.ComplexityEnabled) on $src." `
                -Remediation $(if ($pol.ComplexityEnabled) { '' } else {
                    'Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ComplexityEnabled $true' })

            Add-WgResult -Status $(if (-not $pol.ReversibleEncryptionEnabled) { 'PASS' } else { 'FAIL' }) `
                -Id 'HRD-AUTH-15' -Title 'Domain reversible password encryption is off' -Category 'AUTH' `
                -Severity 'High' `
                -Description ("ReversibleEncryptionEnabled is $($pol.ReversibleEncryptionEnabled) on $src." +
                              $(if ($pol.ReversibleEncryptionEnabled) {
                                  ' This stores passwords in a recoverable form, which is equivalent to plaintext.'
                                } else { '' })) `
                -Remediation $(if (-not $pol.ReversibleEncryptionEnabled) { '' } else {
                    'Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ReversibleEncryptionEnabled $false' })

            $lt = [int] $pol.LockoutThreshold
            Add-WgResult -Status $(if ($lt -gt 0 -and $lt -le 10) { 'PASS' }
                                   elseif ($lt -eq 0) { 'FAIL' } else { 'WARN' }) `
                -Id 'HRD-AUTH-16' -Title 'Domain account lockout threshold' -Category 'AUTH' -Severity 'High' `
                -Description $(if ($lt -eq 0) {
                    "LockoutThreshold is 0 on $src, so accounts never lock and password spraying is unlimited."
                } else {
                    "LockoutThreshold is $lt on $src (CIS asks for 1-10, and not 0)."
                }) `
                -Remediation $(if ($lt -gt 0 -and $lt -le 10) { '' } else {
                    'Set-ADDefaultDomainPasswordPolicy -Identity <domain> -LockoutThreshold 10' })

            $ld = [int] $pol.LockoutDuration.TotalMinutes
            Add-WgResult -Status $(if ($ld -ge 15 -or $ld -eq 0) { 'PASS' } else { 'WARN' }) `
                -Id 'HRD-AUTH-17' -Title 'Domain account lockout duration' -Category 'AUTH' -Severity 'Medium' `
                -Description ("LockoutDuration is $ld minute(s) on $src" +
                              $(if ($ld -eq 0) { ' (locked until an administrator unlocks, which satisfies the benchmark).' }
                                else { ' (CIS asks for 15 or more).' })) `
                -Remediation $(if ($ld -ge 15 -or $ld -eq 0) { '' } else {
                    'Set-ADDefaultDomainPasswordPolicy -Identity <domain> -LockoutDuration 00:15:00' })

            Add-WgResult -Status 'INFO' -Id 'HRD-AUTH-18' -Title 'Domain password policy detail' `
                -Category 'AUTH' -Severity 'Low' `
                -Description ("History $($pol.PasswordHistoryCount), min age " +
                              "$([int] $pol.MinPasswordAge.TotalDays)d, max age " +
                              "$([int] $pol.MaxPasswordAge.TotalDays)d, lockout observation window " +
                              "$([int] $pol.LockoutObservationWindow.TotalMinutes)min. Note that a " +
                              'fine-grained password policy (PSO) can override all of this for specific ' +
                              'users or groups - check Get-ADFineGrainedPasswordPolicy as well.')
        }
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# ESCAPING
# JSON is emitted by hand rather than through ConvertTo-Json: it keeps one
# result per line (so grep and Select-String work inside an enclave with no
# jq), it produces identical output on PowerShell 3 through 7, and it avoids
# ConvertTo-Json's depth and ordering surprises.
# ─────────────────────────────────────────────────────────────────────────────
function ConvertTo-WgJsonString {
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $c = [int] $ch
        switch ($ch) {
            '"'  { [void] $sb.Append('\"') }
            '\'  { [void] $sb.Append('\\') }
            "`n" { [void] $sb.Append('\n') }
            "`r" { [void] $sb.Append('\r') }
            "`t" { [void] $sb.Append('\t') }
            "`b" { [void] $sb.Append('\b') }
            "`f" { [void] $sb.Append('\f') }
            default {
                if ($c -lt 32 -or $c -eq 127) { [void] $sb.Append(('\u{0:x4}' -f $c)) }
                else { [void] $sb.Append($ch) }
            }
        }
    }
    return $sb.ToString()
}

function ConvertTo-WgHtml {
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    $v = $Value -replace '&', '&amp;'
    $v = $v -replace '<', '&lt;'
    $v = $v -replace '>', '&gt;'
    $v = $v -replace '"', '&quot;'
    $v = $v -replace "'", '&#39;'
    $v = $v -replace "`r`n", '<br>'
    $v = $v -replace "`n", '<br>'
    return $v
}

function ConvertTo-WgCsvField {
    param([string] $Value)
    $v = "$Value" -replace '"', '""'
    $v = $v -replace "[`r`n]+", ' '
    # Guard against spreadsheet formula injection: a finding that starts with
    # =, +, - or @ would otherwise be evaluated when the CSV is opened.
    if ($v -match '^[=+@\-]') { $v = "'" + $v }
    return '"' + $v + '"'
}

# Split-Path throws on an empty path, so unset -Baseline / -Waivers would abort
# the report writer part-way through and leave a truncated file behind.
function Get-WgLeafName {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    try { return (Split-Path -Leaf $Path) } catch { return $Path }
}

# ─────────────────────────────────────────────────────────────────────────────
# SCORING - PASS / (PASS + FAIL + WARN)
# INFO, SKIP and WAIVED are excluded, so a non-admin run or a set of documented
# waivers does not make a well-configured host look broken.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgCompliancePct {
    $denom = $script:Counts.PASS + $script:Counts.FAIL + $script:Counts.WARN
    if ($denom -le 0) { return '0.0' }
    return ('{0:F1}' -f (($script:Counts.PASS / $denom) * 100))
}

# ─────────────────────────────────────────────────────────────────────────────
# WAIVERS
# ─────────────────────────────────────────────────────────────────────────────
function Import-WgWaivers {
    param([string] $Path)
    $map = @{}
    if (-not $Path) { return $map }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "Waiver file not readable: $Path" -ForegroundColor Red
        exit 1
    }
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $l = "$line".Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        $parts = $l -split '\|', 2
        $id = $parts[0].Trim()
        $reason = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
        if ($id) { $map[$id.ToLower()] = $reason }
    }
    return $map
}

# ─────────────────────────────────────────────────────────────────────────────
# DRIFT vs BASELINE
# Parsed with a regex over WinGuard's own one-result-per-line JSON, so a
# baseline taken by any version (or by the Python engine) can be read back
# without a JSON parser being available.
# ─────────────────────────────────────────────────────────────────────────────
function Get-WgDrift {
    param([string] $BaselinePath)
    if (-not $BaselinePath) { return }
    if (-not (Test-Path -LiteralPath $BaselinePath)) {
        Write-Host "Baseline not readable: $BaselinePath" -ForegroundColor Red
        exit 1
    }

    $old = @{}
    foreach ($line in (Get-Content -LiteralPath $BaselinePath -ErrorAction SilentlyContinue)) {
        $l = "$line"
        if ($l -match '"change"\s*:') { continue }          # skip the drift block
        if ($l -notmatch '"id"\s*:\s*"([^"]*)"') { continue }
        $id = $Matches[1]
        if ($l -match '"status"\s*:\s*"([^"]*)"') { $old[$id] = $Matches[1] }
    }
    if ($old.Count -eq 0) {
        Write-WgLog "Baseline contained no readable results: $BaselinePath"
        return
    }

    foreach ($r in $script:Results) {
        $o = if ($old.ContainsKey($r.id)) { $old[$r.id] } else { $null }
        $isBad = ($r.status -eq 'FAIL' -or $r.status -eq 'WARN')
        if ($null -eq $o) {
            if ($isBad) {
                [void] $script:DriftRows.Add([PSCustomObject] @{
                    change = 'NEW'; id = $r.id; from = '-'; to = $r.status; title = $r.title })
                $script:DriftNew++
            }
            continue
        }
        if ($o -eq $r.status) { continue }
        $oWasBad = ($o -eq 'FAIL' -or $o -eq 'WARN')
        $kind =
            if ($isBad -and -not $oWasBad)                 { 'REGRESSED' }
            elseif ($r.status -eq 'PASS' -and $oWasBad)    { 'FIXED' }
            else                                            { 'CHANGED' }
        [void] $script:DriftRows.Add([PSCustomObject] @{
            change = $kind; id = $r.id; from = $o; to = $r.status; title = $r.title })
        if ($kind -eq 'REGRESSED') { $script:DriftNew++ }
        if ($kind -eq 'FIXED')     { $script:DriftFixed++ }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────────────────────────────────────────
function Write-WgJsonReport {
    param([string] $Path)
    $sw = New-Object System.IO.StreamWriter($Path, $false, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $elapsed = [int] ((Get-Date) - $script:StartTime).TotalSeconds
        $j = { param($v) ConvertTo-WgJsonString $v }

        $sw.WriteLine('{')
        $sw.WriteLine('  "tool": "' + (& $j $script:ToolName) + '",')
        $sw.WriteLine('  "version": "' + (& $j $script:ToolVersion) + '",')
        $sw.WriteLine('  "engine": "' + (& $j $script:ToolEngine) + '",')
        $sw.WriteLine('  "script_sha256": "' + (& $j $script:ScriptSha) + '",')
        $sw.WriteLine('  "hostname": "' + (& $j $script:HostName) + '",')
        $sw.WriteLine('  "scan_date": "' + (Get-Date).ToString('o') + '",')
        $sw.WriteLine('  "os": "' + (& $j $script:OsCaption) + '",')
        $sw.WriteLine('  "os_version": "' + (& $j $script:OsVersion) + '",')
        $sw.WriteLine('  "os_build": ' + $script:OsBuild + ',')
        $sw.WriteLine('  "os_baseline": "' + (& $j $script:OsToken) + '",')
        $sw.WriteLine('  "role": "' + (& $j $script:OsRole) + '",')
        $sw.WriteLine('  "domain_role": "' + (& $j $script:DomainRole) + '",')
        $sw.WriteLine('  "is_server": ' + $script:IsServer.ToString().ToLower() + ',')
        $sw.WriteLine('  "powershell": "' + (& $j "$($PSVersionTable.PSVersion)") + '",')
        $sw.WriteLine('  "scan_mode": "' + (& $j $script:ScanMode) + '",')
        $sw.WriteLine('  "run_as_admin": ' + $script:IsAdmin.ToString().ToLower() + ',')
        $sw.WriteLine('  "duration_seconds": ' + $elapsed + ',')
        $sw.WriteLine('  "baseline": "' + (& $j (Get-WgLeafName $script:BaselinePath)) + '",')
        $sw.WriteLine('  "waiver_file": "' + (& $j (Get-WgLeafName $script:WaiverPath)) + '",')
        $sw.WriteLine('  "summary": {')
        $sw.WriteLine('    "total": ' + $script:Counts.TOTAL + ',')
        $sw.WriteLine('    "pass": ' + $script:Counts.PASS + ',')
        $sw.WriteLine('    "fail": ' + $script:Counts.FAIL + ',')
        $sw.WriteLine('    "warn": ' + $script:Counts.WARN + ',')
        $sw.WriteLine('    "info": ' + $script:Counts.INFO + ',')
        $sw.WriteLine('    "skip": ' + $script:Counts.SKIP + ',')
        $sw.WriteLine('    "waived": ' + $script:Counts.WAIVED + ',')
        $sw.WriteLine('    "priv_skip": ' + $script:Counts.PRIV_SKIP + ',')
        $sw.WriteLine('    "compliance_pct": ' + (Get-WgCompliancePct) + ',')
        $sw.WriteLine('    "compliance_formula": "pass/(pass+fail+warn)",')
        $sw.WriteLine('    "drift_new_or_regressed": ' + $script:DriftNew + ',')
        $sw.WriteLine('    "drift_fixed": ' + $script:DriftFixed)
        $sw.WriteLine('  },')

        $sw.WriteLine('  "by_framework": {')
        $fw = @('CIS', 'STIG', 'MSFT-BASELINE', 'POSTURE', 'AIRGAP')
        $fwLines = @()
        foreach ($f in $fw) {
            $rs = @($script:Results | Where-Object { $_.framework -eq $f })
            if ($rs.Count -eq 0) { continue }
            $p = @($rs | Where-Object { $_.status -eq 'PASS' }).Count
            $fl = @($rs | Where-Object { $_.status -eq 'FAIL' }).Count
            $w = @($rs | Where-Object { $_.status -eq 'WARN' }).Count
            $den = $p + $fl + $w
            $pct = if ($den -gt 0) { '{0:F1}' -f (($p / $den) * 100) } else { '0.0' }
            $fwLines += ('    "' + (& $j $f) + '": {"total": ' + $rs.Count + ', "pass": ' + $p +
                         ', "fail": ' + $fl + ', "warn": ' + $w + ', "compliance_pct": ' + $pct + '}')
        }
        $sw.WriteLine(($fwLines -join ",`r`n"))
        $sw.WriteLine('  },')

        $sw.WriteLine('  "drift": [')
        $dl = @()
        foreach ($d in $script:DriftRows) {
            $dl += ('    {"change": "' + (& $j $d.change) + '", "id": "' + (& $j $d.id) +
                    '", "from": "' + (& $j $d.from) + '", "to": "' + (& $j $d.to) +
                    '", "title": "' + (& $j $d.title) + '"}')
        }
        if ($dl.Count -gt 0) { $sw.WriteLine(($dl -join ",`r`n")) }
        $sw.WriteLine('  ],')

        # One result per line is intentional: it keeps the file greppable and
        # diffable, which matters when the enclave has no JSON tooling.
        $sw.WriteLine('  "results": [')
        $first = $true
        foreach ($r in $script:Results) {
            $prefix = if ($first) { '    ' } else { '   ,' }
            $first = $false
            $sw.WriteLine($prefix + '{"id":"' + (& $j $r.id) + '","status":"' + (& $j $r.status) +
                '","framework":"' + (& $j $r.framework) + '","severity":"' + (& $j $r.severity) +
                '","title":"' + (& $j $r.title) + '","category":"' + (& $j $r.category) +
                '","description":"' + (& $j $r.description) + '","remediation":"' + (& $j $r.remediation) +
                '","refs":"' + (& $j $r.refs) + '","os":"' + (& $j $r.os) +
                '","role":"' + (& $j $r.role) + '","ts":"' + (& $j $r.ts) + '"}')
        }
        $sw.WriteLine('  ]')
        $sw.WriteLine('}')
    } catch {
        # A partially written report is worse than none: it looks valid and is
        # not. Report the failure loudly and remove the fragment.
        $sw.Close()
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        Write-Host "ERROR: the JSON report could not be written: $($_.Exception.Message)" -ForegroundColor Red
        throw
    } finally {
        $sw.Close()
    }
    return $Path
}

# ─────────────────────────────────────────────────────────────────────────────
# CSV REPORT
# ─────────────────────────────────────────────────────────────────────────────
function Write-WgCsvReport {
    param([string] $Path)
    $sw = New-Object System.IO.StreamWriter($Path, $false, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $sw.WriteLine('"id","status","framework","severity","category","title","description","reference","remediation"')
        foreach ($r in $script:Results) {
            $sw.WriteLine((@(
                (ConvertTo-WgCsvField $r.id), (ConvertTo-WgCsvField $r.status),
                (ConvertTo-WgCsvField $r.framework), (ConvertTo-WgCsvField $r.severity),
                (ConvertTo-WgCsvField $r.category), (ConvertTo-WgCsvField $r.title),
                (ConvertTo-WgCsvField $r.description), (ConvertTo-WgCsvField $r.refs),
                (ConvertTo-WgCsvField $r.remediation)
            ) -join ','))
        }
    } catch {
        $sw.Close()
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        Write-Host "ERROR: the CSV report could not be written: $($_.Exception.Message)" -ForegroundColor Red
        throw
    } finally { $sw.Close() }
    return $Path
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT - a standalone dashboard. The Content-Security-Policy is what
# makes it safe to carry out of an enclave: the page cannot load or send
# anything, so it can be opened on any workstation without a callback.
# ─────────────────────────────────────────────────────────────────────────────
function Write-WgHtmlReport {
    param([string] $Path)

    $pct     = Get-WgCompliancePct
    $pctInt  = [int] ([double] $pct)
    $elapsed = [int] ((Get-Date) - $script:StartTime).TotalSeconds
    $scoreColor = if ($pctInt -ge 80) { '#27ae60' } elseif ($pctInt -ge 60) { '#f39c12' } else { '#e74c3c' }

    $h = { param($v) ConvertTo-WgHtml $v }
    $c = $script:Counts

    $sw = New-Object System.IO.StreamWriter($Path, $false, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $sw.Write(@'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Air-gap safe: this report can never load or send anything over the network -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<style>
:root{--pass:#27ae60;--fail:#e74c3c;--warn:#f39c12;--info:#3498db;--skip:#7f8c8d;--waived:#8e44ad;
  --bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#1f6feb;--head:#21262d}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;font-size:14px}
a{color:var(--accent);text-decoration:none}
.header{display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.logo{font-size:2rem;font-weight:900;letter-spacing:-1px;
  background:linear-gradient(135deg,#1f6feb,#56d4dd);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header-meta{font-size:.8rem;color:#8b949e;line-height:1.7}
.header-meta strong{color:var(--text)}
.score-row{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.score-card{background:var(--head);border:1px solid var(--border);border-radius:12px;
  padding:20px 28px;display:flex;align-items:center;gap:20px;flex:1;min-width:260px}
.score-circle{width:80px;height:80px;border-radius:50%;border:5px solid #e74c3c;
  display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:700;color:#e74c3c;flex-shrink:0}
.score-detail h2{font-size:1rem;font-weight:600;color:var(--text)}
.score-detail p{font-size:.8rem;color:#8b949e;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--head);border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center}
.card .num{font-size:2rem;font-weight:700}
.card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-top:2px}
.fw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:20px}
.fw{background:var(--head);border:1px solid var(--border);border-radius:10px;padding:12px 16px}
.fw h4{font-size:.78rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-bottom:6px}
.fw .pc{font-size:1.5rem;font-weight:700}
.fw .dt{font-size:.72rem;color:#8b949e;margin-top:3px}
.controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;align-items:center}
.search{flex:1;min-width:200px;padding:8px 12px;border-radius:6px;
  background:var(--head);border:1px solid var(--border);color:var(--text);font-size:.85rem}
.filter-btn{padding:6px 14px;border-radius:20px;border:none;cursor:pointer;
  font-size:.78rem;font-weight:600;transition:opacity .15s;opacity:.7}
.filter-btn:hover,.filter-btn.active{opacity:1}
.fb-all{background:#484f58;color:#fff}
.fb-PASS{background:var(--pass);color:#fff}.fb-FAIL{background:var(--fail);color:#fff}
.fb-WARN{background:var(--warn);color:#000}.fb-INFO{background:var(--info);color:#fff}
.fb-SKIP{background:var(--skip);color:#fff}.fb-WAIVED{background:var(--waived);color:#fff}
.fg{background:#30363d;color:#c9d1d9}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{background:var(--head);border-bottom:1px solid var(--border);padding:10px 12px;text-align:left;
  font-weight:600;color:#8b949e;text-transform:uppercase;font-size:.72rem;letter-spacing:.5px}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:700;font-size:.7rem;white-space:nowrap}
.b-PASS{background:var(--pass);color:#fff}.b-FAIL{background:var(--fail);color:#fff}
.b-WARN{background:var(--warn);color:#000}.b-INFO{background:var(--info);color:#fff}
.b-SKIP{background:var(--skip);color:#fff}.b-WAIVED{background:var(--waived);color:#fff}
.fwtag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.66rem;font-weight:700;
  background:#1f6feb22;color:#79c0ff;border:1px solid #1f6feb55;white-space:nowrap}
.sev{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.66rem;font-weight:700}
.sev-High{background:#e74c3c22;color:#ff7b72;border:1px solid #e74c3c55}
.sev-Medium{background:#f39c1222;color:#f0b849;border:1px solid #f39c1255}
.sev-Low{background:#7f8c8d22;color:#9aa5ad;border:1px solid #7f8c8d55}
.id-cell{font-family:Consolas,monospace;font-size:.78rem;color:#79c0ff;white-space:nowrap}
.ref{font-family:Consolas,monospace;font-size:.7rem;color:#8b949e;display:block;margin-top:2px}
.rem{font-size:.75rem;color:#f39c12;margin-top:5px;font-family:Consolas,monospace;
  background:rgba(243,156,18,.08);padding:4px 8px;border-radius:4px;display:block;word-break:break-word}
.prog-bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-bottom:20px}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--fail) 0%,var(--warn) 50%,var(--pass) 100%)}
.priv-warn{background:rgba(243,156,18,.12);border:1px solid var(--warn);border-radius:8px;
  padding:12px 16px;margin-bottom:20px;font-size:.85rem;color:var(--warn)}
.drift{background:var(--head);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin-bottom:20px}
.drift h3{font-size:.9rem;margin-bottom:8px}
.drift td{padding:5px 10px}
.d-REGRESSED,.d-NEW{color:var(--fail);font-weight:700}
.d-FIXED{color:var(--pass);font-weight:700}.d-CHANGED{color:var(--warn)}
.desc{color:#8b949e}
.sha{font-family:Consolas,monospace;font-size:.72rem;color:#8b949e;word-break:break-all}
footer{margin-top:30px;font-size:.72rem;color:#484f58;text-align:center;padding:10px;line-height:1.8}
@media print{body{background:#fff;color:#000}.controls{display:none}}
</style>
'@)
        $sw.WriteLine('<title>WinGuard - ' + (& $h $script:HostName) + ' - ' + $script:ReportTs + '</title>')
        $sw.WriteLine('</head>')
        $sw.WriteLine('<body>')
        $sw.WriteLine('<div class="header">')
        $sw.WriteLine('  <div class="logo">WinGuard</div>')
        $sw.WriteLine('  <div class="header-meta">')
        $sw.WriteLine('    <div>&#128187; <strong>' + (& $h $script:HostName) + '</strong> &nbsp;|&nbsp; &#128197; <strong>' +
            (& $h (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')) + '</strong></div>')
        $sw.WriteLine('    <div>&#129521; <strong>' + (& $h $script:OsCaption) + '</strong> &nbsp;|&nbsp; build <strong>' +
            $script:OsBuild + '</strong> &nbsp;|&nbsp; baseline <strong>' + (& $h $script:OsToken) +
            '</strong> &nbsp;|&nbsp; <strong>' + (& $h $script:DomainRole) + '</strong></div>')
        $sw.WriteLine('    <div>&#9881; Mode: <strong>' + (& $h $script:ScanMode) +
            '</strong> &nbsp;|&nbsp; &#128273; Admin: <strong>' + $script:IsAdmin +
            '</strong> &nbsp;|&nbsp; PS <strong>' + (& $h "$($PSVersionTable.PSVersion)") +
            '</strong> &nbsp;|&nbsp; &#9201; ' + $elapsed + 's &nbsp;|&nbsp; v' + $script:ToolVersion + '</div>')
        $sw.WriteLine('    <div class="sha">script sha256: ' + (& $h $script:ScriptSha) + '</div>')
        $sw.WriteLine('  </div>')
        $sw.WriteLine('</div>')

        if (-not $script:IsAdmin) {
            $sw.WriteLine('<div class="priv-warn">&#9888; &nbsp;<strong>Non-administrator scan</strong> &mdash; ' +
                $c.PRIV_SKIP + ' privileged checks were skipped. Re-run from an elevated PowerShell prompt for full coverage.</div>')
        }

        $sw.WriteLine('<div class="score-row"><div class="score-card">')
        $sw.WriteLine('  <div class="score-circle" style="border-color:' + $scoreColor + ';color:' + $scoreColor + '">' + $pct + '%</div>')
        $sw.WriteLine('  <div class="score-detail"><h2>Compliance Score</h2>')
        $sw.WriteLine('    <p>' + $c.PASS + ' passed &middot; ' + $c.FAIL + ' failed &middot; ' + $c.WARN +
            ' warnings &middot; ' + $c.WAIVED + ' waived &middot; ' + $c.SKIP + ' skipped</p>')
        $sw.WriteLine('    <p style="margin-top:8px;color:#8b949e">Score = pass &divide; (pass + fail + warn) &middot; ' +
            $c.TOTAL + ' checks total. INFO, SKIP and WAIVED are excluded.</p>')
        $sw.WriteLine('  </div></div></div>')
        $sw.WriteLine('<div class="prog-bar"><div class="prog-fill" style="width:' + $pct + '%"></div></div>')

        $sw.WriteLine('<div class="cards">')
        foreach ($k in @(
            @{ L = 'Pass'; V = $c.PASS; C = 'var(--pass)' }, @{ L = 'Fail'; V = $c.FAIL; C = 'var(--fail)' },
            @{ L = 'Warn'; V = $c.WARN; C = 'var(--warn)' }, @{ L = 'Waived'; V = $c.WAIVED; C = 'var(--waived)' },
            @{ L = 'Info'; V = $c.INFO; C = 'var(--info)' }, @{ L = 'Skip'; V = $c.SKIP; C = 'var(--skip)' },
            @{ L = 'Total'; V = $c.TOTAL; C = 'var(--text)' })) {
            $sw.WriteLine('  <div class="card"><div class="num" style="color:' + $k.C + '">' + $k.V +
                '</div><div class="lbl">' + $k.L + '</div></div>')
        }
        $sw.WriteLine('</div>')

        # Per-framework score cards
        $fwOrder = @(
            @{ K = 'CIS'; L = 'CIS Benchmark' }, @{ K = 'STIG'; L = 'DISA STIG' }
            @{ K = 'MSFT-BASELINE'; L = 'MS Security Baseline' }
            @{ K = 'POSTURE'; L = 'Hardening Posture' }, @{ K = 'AIRGAP'; L = 'Air-gap Isolation' })
        $any = $false
        $fwHtml = New-Object System.Text.StringBuilder
        foreach ($f in $fwOrder) {
            $rs = @($script:Results | Where-Object { $_.framework -eq $f.K })
            if ($rs.Count -eq 0) { continue }
            $any = $true
            $p = @($rs | Where-Object { $_.status -eq 'PASS' }).Count
            $fl = @($rs | Where-Object { $_.status -eq 'FAIL' }).Count
            $w = @($rs | Where-Object { $_.status -eq 'WARN' }).Count
            $den = $p + $fl + $w
            $fp = if ($den -gt 0) { '{0:F1}' -f (($p / $den) * 100) } else { '0.0' }
            $fpi = [int] ([double] $fp)
            $col = if ($fpi -ge 80) { 'var(--pass)' } elseif ($fpi -ge 60) { 'var(--warn)' } else { 'var(--fail)' }
            [void] $fwHtml.AppendLine('  <div class="fw"><h4>' + (& $h $f.L) + '</h4><div class="pc" style="color:' +
                $col + '">' + $fp + '%</div><div class="dt">' + $rs.Count + ' checks &middot; ' + $p +
                ' pass &middot; ' + $fl + ' fail &middot; ' + $w + ' warn</div></div>')
        }
        if ($any) {
            $sw.WriteLine('<div class="fw-grid">')
            $sw.Write($fwHtml.ToString())
            $sw.WriteLine('</div>')
        }

        if ($script:BaselinePath) {
            $sw.WriteLine('<div class="drift"><h3>&#128200; Drift since baseline <code>' +
                (& $h (Get-WgLeafName $script:BaselinePath)) + '</code> &mdash; ' + $script:DriftNew +
                ' new/regressed &middot; ' + $script:DriftFixed + ' fixed &middot; ' +
                $script:DriftRows.Count + ' changed</h3>')
            if ($script:DriftRows.Count -gt 0) {
                $sw.WriteLine('<table><thead><tr><th>Change</th><th>Check ID</th><th>From</th><th>To</th><th>Title</th></tr></thead><tbody>')
                foreach ($d in $script:DriftRows) {
                    $sw.WriteLine('<tr><td class="d-' + (& $h $d.change) + '">' + (& $h $d.change) +
                        '</td><td class="id-cell">' + (& $h $d.id) + '</td><td>' + (& $h $d.from) +
                        '</td><td>' + (& $h $d.to) + '</td><td>' + (& $h $d.title) + '</td></tr>')
                }
                $sw.WriteLine('</tbody></table>')
            } else {
                $sw.WriteLine('<p>No changes since the baseline.</p>')
            }
            $sw.WriteLine('</div>')
        }

        $sw.WriteLine('<div class="controls">')
        $sw.WriteLine('  <input class="search" type="text" id="srch" placeholder="&#128269; Search checks, categories, registry paths, references..." onkeyup="ft()">')
        $sw.WriteLine('  <button class="filter-btn fb-all active" onclick="sf(this,0,' + "'all'" + ')">All (' + $c.TOTAL + ')</button>')
        foreach ($s in @('FAIL', 'WARN', 'PASS', 'WAIVED', 'INFO', 'SKIP')) {
            $sw.WriteLine('  <button class="filter-btn fb-' + $s + '" onclick="sf(this,0,' + "'$s'" + ')">' +
                $s.Substring(0, 1) + $s.Substring(1).ToLower() + ' (' + $c[$s] + ')</button>')
        }
        foreach ($f in $fwOrder) {
            $n = @($script:Results | Where-Object { $_.framework -eq $f.K }).Count
            if ($n -eq 0) { continue }
            $sw.WriteLine('  <button class="filter-btn fg" onclick="sf(this,1,' + "'$($f.K)'" + ')">' +
                (& $h $f.L) + ' (' + $n + ')</button>')
        }
        $sw.WriteLine('</div>')

        $sw.WriteLine('<table id="t"><thead><tr>')
        $sw.WriteLine('  <th style="width:70px">Status</th><th style="width:150px">Check ID</th>')
        $sw.WriteLine('  <th style="width:150px">Category</th><th style="width:70px">Severity</th>')
        $sw.WriteLine('  <th>Finding &amp; Remediation</th>')
        $sw.WriteLine('</tr></thead><tbody id="tb">')
        foreach ($r in $script:Results) {
            $rem = if ($r.remediation) { '<span class="rem">&#128295; ' + (& $h $r.remediation) + '</span>' } else { '' }
            $ref = if ($r.refs) { '<span class="ref">' + (& $h $r.refs) + '</span>' } else { '' }
            $sw.WriteLine('<tr data-s="' + (& $h $r.status) + '" data-f="' + (& $h $r.framework) + '">' +
                '<td><span class="badge b-' + (& $h $r.status) + '">' + (& $h $r.status) + '</span></td>' +
                '<td class="id-cell">' + (& $h $r.id) + '<span class="ref"><span class="fwtag">' +
                (& $h $r.framework) + '</span></span></td>' +
                '<td>' + (& $h $r.category) + '</td>' +
                '<td><span class="sev sev-' + (& $h $r.severity) + '">' + (& $h $r.severity) + '</span></td>' +
                '<td><strong>' + (& $h $r.title) + '</strong><br><small class="desc">' +
                (& $h $r.description) + '</small>' + $ref + $rem + '</td></tr>')
        }
        $sw.WriteLine('</tbody></table>')

        $sw.WriteLine('<footer>')
        $sw.WriteLine('  ' + (& $h $script:ToolName) + ' v' + $script:ToolVersion +
            ' &nbsp;&middot;&nbsp; CIS Benchmarks + DISA STIG + Microsoft Security Baseline + Hardening Posture + Air-gap Isolation<br>')
        $sw.WriteLine('  Windows Server 2016 / 2019 / 2022 / 2025 &nbsp;&middot;&nbsp; detected baseline: <strong>' +
            (& $h $script:OsToken) + ' (' + (& $h $script:OsRole) + ')</strong><br>')
        $sw.WriteLine('  Generated ' + (& $h (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) +
            ' &nbsp;&middot;&nbsp; read-only audit &nbsp;&middot;&nbsp; for authorised security testing only')
        $sw.WriteLine('</footer>')

        $sw.Write(@'
<script>
var curS='all',curF='all';
function sf(btn,kind,val){
  if(kind===0){curS=val;}else{curF=(curF===val?'all':val);}
  var all=document.querySelectorAll('.filter-btn');
  for(var i=0;i<all.length;i++){all[i].classList.remove('active');}
  if(kind===0){btn.classList.add('active');}
  else if(curF!=='all'){btn.classList.add('active');}
  if(curF==='all'&&kind===1){
    var ab=document.querySelector('.fb-'+curS)||document.querySelector('.fb-all');
    if(ab){ab.classList.add('active');}
  }
  ft();
}
function ft(){
  var q=document.getElementById('srch').value.toLowerCase();
  var rows=document.querySelectorAll('#tb tr');
  for(var i=0;i<rows.length;i++){
    var r=rows[i];
    var sm=(curS==='all')||(r.getAttribute('data-s')===curS);
    var fm=(curF==='all')||(r.getAttribute('data-f')===curF);
    var tm=(!q)||(r.textContent.toLowerCase().indexOf(q)>-1);
    r.style.display=(sm&&fm&&tm)?'':'none';
  }
}
</script>
</body>
</html>
'@)
    } catch {
        $sw.Close()
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        Write-Host "ERROR: the HTML report could not be written: $($_.Exception.Message)" -ForegroundColor Red
        throw
    } finally { $sw.Close() }
    return $Path
}

# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE SUMMARY TABLE
# A ~940-check run cannot print one row per check and stay readable, so this
# aggregates to one row per category and then lists only what needs acting on.
# Colour follows the convention the team already reads:
#   green = OK, magenta = might be a finding, red = bad, yellow = could not test
# ─────────────────────────────────────────────────────────────────────────────
function Write-WgSummaryTable {
    if ($script:Results.Count -eq 0) { return }

    Write-Host ''
    Write-Host '  ###########################################################################' -ForegroundColor DarkCyan
    Write-Host '  #  Results by category                                                    #' -ForegroundColor DarkCyan
    Write-Host '  ###########################################################################' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host ('  {0,-34} {1,-16} {2,5} {3,6} {4,5} {5,5} {6,5}' -f
        'Category', 'Framework', 'OK', 'MAYBE', 'BAD', 'INFO', 'N/T') -ForegroundColor White
    Write-Host ('  ' + ('-' * 82)) -ForegroundColor DarkGray

    $groups = $script:Results |
        Group-Object -Property { "$($_.framework)`u{241F}$($_.category)" } |
        Sort-Object Name
    foreach ($g in $groups) {
        $parts = $g.Name -split "`u{241F}"
        $fw  = $parts[0]
        $cat = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $ok    = @($g.Group | Where-Object { $_.status -eq 'PASS' }).Count
        $maybe = @($g.Group | Where-Object { $_.status -eq 'WARN' }).Count
        $bad   = @($g.Group | Where-Object { $_.status -eq 'FAIL' }).Count
        $info  = @($g.Group | Where-Object { $_.status -eq 'INFO' -or $_.status -eq 'WAIVED' }).Count
        $nt    = @($g.Group | Where-Object { $_.status -eq 'SKIP' }).Count

        # Row colour reflects the worst thing in it
        $colour = if ($bad -gt 0) { 'Red' } elseif ($maybe -gt 0) { 'Magenta' }
                  elseif ($ok -gt 0) { 'Green' } elseif ($nt -gt 0) { 'Yellow' } else { 'Gray' }
        if ($cat.Length -gt 34) { $cat = $cat.Substring(0, 31) + '...' }
        Write-Host ('  {0,-34} {1,-16} {2,5} {3,6} {4,5} {5,5} {6,5}' -f
            $cat, $fw, $ok, $maybe, $bad, $info, $nt) -ForegroundColor $colour
    }

    # ── What to act on ──────────────────────────────────────────────────────
    $act = @($script:Results | Where-Object { $_.status -eq 'FAIL' -or $_.status -eq 'WARN' })
    if ($act.Count -eq 0) {
        Write-Host ''
        Write-Host '  Nothing failed and nothing warned. Open the HTML report for the detail.' -ForegroundColor Green
        return
    }

    $sevRank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    $ordered = $act |
        Sort-Object @{ Expression = { if ($_.status -eq 'FAIL') { 0 } else { 1 } } },
                    @{ Expression = { $sevRank["$($_.severity)"] } },
                    @{ Expression = { $_.id } }
    $cap  = 40
    $show = @($ordered | Select-Object -First $cap)

    Write-Host ''
    Write-Host '  ###########################################################################' -ForegroundColor DarkCyan
    Write-Host '  #  Findings to act on, worst first                                        #' -ForegroundColor DarkCyan
    Write-Host '  ###########################################################################' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host ('  {0,-6} {1,-8} {2,-22} {3}' -f 'RESULT', 'SEVERITY', 'CHECK', 'FINDING') -ForegroundColor White
    Write-Host ('  ' + ('-' * 100)) -ForegroundColor DarkGray

    foreach ($r in $show) {
        $label  = if ($r.status -eq 'FAIL') { 'BAD' } else { 'MAYBE' }
        $colour = if ($r.status -eq 'FAIL') { 'Red' } else { 'Magenta' }
        $title  = "$($r.title)"
        if ($title.Length -gt 62) { $title = $title.Substring(0, 59) + '...' }
        $id = "$($r.id)"
        if ($id.Length -gt 22) { $id = $id.Substring(0, 19) + '...' }
        Write-Host ('  {0,-6} {1,-8} {2,-22} {3}' -f $label, $r.severity, $id, $title) -ForegroundColor $colour
    }

    if ($ordered.Count -gt $cap) {
        Write-Host ''
        Write-Host ("  ... and $($ordered.Count - $cap) more. The full list, with the exact fix for each, " +
                    'is in the HTML and CSV reports.') -ForegroundColor DarkGray
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# TRANSFER BUNDLE - for carrying results off the enclave (sneakernet).
# Produces a .zip with the reports, a MANIFEST and SHA256SUMS, and prints the
# bundle's own hash to record in the media transfer log.
# ─────────────────────────────────────────────────────────────────────────────
function New-WgBundle {
    param([string[]] $Files, [string] $OutDir)

    $base  = "$($script:ToolName)_$($script:HostName)_$($script:ReportTs)"
    $stage = Join-Path $OutDir ".${base}_bundle"
    $inner = Join-Path $stage $base
    $zip   = Join-Path $OutDir "$base.zip"

    try {
        $null = New-Item -ItemType Directory -Path $inner -Force -ErrorAction Stop
        foreach ($f in $Files) {
            if ($f -and (Test-Path -LiteralPath $f)) { Copy-Item -LiteralPath $f -Destination $inner -Force }
        }

        $operator = "$env:USERDOMAIN\$env:USERNAME"
        $manifest = @(
            "tool=$($script:ToolName)"
            "version=$($script:ToolVersion)"
            "engine=$($script:ToolEngine)"
            "script_sha256=$($script:ScriptSha)"
            "hostname=$($script:HostName)"
            "os=$($script:OsCaption)"
            "os_build=$($script:OsBuild)"
            "os_baseline=$($script:OsToken)"
            "role=$($script:OsRole)"
            "run_as_admin=$($script:IsAdmin)"
            "operator=$operator"
            "created=$((Get-Date).ToString('o'))"
            ("summary=pass:$($script:Counts.PASS) fail:$($script:Counts.FAIL) " +
             "warn:$($script:Counts.WARN) waived:$($script:Counts.WAIVED) " +
             "info:$($script:Counts.INFO) skip:$($script:Counts.SKIP)")
            "compliance_pct=$(Get-WgCompliancePct)"
        )
        Set-Content -LiteralPath (Join-Path $inner 'MANIFEST.txt') -Value $manifest -Encoding ASCII

        $sums = @()
        foreach ($f in (Get-ChildItem -LiteralPath $inner -File)) {
            if ($f.Name -eq 'SHA256SUMS') { continue }
            $sums += "$(Get-WgSha256 $f.FullName)  $($f.Name)"
        }
        Set-Content -LiteralPath (Join-Path $inner 'SHA256SUMS') -Value $sums -Encoding ASCII

        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive -Path $inner -DestinationPath $zip -Force -ErrorAction Stop
        } else {
            # PowerShell 3/4 have no Compress-Archive; .NET 4.5 does have ZipFile
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)
        }
        return $zip
    } catch {
        return $null
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT DIRECTORY
# The reports enumerate this host's weaknesses, so the directory is restricted
# to Administrators and SYSTEM - the Windows equivalent of RHELGuard's umask 077.
# ─────────────────────────────────────────────────────────────────────────────
function Initialize-WgOutputDir {
    param([string] $Path)

    $created = $false
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            $null = New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop
            $created = $true
        }
        $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    } catch {
        Write-Host "Cannot create output directory: $Path" -ForegroundColor Red
        exit 1
    }

    # Only re-permission a directory this run created. A directory that already
    # existed belongs to whoever set it up - replacing its ACL because reports
    # are about to be written into it would be a destructive surprise.
    if (-not $created) {
        Write-WgLog 'Output directory already existed; its permissions were left unchanged.'
        return $full
    }

    try {
        $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)   # drop inherited ACEs

        # Remove whatever survived protection, so the result is exactly the
        # principals granted below. Removal is individually guarded: .NET throws
        # on an inherited rule, and failing to strip one extra ACE is far better
        # than abandoning the grants and locking the operator out.
        foreach ($rule in @($acl.Access)) {
            try { [void] $acl.RemoveAccessRule($rule) } catch { }
        }

        $grantees = New-Object System.Collections.ArrayList
        foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {   # Administrators, SYSTEM
            [void] $grantees.Add((New-Object System.Security.Principal.SecurityIdentifier($sid)))
        }

        # The account that ran the scan, by SID. This is the part that matters:
        # when the scan runs elevated, the operator's own non-elevated Explorer
        # session uses a filtered token WITHOUT Administrators, so an
        # Administrators-only ACL locks them out of their own reports.
        try {
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
            if ($me) { [void] $grantees.Add($me) }
        } catch { }

        # Under "runas /user:" or sudo-style elevation the reports are usually
        # wanted by the user who initiated it, not just the elevated account.
        foreach ($envUser in @($env:SUDO_USER)) {
            if (-not $envUser) { continue }
            try {
                $acct = New-Object Security.Principal.NTAccount($envUser)
                [void] $grantees.Add($acct.Translate([Security.Principal.SecurityIdentifier]))
            } catch { }
        }

        foreach ($id in ($grantees | Select-Object -Unique)) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }

        Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    } catch {
        # Tightening the ACL is best-effort: on a non-NTFS target, a redirected
        # or roaming profile, or without ownership, it can legitimately fail.
        # The scan still runs - the reports are simply left with the inherited
        # permissions of their parent, which is the safe direction to fail in.
        Write-WgLog ('Could not restrict the output directory ACL (' +
                     "$($_.Exception.GetType().Name)); the reports keep the parent's " +
                     'permissions. Protect them manually if that matters here.')
    }
    return $full
}


# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORK RUNNERS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WgCisChecks {
    Write-WgBanner "CIS Microsoft Windows Server $($script:OsToken) Benchmark"
    $rows = @($script:CisTable -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') })
    Invoke-WgTable -Rows $rows -Framework 'CIS' -Categories $script:CisCategories
}

function Invoke-WgStigChecks {
    Write-WgBanner "DISA STIG - Windows Server $($script:OsToken) ($($script:OsRole))"
    $rows = @($script:StigTable -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') })
    Invoke-WgTable -Rows $rows -Framework 'STIG' -Categories $null

    if ($script:IncludeManualRules) {
        Write-WgBanner 'DISA STIG - rules requiring manual review'
        $mrows = @($script:StigManualTable -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') })
        foreach ($line in $mrows) {
            $f = $line -split "`t"
            if ($f.Count -lt 12) { continue }
            if (-not (Test-WgApplies $f[10])) { continue }
            $sev = switch ($f[9]) { 'H' { 'High' } 'L' { 'Low' } default { 'Medium' } }
            Add-WgResult -Status 'INFO' -Id $f[0] -Title $f[2] -Category 'MANUAL REVIEW' `
                -Framework 'STIG' -Severity $sev -Refs (Format-WgRefs -Refs $f[11] -Framework 'STIG') `
                -Description ('This STIG rule cannot be determined automatically and requires ' +
                              'manual review against local documentation or configuration. ' +
                              'Subject: ' + $f[4] + '.') `
                -Remediation 'Review manually and record the result in your STIG checklist'
        }
    }
}

function Invoke-WgBaselineChecks {
    Write-WgBanner 'Microsoft Security Baseline (Security Compliance Toolkit)'
    $rows = @($script:BaselineTable -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') })
    $applicable = @($rows | Where-Object { Test-WgApplies (($_ -split "`t")[10]) })
    if ($applicable.Count -eq 0) {
        # Say so rather than silently contributing nothing to the score.
        Add-WgResult -Status 'INFO' -Id 'MSB-COVERAGE' `
            -Title "No Microsoft Security Baseline content for Windows Server $($script:OsToken)" `
            -Category 'MS SECURITY BASELINE' -Framework 'MSFT-BASELINE' -Severity 'Low' `
            -Description ('This build carries Microsoft Security Baseline settings for Windows ' +
                          "Server 2022 and 2025 only, so none apply to Server $($script:OsToken). " +
                          'The CIS and STIG checks in this report still cover this host; CIS in ' +
                          'particular overlaps the Microsoft baseline heavily.')
        return
    }
    Invoke-WgTable -Rows $rows -Framework 'MSFT-BASELINE' -Categories $null
}

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WgPreflight {
    Get-WgPlatform

    if ($script:ScriptPath) { $script:ScriptSha = Get-WgSha256 $script:ScriptPath }

    $script:OutputDir = Initialize-WgOutputDir $script:OutputDir
    $script:WaiverMap = Import-WgWaivers $script:WaiverPath

    if ($script:BaselinePath -and -not (Test-Path -LiteralPath $script:BaselinePath)) {
        Write-Host "Baseline not readable: $($script:BaselinePath)" -ForegroundColor Red
        exit 1
    }

    if ($script:OsToken -eq 'unknown') {
        Write-Host ''
        Write-Host '  WARNING: this Windows build could not be mapped to a known baseline.' -ForegroundColor Yellow
        Write-Host "  Build $($script:OsBuild) is older than Windows Server 2012." -ForegroundColor Yellow
        Write-Host '  Benchmark checks will be skipped; posture and air-gap checks still run.' -ForegroundColor Yellow
        Write-Host ''
    } elseif ($script:OsToken -eq '2012' -or $script:OsToken -eq '2012R2') {
        Write-Host ''
        Write-Host "  NOTE: Windows Server $($script:OsToken) is out of support and has no current" -ForegroundColor Yellow
        Write-Host '  CIS/STIG content in this build. The Server 2016 baseline is applied as the' -ForegroundColor Yellow
        Write-Host '  closest available reference; treat those findings as best-effort.' -ForegroundColor Yellow
        Write-Host ''
        $script:OsToken = '2016'
    } elseif (-not $script:IsServer) {
        Write-Host ''
        Write-Host '  NOTE: this is a client SKU. Server benchmarks are applied as the closest' -ForegroundColor Yellow
        Write-Host '  available reference; some findings will not be relevant to a workstation.' -ForegroundColor Yellow
        Write-Host ''
    }

    if (-not $script:IsAdmin) {
        Write-Host ''
        Write-Host '  +------------------------------------------------------------------+' -ForegroundColor Yellow
        Write-Host '  |  Running WITHOUT administrator rights.                           |' -ForegroundColor Yellow
        Write-Host '  |  Account policy, user rights and audit policy cannot be read and  |' -ForegroundColor Yellow
        Write-Host '  |  will be reported as SKIP. Re-run elevated for full coverage.     |' -ForegroundColor Yellow
        Write-Host '  +------------------------------------------------------------------+' -ForegroundColor Yellow
        Write-Host ''
    }

    Write-WgLog "Tool       : $($script:ToolName) v$($script:ToolVersion)"
    Write-WgLog "Host       : $($script:HostName)"
    Write-WgLog "OS         : $($script:OsCaption)"
    Write-WgLog "Version    : $($script:OsVersion)  (build $($script:OsBuild))"
    Write-WgLog "Baseline   : Windows Server $($script:OsToken), role $($script:OsRole) ($($script:DomainRole))"
    Write-WgLog "PowerShell : $($PSVersionTable.PSVersion)"
    Write-WgLog "Mode       : $($script:ScanMode)"
    Write-WgLog "Throttle   : $($script:ThrottleMs)ms"
    Write-WgLog "As admin   : $($script:IsAdmin)"
    Write-WgLog "Output     : $($script:OutputDir)"
    Write-WgLog "SHA-256    : $($script:ScriptSha)"
    if ($script:IncludeDomainPol -and -not $script:IsDC) {
        Write-WgLog 'Domain pol : enabled - this makes ONE LDAP query to the host''s own domain controller'
    }
    if ($script:WaiverMap.Count -gt 0) {
        Write-WgLog "Waivers    : $($script:WaiverMap.Count) loaded from $($script:WaiverPath)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WgMain {

    Invoke-WgPreflight

    if (-not $script:QuietMode) {
        Write-Host ''
        Write-Host '  __        __  ___   _   _    ____   _   _      _      ____    ____  ' -ForegroundColor Cyan
        Write-Host '  \ \      / / |_ _| | \ | |  / ___| | | | |    / \    |  _ \  |  _ \ ' -ForegroundColor Cyan
        Write-Host '   \ \ /\ / /   | |  |  \| | | |  _  | | | |   / _ \   | |_) | | | | |' -ForegroundColor Cyan
        Write-Host '    \ V  V /    | |  | |\  | | |_| | | |_| |  / ___ \  |  _ <  | |_| |' -ForegroundColor Cyan
        Write-Host '     \_/\_/    |___| |_| \_|  \____|  \___/  /_/   \_\ |_| \_\ |____/ ' -ForegroundColor Cyan
        Write-Host ''
        Write-Host "  v$($script:ToolVersion) " -ForegroundColor White -NoNewline
        Write-Host "- CIS + DISA STIG + MS Baseline + Hardening + Air-gap - " -NoNewline
        Write-Host "$($script:HostName)" -ForegroundColor Cyan -NoNewline
        Write-Host " (Server $($script:OsToken)/$($script:OsRole))"
        Write-Host ''
    }

    $benchmarksAvailable = ($script:OsToken -ne 'unknown')

    switch ($script:ScanMode) {
        'cis'      { if ($benchmarksAvailable) { Invoke-WgCisChecks } }
        'stig'     { if ($benchmarksAvailable) { Invoke-WgStigChecks } }
        'baseline' { if ($benchmarksAvailable) { Invoke-WgBaselineChecks } }
        'posture'  { Invoke-WgPostureChecks; Invoke-WgExtraChecks }
        'airgap'   { Invoke-WgAirgapChecks }
        'all' {
            if ($benchmarksAvailable) {
                Invoke-WgCisChecks
                Invoke-WgStigChecks
                Invoke-WgBaselineChecks
            }
            Invoke-WgPostureChecks
            Invoke-WgExtraChecks
            Invoke-WgAirgapChecks
        }
    }

    if ($script:Counts.TOTAL -eq 0) {
        Write-Host ''
        Write-Host '  No checks ran. If you selected a benchmark mode on an unsupported build,' -ForegroundColor Yellow
        Write-Host '  try -Mode posture or -Mode airgap instead.' -ForegroundColor Yellow
        Write-Host ''
        exit 1
    }

    Get-WgDrift $script:BaselinePath

    # ── Summary (always printed, even with -Quiet) ───────────────────────────
    Write-WgSummaryTable

    $pct     = Get-WgCompliancePct
    $elapsed = [int] ((Get-Date) - $script:StartTime).TotalSeconds
    $c       = $script:Counts

    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host "   SCAN COMPLETE  ${elapsed}s  |  Server $($script:OsToken) ($($script:OsRole))  |  $($script:HostName)" -ForegroundColor White
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host ('   {0,-11}{1}' -f 'PASS', $c.PASS)   -ForegroundColor Green
    Write-Host ('   {0,-11}{1}' -f 'FAIL', $c.FAIL)   -ForegroundColor Red
    Write-Host ('   {0,-11}{1}' -f 'WARN', $c.WARN)   -ForegroundColor Yellow
    Write-Host ('   {0,-11}{1}' -f 'WAIVED', $c.WAIVED) -ForegroundColor Magenta
    Write-Host ('   {0,-11}{1}' -f 'INFO', $c.INFO)   -ForegroundColor Cyan
    Write-Host ('   {0,-11}{1}' -f 'SKIP', $c.SKIP)   -ForegroundColor DarkGray
    if (-not $script:IsAdmin) {
        Write-Host ('   {0,-11}{1}  (re-run elevated for full coverage)' -f 'PRIV-SKIP', $c.PRIV_SKIP) -ForegroundColor Yellow
    }
    Write-Host ('   {0,-11}{1}' -f 'TOTAL', $c.TOTAL)
    Write-Host ''
    Write-Host "   Compliance Score : $pct%" -ForegroundColor White -NoNewline
    Write-Host '   (pass / (pass + fail + warn))'

    # Per-framework breakdown
    foreach ($f in @('CIS', 'STIG', 'MSFT-BASELINE', 'POSTURE', 'AIRGAP')) {
        $rs = @($script:Results | Where-Object { $_.framework -eq $f })
        if ($rs.Count -eq 0) { continue }
        $p = @($rs | Where-Object { $_.status -eq 'PASS' }).Count
        $fl = @($rs | Where-Object { $_.status -eq 'FAIL' }).Count
        $w = @($rs | Where-Object { $_.status -eq 'WARN' }).Count
        $den = $p + $fl + $w
        $fp = if ($den -gt 0) { '{0:F1}' -f (($p / $den) * 100) } else { '0.0' }
        Write-Host ('   {0,-16}{1,6}%   ({2} checks: {3} pass, {4} fail, {5} warn)' -f $f, $fp, $rs.Count, $p, $fl, $w)
    }

    if ($script:BaselinePath) {
        Write-Host ''
        Write-Host "   Drift            : " -NoNewline
        Write-Host "$($script:DriftNew) new/regressed" -ForegroundColor Red -NoNewline
        Write-Host ' / ' -NoNewline
        Write-Host "$($script:DriftFixed) fixed" -ForegroundColor Green
        foreach ($d in @($script:DriftRows | Where-Object { $_.change -eq 'NEW' -or $_.change -eq 'REGRESSED' } |
                         Select-Object -First 15)) {
            Write-Host ('      {0,-10} {1,-28} {2} -> {3}' -f $d.change, $d.id, $d.from, $d.to)
        }
    }
    Write-Host ''

    # ── Reports ──────────────────────────────────────────────────────────────
    Write-WgLog 'Generating reports...'
    $stem = Join-Path $script:OutputDir "$($script:ToolName)_$($script:HostName)_$($script:ReportTs)"
    $jout = Write-WgJsonReport "$stem.json"
    $hout = Write-WgHtmlReport "$stem.html"
    $cout = Write-WgCsvReport  "$stem.csv"

    Write-Host "   JSON   -> " -NoNewline; Write-Host $jout -ForegroundColor Cyan
    Write-Host "   HTML   -> " -NoNewline; Write-Host $hout -ForegroundColor Cyan
    Write-Host "   CSV    -> " -NoNewline; Write-Host $cout -ForegroundColor Cyan

    if ($script:MakeBundle) {
        $bout = New-WgBundle -Files @($jout, $hout, $cout) -OutDir $script:OutputDir
        if ($bout) {
            Write-Host "   BUNDLE -> " -NoNewline; Write-Host $bout -ForegroundColor Cyan
            Write-Host "      sha256: $(Get-WgSha256 $bout)   <- record this in your media transfer log"
        } else {
            Write-Host '   Bundle could not be created (compression unavailable or write error).' -ForegroundColor Yellow
        }
    }

    Write-Host ''
    if (-not $script:QuietMode) {
        Write-Host '   Done. Open the HTML report for the full dashboard.' -ForegroundColor Green
        Write-Host ''
    }

    if ($script:StrictMode -and $script:Counts.FAIL -gt 0) { exit 2 }
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# Parameters are copied into script scope so every function sees one source of
# truth, rather than relying on inherited parameter variables.
# ─────────────────────────────────────────────────────────────────────────────
$script:ScanMode           = $Mode
$script:OutputDir          = $Output
$script:ThrottleMs         = $Throttle
$script:QuietMode          = [bool] $Quiet
$script:BaselinePath       = $Baseline
$script:WaiverPath         = $Waivers
$script:MaxPatchDays       = $MaxPatchAge
$script:MaxSigAge          = $MaxSignatureAge
$script:MakeBundle         = [bool] $Bundle
$script:StrictMode         = [bool] $Strict
$script:IncludeManualRules = [bool] $IncludeManual
$script:IncludeDomainPol   = [bool] $IncludeDomainPolicy

Invoke-WgMain
