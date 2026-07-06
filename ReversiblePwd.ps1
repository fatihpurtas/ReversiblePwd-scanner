<#
.SYNOPSIS
    Audits Active Directory for accounts storing passwords with reversible encryption.

.DESCRIPTION
    Finds user accounts that have the ENCRYPTED_TEXT_PWD_ALLOWED (0x80) bit set in
    userAccountControl. When this flag is enabled, Active Directory stores the
    account's password in a reversibly encrypted form that can be decrypted to
    plaintext, effectively the same risk as storing the password in clear text.

    Uses only built-in System.DirectoryServices classes, with no ActiveDirectory
    module and no administrative privileges are required (read access is enough).

.PARAMETER Server
    Optional domain controller to query directly (e.g. dc01.example.com).

.PARAMETER SearchBase
    Optional distinguished name to scope the search.

.PARAMETER OutputPath
    CSV output path. Defaults to .\reversible_pwd_<domain>.csv

.PARAMETER IncludeDisabled
    Include disabled accounts. By default only enabled accounts are reported.

.EXAMPLE
    .\ReversiblePwd.ps1
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$SearchBase,
    [string]$OutputPath,
    [switch]$IncludeDisabled
)

function Convert-FileTimeUtc {
    param([object]$val)
    if ($null -eq $val) { return $null }
    $n = 0L
    if (-not [Int64]::TryParse([string]$val, [ref]$n)) { return $null }
    if ($n -le 0) { return $null }
    try { [DateTime]::FromFileTimeUtc($n) } catch { $null }
}

function Format-DateUtc {
    param([object]$dt)
    if ($null -eq $dt) { return $null }
    return ([DateTime]$dt).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

# --- Resolve search root via RootDSE (works domain-joined or with -Server) ---
try {
    $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry($rootDsePath)
    $defaultNC = [string]$rootDse.Properties["defaultNamingContext"].Value
    if ([string]::IsNullOrWhiteSpace($defaultNC)) { throw "defaultNamingContext was empty." }
} catch {
    Write-Error "Unable to contact Active Directory. Run on a domain-joined machine or pass -Server. Details: $($_.Exception.Message)"
    exit 1
}

$base = if ($SearchBase) { $SearchBase } else { $defaultNC }
$domainName = (($defaultNC -split ',') | Where-Object { $_ -match '^(?i)DC=' } | ForEach-Object { $_ -replace '^(?i)DC=','' }) -join '_'
$searchRootPath = if ($Server) { "LDAP://$Server/$base" } else { "LDAP://$base" }
$root = New-Object System.DirectoryServices.DirectoryEntry($searchRootPath)

$disabledClause = if ($IncludeDisabled) { "" } else { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" }
$Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128)$disabledClause)"

$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.Filter = $Filter
$searcher.PageSize = 1000
foreach ($pr in @("name","samaccountname","distinguishedname","useraccountcontrol","pwdlastset","lastlogontimestamp","admincount")) {
    [void]$searcher.PropertiesToLoad.Add($pr)
}

Write-Host "Searching for reversible-encryption accounts in $base ..." -ForegroundColor Cyan

$results = $null
$rows = [System.Collections.Generic.List[object]]::new()
try {
    try { $results = $searcher.FindAll() } catch { Write-Error "LDAP query failed: $($_.Exception.Message)"; exit 1 }

    $total = $results.Count; $i = 0
    foreach ($res in $results) {
        $i++
        if ($total -gt 0) { Write-Progress -Activity "Analyzing accounts..." -Status "$i of $total" -PercentComplete (($i / $total) * 100) }
        $p = $res.Properties
        $uac = if ($p["useraccountcontrol"].Count) { [int]$p["useraccountcontrol"][0] } else { 0 }
        $pls = if ($p["pwdlastset"].Count) { Convert-FileTimeUtc $p["pwdlastset"][0] } else { $null }

        $rows.Add([pscustomobject]@{
            Name              = if ($p["name"].Count) { $p["name"][0] } else { "N/A" }
            SamAccountName    = if ($p["samaccountname"].Count) { $p["samaccountname"][0] } else { "N/A" }
            Enabled           = -not ($uac -band 2)
            AdminCount        = if ($p["admincount"].Count) { $p["admincount"][0] } else { 0 }
            PwdLastSet        = Format-DateUtc $pls
            LastLogon         = Format-DateUtc (Convert-FileTimeUtc ($p["lastlogontimestamp"] | Select-Object -First 1))
            DistinguishedName = if ($p["distinguishedname"].Count) { $p["distinguishedname"][0] } else { "N/A" }
        })
    }
    Write-Progress -Activity "Analyzing accounts..." -Completed
} finally {
    if ($results) { $results.Dispose() }
    $searcher.Dispose(); $root.Dispose()
}

$rows = @($rows | Sort-Object @{Expression={[int]$_.AdminCount}; Descending=$true}, SamAccountName)
if (-not $OutputPath) { $OutputPath = ".\reversible_pwd_$domainName.csv" }

if ($rows.Count -eq 0) {
    Write-Host "`nNo accounts with reversible password encryption found." -ForegroundColor Green
    exit 0
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$privCount = @($rows | Where-Object { [int]$_.AdminCount -ge 1 }).Count
Write-Host "`n=== REVERSIBLE PASSWORD ENCRYPTION EXPOSURE ===" -ForegroundColor Yellow
Write-Host "Accounts with reversible encryption: $($rows.Count)" -ForegroundColor Green
Write-Host "  - Privileged (adminCount>=1): $privCount" -ForegroundColor Red
Write-Host "CSV saved: $OutputPath" -ForegroundColor Cyan
$rows | Format-Table Name, SamAccountName, Enabled, AdminCount, PwdLastSet -AutoSize
