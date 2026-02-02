<#
.SYNOPSIS
  Retrieve DNS-related records (hostname/IP) from phpIPAM using PSPHPIPAM.
  Treats phpIPAM hostnames as forward records (A/AAAA) and exposes PTR preference.

.PARAMETER ApiUrl
  Base URL of the phpIPAM API, e.g. https://ipam.example.com/api/MyApp

.PARAMETER AppId
  The phpIPAM API App ID (visible in Administration > API).

.PARAMETER Username
  API user (basic auth to obtain token).

.PARAMETER Password
  API password.

.PARAMETER SubnetId
  (Optional) Subnet ID to limit the query. If omitted, all subnets are traversed.

.PARAMETER ExportCsv
  (Optional) Path to export a CSV file, eg. .\phpipam_dns_records.csv

.EXAMPLE
  .\Get-PhpIpamDnsRecords.ps1 `
     -ApiUrl "https://ipam.example.com/api/MyApp" `
     -AppId "MyApp" `
     -Username "apiuser" `
     -Password "P@ssw0rd!" `
     -ExportCsv ".\phpipam_dns_records.csv"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]  [string]$ApiUrl="http://suo04ctcinf7.demo.local/administration/api/",
  [Parameter(Mandatory=$true)]  [string]$AppId="morpheus",
  [Parameter(Mandatory=$true)]  [string]$Username="morpheus",
  [Parameter(Mandatory=$true)]  [string]$Password="We95sms!!",
  [Parameter(Mandatory=$false)] [int]$SubnetId,
  [Parameter(Mandatory=$false)] [string]$ExportCsv="./output/dnsrecords.csv"
)

# Ensure the PSPHPIPAM module is available
if (-not (Get-Module -ListAvailable -Name PSPHPIPAM)) {
  Write-Verbose "PSPHPIPAM module not found. Installing for CurrentUser..."
  Install-Module PSPHPIPAM -Scope CurrentUser -Force -ErrorAction Stop
}
Import-Module PSPHPIPAM -ErrorAction Stop

# 1) Authenticate (create a phpIPAM API session)
#    The module exposes New-PhpIpamSession to obtain a token and use it in subsequent calls.
#    (Run `Get-Command -Module PSPHPIPAM` to explore available functions.)
New-PhpIpamSession `
  -PhpIpamApiUrl $ApiUrl `
  -AppID         $AppId `
  -UserName      $Username `
  -Password      $Password `
  -UseCredAuth `
  -ErrorAction Stop | Out-Null

# Helper to transform an address row to a "DNS record" shaped object
function Convert-ToDnsRecord {
  param(
    [Parameter(Mandatory=$true)] $AddressRow
  )

  # phpIPAM’s address payload typically includes:
  # - ip (string), hostname (string), is_gateway, mac, owner, description, tag, deviceId, PTRignore, etc.
  # IPv4 vs IPv6 detection is needed to set A vs AAAA.
  # Note: PSPHPIPAM often returns .ip in dotted or compressed form already.
  $ip = $AddressRow.ip
  $isIPv6 = $false
  try { 
    $ipObj = [System.Net.IPAddress]::Parse($ip)
    $isIPv6 = $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
  } catch { }

  $recordType = if ($isIPv6) { 'AAAA' } else { 'A' }

  # PTR preference is guided by PTRignore flag in phpIPAM (when set, PTR shouldn't be created/managed).
  $ptrDesired = $true
  if ($null -ne $AddressRow.PTRignore -and [string]$AddressRow.PTRignore -in @('1','true','True')) {
    $ptrDesired = $false
  }

  # Enrich: tag (status), deviceId and description are helpful
  [pscustomobject]@{
    RecordType = $recordType
    Name       = $AddressRow.hostname
    Content    = $ip
    PTRDesired = $ptrDesired
    Tag        = $AddressRow.tag
    Description= $AddressRow.description
    DeviceId   = $AddressRow.deviceId
    SubnetId   = $AddressRow.subnetId
    AddressId  = $AddressRow.id
  }
}

# 2) Get the addresses
$records = New-Object System.Collections.Generic.List[object]

if ($PSBoundParameters.ContainsKey('SubnetId')) {
  # Pull addresses for a specific subnet
  # The module exposes Get-PhpIpamSubnetAddressesByID (by subnet ID).
  $addr = Get-PhpIpamSubnetAddressesByID -id $SubnetId -ErrorAction Stop
  foreach ($a in $addr) {
    $records.Add( (Convert-ToDnsRecord -AddressRow $a) )
  }
} else {
  # Enumerate all subnets, then pull addresses per subnet
  $allSubnets = Get-PhpIpamSubnets -ErrorAction Stop
  foreach ($s in $allSubnets) {
    try {
      $addr = Get-PhpIpamSubnetAddressesByID -id $s.id -ErrorAction Stop
      foreach ($a in $addr) {
        $records.Add( (Convert-ToDnsRecord -AddressRow $a) )
      }
    } catch {
      Write-Warning "Failed to fetch addresses for subnet ID $($s.id): $($_.Exception.Message)"
    }
  }
}

# 3) Clean output: ignore empty hostnames if you only want DNS-like rows
$dnsLike = $records.Where({ $_.Name -and $_.Name.Trim().Length -gt 0 })

# 4) Export or emit to pipeline
if ($ExportCsv) {
  $dnsLike | Sort-Object Name,RecordType,Content | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
  Write-Host "Exported $(($dnsLike).Count) DNS-like records to $ExportCsv"
} else {
  $dnsLike | Sort-Object Name,RecordType,Content | Format-Table -AutoSize
}