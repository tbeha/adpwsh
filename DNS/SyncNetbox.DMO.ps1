<#
.SYNOPSIS
    Synchronize NetBox IPAM dns_name records to Microsoft DNS.

.DESCRIPTION
    Reads active IP addresses from NetBox via REST API.
    For every IP address with a populated dns_name field, the script creates or updates
    Microsoft DNS A / AAAA records.

    Recommended model:
        NetBox = Source of Truth
        Microsoft DNS = Target

.NOTES
    Requires:
        - Windows PowerShell 5.1 recommended
        - DnsServer PowerShell module / RSAT DNS tools
        - Netbox PowerShell module  
        - Network access to NetBox API
        - Permission to manage Microsoft DNS records

#>

[CmdletBinding()]
param(
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$NetBoxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string[]]$ForwardZones = @("dmo.ctc.int.hpe.com"),
    [string]$NetBoxStatus = "active",
    [int]$PageLimit = 1000,
    [Boolean]$CreatePtr = $true,
    [Boolean]$UpdateExisting = $true,
    [Boolean]$RemoveStaleRecords = $true,
    [Boolean]$WhatIfMode = $true,
    [string]$LogPath = ".\NetBox-DNS-Sync.log",
    [string]$CsvReportPath = ".\NetBox-DNS-Sync-Report.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

$script:Report = New-Object System.Collections.Generic.List[object]

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO","WARN","ERROR","CREATE","UPDATE","DELETE","SKIP","DRYRUN")]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "{0} [{1}] {2}" -f $timestamp, $Level, $Message

    Write-Host $line

    try {
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }
    catch {
        Write-Warning "Unable to write to log file '$LogPath': $($_.Exception.Message)"
    }
}

function Add-ReportItem {
    param(
        [string]$Action,
        [string]$ZoneName,
        [string]$RecordName,
        [string]$RecordType,
        [string]$IPAddress,
        [string]$DnsName,
        [string]$Message
    )

    $script:Report.Add([pscustomobject]@{
        Timestamp  = Get-Date
        Action     = $Action
        ZoneName   = $ZoneName
        RecordName = $RecordName
        RecordType = $RecordType
        IPAddress  = $IPAddress
        DnsName    = $DnsName
        Message    = $Message
    })
}

# ---------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------

function Test-Prerequisites {
    Write-Log -Level INFO -Message "Checking prerequisites"

    $dnsModule = Get-Module -ListAvailable -Name DnsServer

    if (-not $dnsModule) {
        throw "DnsServer PowerShell module not found. Install RSAT DNS tools or run on a DNS server."
    }

    Import-Module DnsServer -ErrorAction Stop

    try {
        $null = Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop
    }
    catch {
        throw "Unable to query DNS server '$DnsServer'. Error: $($_.Exception.Message)"
    }

    foreach ($zone in $ForwardZones) {
        try {
            $null = Get-DnsServerZone -ComputerName $DnsServer -Name $zone -ErrorAction Stop
            Write-Log -Level INFO -Message "Validated DNS zone '$zone' on '$DnsServer'"
        }
        catch {
            throw "DNS zone '$zone' not found or not accessible on '$DnsServer'. Error: $($_.Exception.Message)"
        }
    }

    $dnsModule = Get-Module -ListAvailable -Name PowerNetbox

    if (-not $dnsModule) {
        throw "Netbox PowerShell module not found. Install PowerNetbox tool."
    }    

    Import-Module PowerNetbox -ErrorAction Stop

}

# ---------------------------------------------------------------------
# NetBox API
# ---------------------------------------------------------------------

function Get-NetboxSession{
    $secureToken = Get-Content $netboxTokenPath -Raw | ConvertTo-SecureString -AsPlainText -Force
    $nbcred = [pscredential]::new('admin', $securetoken)
    Connect-NBApi -Uri $netboxBaseUrl -Credential $nbcred -SkipCertificateCheck
}

# ---------------------------------------------------------------------
# DNS helper functions
# ---------------------------------------------------------------------

function Get-IPAddressWithoutPrefix {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    return ($Address -split "/")[0]
}

function Get-IPFamily {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    if ($IPAddress -match ":") {
        return 6
    }

    if ($IPAddress -match "^\d{1,3}(\.\d{1,3}){3}$") {
        return 4
    }

    throw "Unable to determine IP family for '$IPAddress'"
}

function Normalize-Fqdn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DnsName
    )

    return $DnsName.Trim().TrimEnd(".").ToLowerInvariant()
}

function Get-MatchingForwardZone {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [string[]]$Zones
    )

    $normalizedFqdn = Normalize-Fqdn -DnsName $Fqdn

    $matchedZones = $Zones |
        ForEach-Object { $_.Trim().TrimEnd(".").ToLowerInvariant() } |
        Where-Object {
            $normalizedFqdn -eq $_ -or $normalizedFqdn.EndsWith(".$_")
        } |
        Sort-Object Length -Descending

    if (-not $matchedZones -or $matchedZones.Count -eq 0) {
        return $null
    }

    return $matchedZones[0]
}

function Get-RecordNameFromFqdn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [string]$ZoneName
    )

    $normalizedFqdn = Normalize-Fqdn -DnsName $Fqdn
    $normalizedZone = Normalize-Fqdn -DnsName $ZoneName

    if ($normalizedFqdn -eq $normalizedZone) {
        return "@"
    }

    $suffix = ".$normalizedZone"

    if ($normalizedFqdn.EndsWith($suffix)) {
        return $normalizedFqdn.Substring(0, $normalizedFqdn.Length - $suffix.Length)
    }

    throw "FQDN '$Fqdn' does not belong to zone '$ZoneName'"
}

function Test-DnsNameAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DnsName
    )

    if (-not $AllowedDnsNameSuffixes -or $AllowedDnsNameSuffixes.Count -eq 0) {
        return $true
    }

    $normalizedName = Normalize-Fqdn -DnsName $DnsName

    foreach ($suffix in $AllowedDnsNameSuffixes) {
        $normalizedSuffix = Normalize-Fqdn -DnsName $suffix

        if ($normalizedName -eq $normalizedSuffix -or $normalizedName.EndsWith(".$normalizedSuffix")) {
            return $true
        }
    }

    return $false
}

function Get-DnsRecordValue {
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    switch ($Record.RecordType) {
        "A" {
            return $Record.RecordData.IPv4Address.IPAddressToString
        }
        "AAAA" {
            return $Record.RecordData.IPv6Address.IPAddressToString
        }
        default {
            return $null
        }
    }
}

function Get-ExistingDnsRecords {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [string]$RecordName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("A","AAAA")]
        [string]$RecordType
    )

    try {
        $records = Get-DnsServerResourceRecord `
            -ComputerName $DnsServer `
            -ZoneName $ZoneName `
            -Name $RecordName `
            -RRType $RecordType `
            -ErrorAction SilentlyContinue

        if ($null -eq $records) {
            return @()
        }

        return @($records)
    }
    catch {
        Write-Log -Level WARN -Message "Failed to query DNS record '$RecordName' in zone '$ZoneName': $($_.Exception.Message)"
        return @()
    }
}

# ---------------------------------------------------------------------
# DNS write operations
# ---------------------------------------------------------------------

function Add-DnsRecordFromNetBox {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [string]$RecordName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("A","AAAA")]
        [string]$RecordType,

        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $true)]
        [string]$DnsName
    )

    if ($WhatIfMode) {
        Write-Log -Level DRYRUN -Message "Would create $RecordType record: $RecordName.$ZoneName -> $IPAddress"
        Add-ReportItem -Action "DRYRUN-CREATE" -ZoneName $ZoneName -RecordName $RecordName -RecordType $RecordType -IPAddress $IPAddress -DnsName $DnsName -Message "Would create record"
        return
    }

    if ($RecordType -eq "A") {
        $params = @{
            ComputerName = $DnsServer
            ZoneName     = $ZoneName
            Name         = $RecordName
            IPv4Address  = $IPAddress
            TimeToLive   = $TimeToLive
            ErrorAction  = "Stop"
        }

        if ($CreatePtr) {
            $params["CreatePtr"] = $true
        }

        Add-DnsServerResourceRecordA @params
    }
    elseif ($RecordType -eq "AAAA") {
        Add-DnsServerResourceRecordAAAA `
            -ComputerName $DnsServer `
            -ZoneName $ZoneName `
            -Name $RecordName `
            -IPv6Address $IPAddress `
            -TimeToLive $TimeToLive `
            -ErrorAction Stop
    }

    Write-Log -Level CREATE -Message "Created $RecordType record: $RecordName.$ZoneName -> $IPAddress"
    Add-ReportItem -Action "CREATE" -ZoneName $ZoneName -RecordName $RecordName -RecordType $RecordType -IPAddress $IPAddress -DnsName $DnsName -Message "Created record"
}

function Remove-DnsRecordObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$DnsName
    )

    $recordValue = Get-DnsRecordValue -Record $Record

    if ($WhatIfMode) {
        Write-Log -Level DRYRUN -Message "Would remove $($Record.RecordType) record: $($Record.HostName).$ZoneName -> $recordValue"
        Add-ReportItem -Action "DRYRUN-DELETE" -ZoneName $ZoneName -RecordName $Record.HostName -RecordType $Record.RecordType -IPAddress $recordValue -DnsName $DnsName -Message "Would remove record"
        return
    }

    Remove-DnsServerResourceRecord `
        -ComputerName $DnsServer `
        -ZoneName $ZoneName `
        -InputObject $Record `
        -Force `
        -ErrorAction Stop

    Write-Log -Level DELETE -Message "Removed $($Record.RecordType) record: $($Record.HostName).$ZoneName -> $recordValue"
    Add-ReportItem -Action "DELETE" -ZoneName $ZoneName -RecordName $Record.HostName -RecordType $Record.RecordType -IPAddress $recordValue -DnsName $DnsName -Message "Removed record"
}

function Sync-OneDnsRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DnsName,

        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    $family = Get-IPFamily -IPAddress $IPAddress

    if ($family -eq 4) {
        $recordType = "A"
    }
    elseif ($family -eq 6) {
        $recordType = "AAAA"
    }
    else {
        throw "Unsupported IP family for '$IPAddress'"
    }

    $zoneName = Get-MatchingForwardZone -Fqdn $DnsName -Zones $ForwardZones

    if (-not $zoneName) {
        Write-Log -Level SKIP -Message "Skipping '$DnsName' because no matching forward zone was found"
        Add-ReportItem -Action "SKIP" -ZoneName "" -RecordName "" -RecordType $recordType -IPAddress $IPAddress -DnsName $DnsName -Message "No matching forward zone"
        return
    }

    $recordName = Get-RecordNameFromFqdn -Fqdn $DnsName -ZoneName $zoneName

    $existingRecords = Get-ExistingDnsRecords `
        -ZoneName $zoneName `
        -RecordName $recordName `
        -RecordType $recordType

    $matchingRecords = @(
        $existingRecords | Where-Object {
            (Get-DnsRecordValue -Record $_) -eq $IPAddress
        }
    )

    if ($matchingRecords.Count -gt 0) {
        Write-Log -Level SKIP -Message "Record already exists: $recordName.$zoneName -> $IPAddress"
        Add-ReportItem -Action "SKIP" -ZoneName $zoneName -RecordName $recordName -RecordType $recordType -IPAddress $IPAddress -DnsName $DnsName -Message "Record already exists"
        return
    }

    if ($existingRecords.Count -eq 0) {
        Add-DnsRecordFromNetBox `
            -ZoneName $zoneName `
            -RecordName $recordName `
            -RecordType $recordType `
            -IPAddress $IPAddress `
            -DnsName $DnsName

        return
    }

    # Existing record with same DNS name but different IP address.
    $existingValues = @(
        $existingRecords | ForEach-Object {
            Get-DnsRecordValue -Record $_
        }
    )

    if (-not $UpdateExisting) {
        Write-Log -Level WARN -Message "Existing $recordType record found for $recordName.$zoneName with different value(s): $($existingValues -join ', '). Use -UpdateExisting to replace."
        Add-ReportItem -Action "WARN" -ZoneName $zoneName -RecordName $recordName -RecordType $recordType -IPAddress $IPAddress -DnsName $DnsName -Message "Existing record differs; update disabled"
        return
    }

    foreach ($record in $existingRecords) {
        Remove-DnsRecordObject `
            -ZoneName $zoneName `
            -Record $record `
            -DnsName $DnsName
    }

    Add-DnsRecordFromNetBox `
        -ZoneName $zoneName `
        -RecordName $recordName `
        -RecordType $recordType `
        -IPAddress $IPAddress `
        -DnsName $DnsName

    Write-Log -Level UPDATE -Message "Updated $recordType record: $recordName.$zoneName -> $IPAddress"
}

# ---------------------------------------------------------------------
# Main synchronization
# ---------------------------------------------------------------------

function Start-NetBoxDnsSync {
    Write-Log -Level INFO -Message "Starting NetBox to Microsoft DNS synchronization"
    Write-Log -Level INFO -Message "NetBox URL: $NetBoxUrl"
    Write-Log -Level INFO -Message "DNS server: $DnsServer"
    Write-Log -Level INFO -Message "Forward zones: $($ForwardZones -join ', ')"
    Write-Log -Level INFO -Message "WhatIf mode: $WhatIfMode"
    Write-Log -Level INFO -Message "Update existing: $UpdateExisting"
    Write-Log -Level INFO -Message "Create PTR: $CreatePtr"

    Test-Prerequisites

    # connect to the Netbox API and retrieve the list of IP addresses with dns_name
    Get-NetboxSession
    $netboxAddresses = Get-NBIPAMAddress -All -ErrorAction Stop

    $desiredRecords = New-Object System.Collections.Generic.List[object]

    foreach ($ipObj in $netboxAddresses) {
        if (-not $ipObj.address) {
            continue
        }

        if (-not $ipObj.dns_name) {
            continue
        }

        $dnsName = Normalize-Fqdn -DnsName $ipObj.dns_name

        if (-not (Test-DnsNameAllowed -DnsName $dnsName)) {
            Write-Log -Level SKIP -Message "Skipping '$dnsName' because it is not in AllowedDnsNameSuffixes"
            Add-ReportItem -Action "SKIP" -ZoneName "" -RecordName "" -RecordType "" -IPAddress $ipObj.address -DnsName $dnsName -Message "DNS suffix not allowed"
            continue
        }

        $ipAddress = Get-IPAddressWithoutPrefix -Address $ipObj.address

        try {
            $family = Get-IPFamily -IPAddress $ipAddress

            if ($family -eq 4) {
                $recordType = "A"
            }
            else {
                $recordType = "AAAA"
            }

            $desiredRecords.Add([pscustomobject]@{
                DnsName    = $dnsName
                IPAddress  = $ipAddress
                RecordType = $recordType
                NetBoxId   = $ipObj.id
            })
        }
        catch {
            Write-Log -Level WARN -Message "Skipping invalid IP address '$($ipObj.address)' for dns_name '$dnsName': $($_.Exception.Message)"
            Add-ReportItem -Action "SKIP" -ZoneName "" -RecordName "" -RecordType "" -IPAddress $ipObj.address -DnsName $dnsName -Message "Invalid IP address"
        }
    }

    Write-Log -Level INFO -Message "Desired DNS records from NetBox: $($desiredRecords.Count)"

    foreach ($record in $desiredRecords) {
        try {
            Sync-OneDnsRecord `
                -DnsName $record.DnsName `
                -IPAddress $record.IPAddress
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to sync '$($record.DnsName)' -> '$($record.IPAddress)': $($_.Exception.Message)"
            Add-ReportItem -Action "ERROR" -ZoneName "" -RecordName "" -RecordType $record.RecordType -IPAddress $record.IPAddress -DnsName $record.DnsName -Message $_.Exception.Message
        }
    }

    if ($RemoveStaleRecords) {
        Write-Log -Level WARN -Message "RemoveStaleRecords is enabled, but stale cleanup is intentionally not implemented globally in this version."
        Write-Log -Level WARN -Message "Reason: Microsoft DNS records do not contain a native NetBox ownership marker. Blind deletion may remove manually managed records."
        Write-Log -Level WARN -Message "Recommendation: use a dedicated zone, dedicated suffix, or naming convention before enabling stale deletion."
    }

    try {
        $script:Report | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8
        Write-Log -Level INFO -Message "CSV report written to '$CsvReportPath'"
    }
    catch {
        Write-Log -Level WARN -Message "Failed to write CSV report '$CsvReportPath': $($_.Exception.Message)"
    }

    Write-Log -Level INFO -Message "Synchronization finished"
}

# ---------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------

try {
    Start-NetBoxDnsSync
}
catch {
    Write-Log -Level ERROR -Message $_.Exception.Message
    throw
}