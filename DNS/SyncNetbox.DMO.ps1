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
    [string]$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string[]]$ForwardZones = @("dmo.ctc.int.hpe.com"),
    [string]$NetBoxStatus = "active",
    [int]$PageLimit = 1000,
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
    $secureToken = Get-Content $netboxToken -Raw | ConvertTo-SecureString -AsPlainText -Force
    $nbcred = [pscredential]::new('admin', $securetoken)
    Connect-NBApi -Uri $netboxBaseUrl -Credential $nbcred -SkipCertificateCheck
}

# ---------------------------------------------------------------------
# DNS helper functions
# ---------------------------------------------------------------------

function Get-SubnetFilter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$cidr
    )
  
    if($cidr -match "^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\/(\d{1,2})$") {
        # Replace last octet with a wildcard for filtering
        $wildcard = "$($matches[1]).*"
    }
    else {
        throw "Invalid CIDR format: $cidr"
    }

    return $wildcard
}

function Get-IPAddressWithoutPrefix {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    return ($Address -split "/")[0]
}

# ---------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------

try{

    Write-Log -Level INFO -Message "Starting NetBox to Microsoft DNS synchronization"
    Write-Log -Level INFO -Message "NetBox URL: $NetBoxBaseUrl"
    Write-Log -Level INFO -Message "DNS server: $DnsServer"
    Write-Log -Level INFO -Message "Forward zones: $($ForwardZones -join ', ')"
    Write-Log -Level INFO -Message "WhatIf mode: $WhatIfMode"
    Write-Log -Level INFO -Message "Update existing: $UpdateExisting"
    Write-Log -Level INFO -Message "Create PTR: $CreatePtr"

    Test-Prerequisites

    # get the DNS records from the DNS Server
    $dnsRecords = Get-DNSServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZones[0] -ErrorAction Stop

    # open the connection to the Netbox
    Get-NetboxSession    
    Write-Log -Level INFO -Message "Connected to NetBox: $(Get-NBVersion)"

    # Get the list of Subnets for the specified domain from Netbox
    $addresses = Get-NBIPAMAddress -All -ErrorAction Stop
    $subnets = Get-NBIPAMPrefix -All -ErrorAction Stop | Where-Object { $_.tags.name -contains $ForwardZones[0] }
    $netboxAddresses = @()
    foreach($sub in $subnets) {
        $subnetFilter = Get-SubnetFilter -cidr $sub.prefix
        $netboxAddresses += $addresses | Where-Object { $_.address -like "$subnetFilter*" }    
    }

    # Process each desired DNS record
    foreach ($ipObj in $netboxAddresses) {
        # test if IP addess is registered in the DNS server
        $existingRecord = $dnsRecords | Where-Object { $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -eq $ipObj.address }
        if($existingRecord) {
            Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) already exists in DNS server."
            # check if the existing record matches the NetBox dns_name
            if($existingRecord.HostName -ne $ipObj.dns_name) { 
                Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) has a different hostname. Updating..."
                # Here you would add the logic to update the DNS record

            }
            else {
                Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) matches NetBox. No action needed."
            }
            $dnsRecords.Remove($existingRecord) # Remove from the list to track stale records
        }
        else {
            Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) does not exist. Creating..."
            # Here you would add the logic to create the DNS record
            #$result = Add-DnsServerResourceRecordA -ComputerName $DnsServer -ZoneName $ForwardZones[0] -CreatePtr -IPAddress $ipObj.address -HostName $ipObj.dns_name -ErrorAction Stop
            #Write-Log -Level INFO -Message "Created DNS record: $($result.HostName) -> $($result.RecordData.IPv4Address)"
        }   
    }
}
catch {
    Write-Log -Level ERROR -Message $_.Exception.Message
    throw
}