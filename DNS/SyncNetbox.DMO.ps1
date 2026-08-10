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
    [string]$LogPath = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-DNS-Sync",
    [string]$CsvReportPath = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-DNS-Sync-Report",
    [string]$dnsMismatches = "C:\Users\thomasb\Documents\adpwsh\Logs\dnsmismatches"
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
$dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogPath = "$LogPath-$dt.log"
$CsvReportPath = "$CsvReportPath-$dt.csv"  
$dnsMismatches = "$dnsMismatches-$dt.json"
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

function Get-NBDomainIPAddresses{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # open the connection to the Netbox
    Get-NetboxSession    
    Write-Log -Level INFO -Message "Connected to NetBox: $(Get-NBVersion)"

    # Get the list of Subnets for the specified domain from Netbox
    $addresses = Get-NBIPAMAddress -All -ErrorAction Stop
    $subnets = Get-NBIPAMPrefix -All -ErrorAction Stop | Where-Object { $_.tags.name -contains $Domain }
    $netboxAddresses = @()
    foreach($sub in $subnets) {
        $subnetFilter = Get-SubnetFilter -cidr $sub.prefix
        $netboxAddresses += $addresses | Where-Object { $_.address -like "$subnetFilter*"  -and $_.status.value -eq 'active'}    
    }
    if($netboxAddresses){
        Write-Log -Level INFO -Message "Retrieved $($netboxAddresses.Count) IP addresses from NetBox for domain '$Domain'."
    }
    else {
        Write-Log -Level WARN -Message "No IP addresses found in NetBox for domain '$Domain'."
    }
    return $netboxAddresses
}

# ---------------------------------------------------------------------
# Execute Main
# ---------------------------------------------------------------------

try{

    Write-Log -Level INFO -Message "Starting NetBox to Microsoft DNS synchronization"
    Write-Log -Level INFO -Message "NetBox URL: $NetBoxBaseUrl"
    Write-Log -Level INFO -Message "DNS server: $DnsServer"
    Write-Log -Level INFO -Message "Forward zones: $($ForwardZones -join ', ')"

    Test-Prerequisites

    # get the DNS records from the DNS Server
    $dnsRecords = [System.Collections.ArrayList](Get-DNSServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZones[0] -RRType A -ErrorAction Stop)    

    # Get the Netbox IP Addresses for the specified domain
    $desiredAddresses = Get-NBDomainIPAddresses -Domain $ForwardZones[0]

    
    # Process each desired DNS record
    foreach ($ipObj in $desiredAddresses) {
        # Remove the prefix from the IP address for comparison
        $ipAddress = Get-IPAddressWithoutPrefix -Address $ipObj.address
        # test if IP addess is registered in the DNS server
        $existingRecord = $dnsRecords | Where-Object { $_.RecordData.IPv4Address -eq $ipAddress }
        if($existingRecord) {
            Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) already exists in DNS server."
            # Remove domain suffix from the existing record's hostname for comparison
            #$existingHostname = $existingRecord.HostName -replace "\.$($ForwardZones[0])$", ""
            $dnsHostname = $existingRecord.HostName -replace '\..*',''
            $nbHostname = $ipObj.dns_name -replace '\..*',''
            # check if the existing record matches the NetBox dns_name
            if($dnsHostname -ne $nbHostname) { 
                Write-Log -Level INFO -Message "Hostname Mismatch for IP $($ipObj.address): $($dnsHostname) (DNS) vs $($nbHostname) (NetBox). Updating..."
                "Hostname Mismatch for IP $($ipObj.address): $dnsHostname (DNS) vs $($ipObj.dns_name) (NetBox)." | Out-File -Append $dnsMismatches
                "DNS Record: $dnsHostname, NetBox Record: $($ipObj.dns_name)" | Out-File -Append $dnsMismatches
            }
            else {
                Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) matches NetBox. No action needed"
            }
            # Remove the existing record from the list to avoid processing it again
            foreach ($record in $existingRecord) {
                $dnsRecords.Remove($record)
                Write-Log -Level INFO -Message "Removed record: $($record.HostName) - $($record.RecordData.IPv4Address). $($dnsRecords.Count) records remaining after removal."
            }
        }
        else {
            Write-Log -Level INFO -Message "DNS record for IP $($ipObj.address) does not exist. Creating..."
        }   
    }
    Write-Log -Level INFO -Message "Synchronization complete. $($dnsRecords.Count) records remain in DNS that are not in NetBox."
    foreach ($record in $dnsRecords) {
        Write-Log -Level INFO -Message "Stale DNS record: $($record.HostName)"
    }
}
catch {
    Write-Log -Level ERROR -Message $_.Exception.Message
    throw
}