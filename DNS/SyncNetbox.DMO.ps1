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
        - SimplySql PowerShell module
        - Network access to NetBox API
        - Permission to manage Microsoft DNS records

#>

[CmdletBinding()]
param(
    [string]$nbsyncpwd = "C:\Users\thomasb\Documents\adpwsh\DNS\nbsync.pwd",
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string]$ForwardZone = "dmo.ctc.int.hpe.com",
    [string]$NetBoxStatus = "active",
    [string]$Path = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-DNS-Sync"
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
$dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogPath = "$Path-$dt.log"

$script:Report = New-Object System.Collections.Generic.List[object]


# ---------------------------------------------------------------------
# Log Database helper functions
# ---------------------------------------------------------------------

function Connect-LogDB{


    $Password = Get-Content $nbsyncpwd -Raw | ConvertTo-SecureString -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential(
        "nbsync",
        $Password
    )
    try{
        Open-MySqlConnection `
            -ConnectionName Nbsync `
            -Server 10.1.103.17 `
            -Database nbsync `
            -Port 3306 `
            -Credential $Cred    
    } catch {
        Write-Host "Error opening database connection: $($_.Exception.Message)"
        throw
    }
}

function Add-LogDBEntry{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("CREATE","UPDATE","DELETE","MISMATCH","SKIP")]
        [string]$Level,
        [Parameter(Mandatory = $true)] 
        [string]$IPaddress,
        [Parameter(Mandatory = $true)] 
        [string]$Netbox,
        [Parameter(Mandatory = $true)] 
        [string]$Dns
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $Query = "INSERT INTO dns_netbox_log `
    (event_time,level,ip_address,netbox_name,dns_name)` 
    VALUES `
    ('$timestamp','$Level','$IPaddress','$Netbox','$Dns');"

    Invoke-SqlUpdate -ConnectionName Nbsync -Query $Query

}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO","WARN","ERROR","CREATE","UPDATE","DELETE","SKIP","DRYRUN")]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$IPaddress="0.0.0.0"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $Query = "INSERT INTO nbsync_errors `
    (event_time,level,ip_address,message)`
    VALUES `
    ('$timestamp','$Level','$IPaddress','$Message');"

    Invoke-SqlUpdate -ConnectionName Nbsync -Query $Query
}


function Close-Database{
    Close-SqlConnection -ConnectionName Nbsync
}

# ---------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------

function Test-Prerequisites {

    # DnsServer Powershell Module
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

    try {
        $null = Get-DnsServerZone -ComputerName $DnsServer -Name $ForwardZone -ErrorAction Stop
    }
    catch {
        throw "DNS zone '$ForwardZone' not found or not accessible on '$DnsServer'. Error: $($_.Exception.Message)"
    }

    # PowerNetbox Powershell Module
    $dnsModule = Get-Module -ListAvailable -Name PowerNetbox

    if (-not $dnsModule) {
        throw "Netbox PowerShell module not found. Install PowerNetbox tool."
    }    
    Import-Module PowerNetbox -ErrorAction Stop

    # SimpliySql Powershell Module
    $dnsModule = Get-Module -ListAvailable -Name SimplySql

    if (-not $dnsModule) {
        throw "SimplySql PowerShell module not found. Install SimplySql tool."
    }    
    Import-Module SimplySql -ErrorAction Stop    

    # Log Database connection 
    Connect-LogDB

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
        Write-Log -Level INFO -Message "Retrieved $($netboxAddresses.Count) IP addresses from NetBox for domain $($Domain)."
    }
    else {
        Write-Log -Level WARN -Message "No IP addresses found in NetBox for domain $($Domain)."
    }
    return $netboxAddresses
}

function Get-Hostname{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn
    )
    $parts = $Fqdn -split '\.', 2
    $hostname = $parts[0]

    return $hostname
}

# ---------------------------------------------------------------------
# Execute Main
# ---------------------------------------------------------------------

try{

    <#
    $line = "timestamp,level,IP address, Netbox Name, DNS Name" 
    try {
        Add-Content -Path $CsvReportPath -Value $line -Encoding UTF8
    }
    catch {
        Write-Warning "Unable to write to log file '$LogPath': $($_.Exception.Message)"
    }
    #>

    Test-Prerequisites

    Write-Log -Level INFO -Message "Starting NetBox to Microsoft DNS synchronization"
    Write-Log -Level INFO -Message "NetBox URL: $NetBoxBaseUrl"
    Write-Log -Level INFO -Message "DNS server: $DnsServer"
    Write-Log -Level INFO -Message "Forward zone: $ForwardZone"

    # get the DNS records from the DNS Server
    $dnsRecords = [System.Collections.ArrayList](Get-DNSServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZone -RRType A -ErrorAction Stop)    

    # Get the Netbox IP Addresses for the specified domain
    #$nbAddresses = @()
    #$nbAddresses = Get-NBDomainIPAddresses -Domain $ForwardZone

    # open the connection to the Netbox
    Get-NetboxSession    
    Write-Log -Level INFO -Message "Connected to NetBox: $(Get-NBVersion)"

    # Get the list of Subnets for the specified domain from Netbox
    $addresses = Get-NBIPAMAddress -All -ErrorAction Stop
    $subnets = Get-NBIPAMPrefix -All -ErrorAction Stop | Where-Object { $_.tags.name -contains $ForwardZone }
    $netboxAddresses = @()
    foreach($sub in $subnets) {
        $subnetFilter = Get-SubnetFilter -cidr $sub.prefix
        $netboxAddresses += $addresses | Where-Object { $_.address -like "$subnetFilter*"  -and $_.status.value -eq 'active'}    
    }
    if($netboxAddresses){
        Write-Log -Level INFO -Message "Retrieved $($netboxAddresses.Count) IP addresses from NetBox for domain $($ForwardZone)."
    }
    else {
        Write-Log -Level WARN -Message "No IP addresses found in NetBox for domain $($ForwardZone)."
        Close-Database
        exit(-1)
    }

    # Process each desired DNS record
    foreach ($ipObj in $netboxAddresses) {
        # Remove the prefix from the IP address for comparison
        $ipAddress = Get-IPAddressWithoutPrefix -Address $ipObj.address
        $nbHostname = $ipObj.dns_name 
        if($nbHostname.Length -gt 0){
            $nbHostname = Get-Hostname -Fqdn $nbHostname
        } 
        # test if IP addess is registered in the DNS server
        $existingRecord = $dnsRecords | Where-Object { $_.RecordData.IPv4Address -eq $ipAddress }
        if($existingRecord) {
            # Remove domain suffix from the existing record's hostname for comparison
            $dnsHostname = $existingRecord[0].HostName
            if($dnsHostname.Length -gt 0){
                $dnsHostname = Get-Hostname -Fqdn $dnsHostname
            }
            # check if the existing record matches the NetBox dns_name
            if($dnsHostname -ne $nbHostname -and $dnsHostname -ne '@') { 
                # Update the A Record on the DNS Server
                try{
                    Remove-DnsServerResourceRecord -ZoneName $ForwardZone -RRType "A" -ComputerName $DnsServer -Name $dnsHostname -RecordData $ipAddress -Force
                    Add-DnsServerResourceRecordA -Name $nbHostname -ZoneName $ForwardZone -AllowUpdateAny -IPv4Address $ipAddress -ComputerName $DnsServer -CreatePtr            
                } catch {
                    Write-Log -Level ERROR -Message $_.Exception.Message -IPaddress $ipAddress
                }
                Add-LogDBEntry -Level MISMATCH -IPaddress $ipAddress -Netbox $nbHostname -Dns $dnsHostname
            }
            else {
                Add-LogDBEntry -Level SKIP -IPaddress $ipAddress -Netbox $nbHostname -Dns $dnsHostname
            }
            # Remove the existing record from the list to avoid processing it again
            foreach ($record in $existingRecord) {
                $dnsRecords.Remove($record)
            }
        }
        else {
            if($nbHostname.Length -gt 0){
                # Add the A Record to the DNS Server
                try{
                    Add-DnsServerResourceRecordA -Name $nbHostname -ZoneName $ForwardZone -AllowUpdateAny -IPv4Address $ipAddress -ComputerName $DnsServer -CreatePtr
                } catch {
                    Write-Log -Level ERROR -Message $_.Exception.Message -IPaddress $ipAddress   
                }
                Add-LogDBEntry -Level CREATE -IPaddress $ipAddress -Netbox $nbHostname -Dns "-"
            }
            else{
                Write-Log -Level ERROR -IPaddress $ipAddress -Message "Missing Netbox Hostname!"
            } 
        }   
    }
    Write-Log -Level INFO -Message "Synchronization complete. $($dnsRecords.Count) records remain in DNS that are not in NetBox."

    foreach ($record in $dnsRecords) {
        Write-Log -Level DELETE -Message "(\'$($record.HostName)\',\'$($record.RecordData.IPv4Address)\')" -IPaddress $record.RecordData.IPv4Address
        #Remove-DnsServerResourceRecord -ZoneName $ForwardZone -RRType "A" -Name $record.HostName -RecordData $record.RecordData.IPv4Address
        Add-LogDBEntry -Level DELETE -IPaddress $record.RecordData.IPv4Address -Netbox "-" -DNs $record.HostName
    }
    Close-Database
}
catch {
    Write-Log -Level ERROR -Message "$($_.Exception.Message)"
    Close-Database
    throw
}