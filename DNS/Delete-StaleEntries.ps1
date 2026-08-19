<#

#>
[CmdletBinding()]
param(
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string]$ForwardZone = "dmo.ctc.int.hpe.com",
    [string]$NetBoxStatus = "active",
    [string]$Path = "C:\Users\thomasb\Documents\adpwsh\Logs\DNSstale"
)

$staleEntries = @(
    ('modtb1001','10.1.73.48')
)



Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
$dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogPath = "$Path-$dt.log"

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


    try {
        $null = Get-DnsServerZone -ComputerName $DnsServer -Name $ForwardZone -ErrorAction Stop
        Write-Log -Level INFO -Message "Validated DNS zone '$ForwardZone' on '$DnsServer'"
    }
    catch {
        throw "DNS zone '$ForwardZone' not found or not accessible on '$DnsServer'. Error: $($_.Exception.Message)"
    }

}

# ---------------------------------------------------------------------
# Execute Main
# ---------------------------------------------------------------------

try{

    $line = "timestamp,level,IP address, Netbox Name, DNS Name" 
    try {
        Add-Content -Path $CsvReportPath -Value $line -Encoding UTF8
    }
    catch {
        Write-Warning "Unable to write to log file '$LogPath': $($_.Exception.Message)"
    }

    Write-Log -Level INFO -Message "Starting NetBox to Microsoft DNS synchronization"
    Write-Log -Level INFO -Message "NetBox URL: $NetBoxBaseUrl"
    Write-Log -Level INFO -Message "DNS server: $DnsServer"
    Write-Log -Level INFO -Message "Forward zone: $ForwardZone"

    Test-Prerequisites

    # get the DNS records from the DNS Server
    $dnsRecords = [System.Collections.ArrayList](Get-DNSServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZone -RRType A -ErrorAction Stop)   


    foreach( $record in $staleEntries){

        # test if IP addess is registered in the DNS server
        $dnsEntry = $dnsRecords | Where-Object { $_.RecordData.IPv4Address -eq $record[1] }        
        #$dnsEntry = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZone -Name $dnsRecord[0]
        foreach($x in $dnsEntry){
            Write-Log -Level Info -Message "Process $($x.HostName) - $($record[1])"
            try{
                Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ForwardZone -RRType 'A' -Name $x.Hostname -RecordData $record[1]
            } catch {
                Write-Log -Level ERROR -Message $_.Exception.Message
            }
        }
        Write-Log -Level Info -Message "Deleted: $($record[0]) - $($record[1])"
    }


} catch {
    Write-Log -Level ERROR -Message $_.Exception.Message
    throw    
}
