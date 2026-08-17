<#
.SYNOPSIS
    Get a IP address from Netbox and register the host in Microsoft DNS.

.DESCRIPTION
    Retrieves the next free IP address in a Netbox subnet and creates a Microsoft DNS A record. 

.PARAMETER DnsServer
   DNS server to target. Defaults to dmodc2.dmo.ctc.int.hpe.com

.PARAMETER ForwardZone
    Forward Looking Zone Name. Defaults to dmo.ctc.int.hpe.com

.PARAMETER Prefix
    Prefix of the ip address subnet

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
    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [Parameter(Mandatory = $true)]
    [string]$hostname, 

    [Parameter(Mandatory = $false)]
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",

    [Parameter(Mandatory = $false)]
    [string]$ForwardZone = "dmo.ctc.int.hpe.com",
    
     [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-IPaddress"
)

# Netbox parameters
$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api"
$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token'

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO","WARN","ERROR")]
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

# ---------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------

function Test-Prerequisites {
    Write-Log -Level INFO -Message "Checking prerequisites"

    $psModule = Get-Module -ListAvailable -Name DnsServer
    if (-not $psModule) {
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

    $psModule = Get-Module -ListAvailable -Name PowerNetbox
    if (-not $psModule) {
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

function Get-NetboxIPaddress{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Cidr,

        [Parameter(Mandatory = $true)]
        [string]$Hostname
    )
    try{
        $pref = Get-NBIPAMPrefix -Prefix $Cidr
        $ipAddress = Get-NBIPAMAvailableIP -Prefix_ID $pref.id -Limit 1
        Write-Log -Level INFO -Message "Retrieved IP Address: $ipAddress in subnet $Cidr"
        New-IPAMAddress -Address $ipAddress -Dns_name $Hostname
        return $ipAddress
    } catch {
        Write-Log -Level ERROR -Message $_.Exception.Message
        Write-Log -Level ERROR -Message "Failed to retrieve IP address from subnet $($Cidr)"
        return "0.0.0.0"
    }
}

function Register-Host{
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,

        [Parameter(Mandatory = $true)]
        [string]$Hostname
    )
    
    try{
        #Add-DnsServerResourceRecordA -Name $Hostname -ZoneName $ForwardZone -AllowUpdateAny -IPv4Address $IpAddress -ComputerName $DnsServer -CreatePtr
        Write-Log -Level INFO -Message "Registered: $($Hostname) : $($IpAddress)"
    } catch {
        Write-Log -Level ERROR -Message $_.Exception.Message
        Write-Log -Level ERROR -Message "Failed to Register: $($Hostname) : $($IpAddress)"
    }
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

try{
    Write-Log -Level INFO -Message "Get IP Address for subnet $($Prefix)"

    Test-Prerequisites

    # open the connection to the Netbox
    Get-NetboxSession    
    Write-Log -Level INFO -Message "Connected to NetBox: $(Get-NBVersion)"
    
    # Get the next IP Address
    $ip = Get-NetboxIPaddress -Cidr $Prefix -Hostname $hostname

    # Register the IP Address
    if( $ip -ne "0.0.0.0"){
        Register-Host -IpAddress $ip -Hostname $hostname
    }

} catch {
    Write-Log -Level ERROR -Message $_.Exception.Message
    throw    
}
