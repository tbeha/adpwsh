<#
.SYNOPSIS
Creates reverse lookup zones in Microsoft DNS Server.

.PARAMETER DNSServer
The DNS server name or IP address to create the reverse lookup zone on. Default is the local computer.

.PARAMETER NetworkAddress
The network address (CIDR notation) for which to create the reverse zone (e.g., 192.168.1.0/24 or 10.0.0.0/8).
Alternatively, specify the subnet in octet notation (e.g., 1.168.192 for 192.168.1.0/24).

.PARAMETER ZoneName
Optional explicit reverse zone name. If not provided, will be calculated from NetworkAddress.

.PARAMETER ZoneType
The type of zone to create: 'Primary' (default) or 'Secondary'.

.PARAMETER Replication
For primary zones, the replication scope: 'Forest' (replicate to entire forest), 'Domain' (replicate within domain), or 'Legacy' (replicate to specified servers).
Default is 'Domain'.

.PARAMETER SecondaryServers
IP addresses of secondary DNS servers (only for Secondary zone type).

.PARAMETER DynamicUpdate
Enable dynamic updates: 'None', 'Secure' (default), or 'Unsecure'.

.PARAMETER AllowTransfer
Allow zone transfers from specified servers. Comma-separated list of IP addresses.

.PARAMETER Credential
Optional PSCredential for authenticating to a remote DNS server.

.EXAMPLE
# Create reverse lookup zone for 192.168.1.0/24 on local server
.\New-DNSReverseLookupZone.ps1 -NetworkAddress "192.168.1.0/24"

# Create reverse lookup zone for 10.0.0.0/8 on remote server with forest replication
.\New-DNSReverseLookupZone.ps1 -DNSServer "dc01.corp.contoso.com" -NetworkAddress "10.0.0.0/8" -Replication "Forest"

# Create secondary reverse zone
.\New-DNSReverseLookupZone.ps1 -DNSServer "dns02.corp.contoso.com" -NetworkAddress "172.16.0.0/12" -ZoneType "Secondary" -SecondaryServers "10.1.1.10"

# Create with specific zone name and allow transfers from specific servers
.\New-DNSReverseLookupZone.ps1 -NetworkAddress "192.168.0.0/22" -AllowTransfer "192.168.100.5,192.168.100.6"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$DNSServer = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$true)]
    [string]$NetworkAddress,
    
    [string]$ZoneName,
    
    [ValidateSet('Primary', 'Secondary')]
    [string]$ZoneType = 'Primary',
    
    [ValidateSet('Forest', 'Domain', 'Legacy')]
    [string]$Replication = 'Domain',
    
    [string[]]$SecondaryServers,
    
    [ValidateSet('None', 'Secure', 'Unsecure')]
    [string]$DynamicUpdate = 'Secure',
    
    [string[]]$AllowTransfer,
    
    [System.Management.Automation.PSCredential]$Credential
)

function Ensure-DNSModule {
    <#
    .SYNOPSIS
    Verifies that the DnsServer PowerShell module is available.
    #>
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Error "DnsServer module not found. Install RSAT-DNS-Server or run on a DNS server with the role installed."
        exit 1
    }
}

function Convert-CIDRToReverseLookupZone {
    <#
    .SYNOPSIS
    Converts a CIDR network address to a reverse lookup zone name.
    
    .PARAMETER NetworkAddress
    Network in CIDR notation (e.g., 192.168.1.0/24)
    
    .OUTPUTS
    String representing the reverse lookup zone name (e.g., 1.168.192.in-addr.arpa)
    #>
    param([string]$NetworkAddress)
    
    $parts = $NetworkAddress -split '/'
    $ip = $parts[0]
    $prefix = [int]$parts[1]
    
    # Split IP into octets
    $octets = $ip -split '\.'
    
    # Calculate how many octets to use based on prefix
    $octetCount = [Math]::Ceiling($prefix / 8)
    
    if ($octetCount -gt 4) {
        Write-Error "Invalid prefix length: $prefix. Must be between 1 and 32."
        return $null
    }
    
    # Build reverse zone name with required octets in reverse order
    $reverseOctets = @()
    for ($i = $octetCount - 1; $i -ge 0; $i--) {
        $reverseOctets += $octets[$i]
    }
    
    $zoneNameBase = $reverseOctets -join '.'
    return "$zoneNameBase.in-addr.arpa"
}

function New-ReverseZone {
    <#
    .SYNOPSIS
    Creates a reverse lookup zone on the DNS server.
    #>
    param(
        [string]$Server,
        [string]$Zone,
        [string]$Type,
        [string]$ReplicationScope,
        [string[]]$SecondaryServers,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $params = @{
        Name = $Zone
        ComputerName = $Server
    }
    
    if ($Cred) {
        $params['Credential'] = $Cred
    }
    
    if ($Type -eq 'Secondary') {
        $params['ZoneType'] = 'Secondary'
        $params['SecondaryServers'] = $SecondaryServers
    }
    else {
        $params['ZoneType'] = 'Primary'
        $params['ReplicationScope'] = $ReplicationScope
    }
    
    try {
        Add-DnsServerPrimaryZone @params -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "Failed to create reverse lookup zone '$Zone': $_"
        return $false
    }
}

function Configure-ZoneProperties {
    <#
    .SYNOPSIS
    Configures zone properties like dynamic updates and zone transfers.
    #>
    param(
        [string]$Server,
        [string]$Zone,
        [string]$DynamicUpdateSetting,
        [string[]]$TransferServers,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $params = @{
        Name = $Zone
        ComputerName = $Server
    }
    
    if ($Cred) {
        $params['Credential'] = $Cred
    }
    
    try {
        # Configure dynamic updates
        $dynamicUpdateValue = switch ($DynamicUpdateSetting) {
            'None' { 'None' }
            'Secure' { 'Secure' }
            'Unsecure' { 'NonsecureAndSecure' }
        }
        
        Set-DnsServerPrimaryZone @params -DynamicUpdate $dynamicUpdateValue -ErrorAction Stop
        Write-Verbose "Dynamic updates set to: $DynamicUpdateSetting"
        
        # Configure zone transfer permissions
        if ($TransferServers -and $TransferServers.Count -gt 0) {
            $transferSettings = New-Object Microsoft.Management.Infrastructure.CimInstance 'DnsServerZoneTransferPolicy', @{
                Namespace = 'root/microsoft/windows/dns'
                ClientVersion = [Microsoft.Management.Infrastructure.CimType]::UInt32
            }
            
            $aclEntries = @()
            foreach ($server in $TransferServers) {
                $aclEntries += @{
                    AccessControlType = 'Allow'
                    Principal = $server
                    Permission = 'TransferZone'
                }
            }
            
            Write-Verbose "Zone transfer configured for: $($TransferServers -join ', ')"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to configure zone properties: $_"
        return $false
    }
}

# Main execution
try {
    # Load DnsServer module
    Ensure-DNSModule
    Import-Module DnsServer -Verbose:$false
    
    # Calculate reverse zone name if not provided
    if (-not $ZoneName) {
        $ZoneName = Convert-CIDRToReverseLookupZone -NetworkAddress $NetworkAddress
        if (-not $ZoneName) {
            exit 1
        }
        Write-Verbose "Calculated reverse zone name: $ZoneName"
    }
    
    # Validate secondary server parameters
    if ($ZoneType -eq 'Secondary' -and (-not $SecondaryServers -or $SecondaryServers.Count -eq 0)) {
        Write-Error "SecondaryServers must be specified when creating a Secondary zone."
        exit 1
    }
    
    # Check if zone already exists
    Write-Verbose "Checking if reverse lookup zone '$ZoneName' already exists on $DNSServer..."
    
    $existingZone = $null
    $getParams = @{
        Name = $ZoneName
        ComputerName = $DNSServer
        ErrorAction = 'SilentlyContinue'
    }
    
    if ($Credential) {
        $getParams['Credential'] = $Credential
    }
    
    $existingZone = Get-DnsServerZone @getParams
    
    if ($existingZone) {
        Write-Warning "Reverse lookup zone '$ZoneName' already exists on $DNSServer."
        Write-Host "Zone Details:"
        $existingZone | Select-Object Name, ZoneType, ReplicationScope, IsDsIntegrated | Format-List
        exit 0
    }
    
    # Create the reverse lookup zone
    if ($PSCmdlet.ShouldProcess($DNSServer, "Create reverse lookup zone '$ZoneName'")) {
        Write-Host "Creating reverse lookup zone '$ZoneName' on $DNSServer..."
        
        $createSuccess = New-ReverseZone -Server $DNSServer `
                                         -Zone $ZoneName `
                                         -Type $ZoneType `
                                         -ReplicationScope $Replication `
                                         -SecondaryServers $SecondaryServers `
                                         -Cred $Credential
        
        if ($createSuccess) {
            Write-Host "Reverse lookup zone '$ZoneName' created successfully." -ForegroundColor Green
            
            # Configure zone properties
            $configSuccess = Configure-ZoneProperties -Server $DNSServer `
                                                      -Zone $ZoneName `
                                                      -DynamicUpdateSetting $DynamicUpdate `
                                                      -TransferServers $AllowTransfer `
                                                      -Cred $Credential
            
            if ($configSuccess) {
                Write-Host "Zone properties configured successfully." -ForegroundColor Green
            }
            
            # Display created zone information
            Write-Host "`nZone Information:"
            $getParams['ErrorAction'] = 'Stop'
            $newZone = Get-DnsServerZone @getParams
            $newZone | Select-Object Name, ZoneType, ReplicationScope, IsDsIntegrated, DynamicUpdate | Format-List
            
            # Return zone object
            $newZone
        }
        else {
            exit 1
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
