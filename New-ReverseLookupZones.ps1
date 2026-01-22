
<# 
.SYNOPSIS
    Creates reverse DNS zones for 10.1.1.0/24 through 10.1.255.0/24.

.DESCRIPTION
    Iterates from 10.1.1.0/24 to 10.1.255.0/24 and creates each reverse lookup zone
    using Add-DnsServerPrimaryZone -NetworkId. Skips zones that already exist.

.PARAMETER ComputerName
    Target DNS server. Defaults to local machine.

.PARAMETER ReplicationScope
    Forest | Domain | Legacy (default: Domain)

.PARAMETER DynamicUpdate
    None | NonSecureAndSecure | Secure (default: Secure)

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    # Dry-run against DNS01
    .\New-ReverseZones-10.1.x.ps1 -ComputerName DNS01 -WhatIf

.EXAMPLE
    # Create zones with Forest replication
    .\New-ReverseZones-10.1.x.ps1 -ReplicationScope Forest
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ComputerName = 'dmodc1.dmo.ctc.int.hpe.com',

    [ValidateSet('Forest','Domain','Legacy')]
    [string]$ReplicationScope = 'Domain',

    [ValidateSet('None','NonSecureAndSecure','Secure')]
    [string]$DynamicUpdate = 'Secure'
)

Import-Module DnsServer -ErrorAction Stop

# Helper: Does a reverse zone exist by expected name?
function Test-ReverseZoneExists {
    param(
        [Parameter(Mandatory=$true)][string]$ZoneName,
        [string]$ComputerName
    )
    try {
        $zone = Get-DnsServerZone -ComputerName $ComputerName -Name $ZoneName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

$results = @()

for ($i = 1; $i -le 255; $i++) {
    $networkId = "10.1.$i.0/24"
    # Zone name for /24 is third octet reversed + remaining: "i.1.10.in-addr.arpa"
    $zoneName  = "$i.1.10.in-addr.arpa"

    $action = "Create reverse zone '$zoneName' for network '$networkId' on $ComputerName (ReplicationScope=$ReplicationScope, DynamicUpdate=$DynamicUpdate)"

    try {
        if ($PSCmdlet.ShouldProcess($zoneName, $action)) {
            if (Test-ReverseZoneExists -ZoneName $zoneName -ComputerName $ComputerName) {
                Write-Verbose "Zone $zoneName already exists. Skipping."
                $results += [pscustomobject]@{
                    NetworkId        = $networkId
                    ZoneName         = $zoneName
                    ComputerName     = $ComputerName
                    ReplicationScope = $ReplicationScope
                    DynamicUpdate    = $DynamicUpdate
                    Status           = 'Exists'
                    Message          = 'Zone already present'
                }
                continue
            }

            $params = @{
                NetworkId        = $networkId
                ReplicationScope = $ReplicationScope
                DynamicUpdate    = $DynamicUpdate
                ComputerName     = $ComputerName
                PassThru         = $true
                ErrorAction      = 'Stop'
            }

            $created = Add-DnsServerPrimaryZone @params
            Write-Host "Created reverse zone: $($created.ZoneName)" -ForegroundColor Green

            $results += [pscustomobject]@{
                NetworkId        = $networkId
                ZoneName         = $created.ZoneName
                ComputerName     = $ComputerName
                ReplicationScope = $ReplicationScope
                DynamicUpdate    = $DynamicUpdate
                Status           = 'Created'
                Message          = 'Success'
            }
        }
    } catch {
        $msg = $_.Exception.Message
        Write-Warning "Failed to create $zoneName ($networkId): $msg"
        $results += [pscustomobject]@{
            NetworkId        = $networkId
            ZoneName         = $zoneName
            ComputerName     = $ComputerName
            ReplicationScope = $ReplicationScope
            DynamicUpdate    = $DynamicUpdate
            Status           = 'Error'
            Message          = $msg
        }
    }
}

# Summary
$results | Sort-Object Status, ZoneName | Format-Table -AutoSize
