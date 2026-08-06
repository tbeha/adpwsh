
$DNSserver = @(
    "10.1.20.12",
    "10.1.20.11"
)

$Subnets = @(
    '15','16','17','18','22','27','30','31','32','33','34','37','38',
    '47','48','50','53','53','55','60','61','62','63','64','65','66',
    '67','68','69','72','77','78','79','87','88','89','90','91','92','93','94','95','96','97','98','99'
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

# Main execution
try {
    # Load DnsServer module
    Ensure-DNSModule
    Import-Module DnsServer -Verbose:$false

    # Get the DNS User Credential if not provided
    if ($Credential) {
        $getParams['Credential'] = $Credential
    }

    # Work the subnet list
    foreach ($sub in 2..8) {
        $zoneName = "$sub.1.10.in-addr.arpa"
        foreach( $DNS  in $DNSserver) {
            try {
                Remove-DnsServerZone -Name $zoneName -ComputerName $DNS -Force -ErrorAction Stop
                Write-Host "Successfully deleted reverse lookup zone: $zoneName"
            }
            catch {
                Write-Error "Failed to delete reverse lookup zone $zoneName : $_"
            }
        }
    }

} 
catch {
    Write-Error "An error occurred: $_"
    exit 1
}