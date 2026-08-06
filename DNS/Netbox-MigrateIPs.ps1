<#
.SYNOPSIS
Retrieves DNS entries from phpIPAM API.

.PARAMETER phpIPAMUrl
The base URL of the phpIPAM installation (e.g., https://phpipam.example.com/api).

.PARAMETER AppId
The API app ID for authentication.

.PARAMETER ApiKey
The API app code/key for authentication (optional if using token-based auth).

.PARAMETER Token
Netbox Token

.PARAMETER ZoneName
Optional filter by DNS zone name. If not specified, returns all zones.

.PARAMETER RecordType
Optional filter by DNS record type (A, AAAA, CNAME, MX, NS, SOA, SRV, TXT, etc.).

.PARAMETER ExportPath
Optional path to export results as CSV or JSON.

.PARAMETER ExportFormat
Export format: 'CSV' or 'JSON'. Default is 'JSON'.

.EXAMPLE
# Get all DNS entries
.\Get-phpIPAMDNSEntries.ps1 -phpIPAMUrl "https://phpipam.example.com/api" -AppId "myapp" -ApiKey "mykey"

# Get DNS entries for a specific zone and export to CSV
.\Get-phpIPAMDNSEntries.ps1 -phpIPAMUrl "https://phpipam.example.com/api" -AppId "myapp" -ApiKey "mykey" -ZoneName "example.com" -ExportPath "c:\temp\dns-records.csv" -ExportFormat "CSV"

# Get A records only
.\Get-phpIPAMDNSEntries.ps1 -phpIPAMUrl "https://phpipam.example.com/api" -AppId "myapp" -ApiKey "mykey" -RecordType "A"

# Use pre-generated token
.\Get-phpIPAMDNSEntries.ps1 -phpIPAMUrl "https://phpipam.example.com/api" -Token "yourtoken123"
#>

[CmdletBinding()]
param(
    [string]$phpIPAMUrl = "http://suo04ctcinf7.demo.local/api/",
    [string]$AppId = "DNS",
    [string]$phpIpamToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\phpIPAM.token',
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxTokenPath = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token'
)

<#
$subnets = @(
    '10.1.35.'     10.1.35.11 hostname not conforming to naming convention
    '10.1.39.'     10.1.39.202 hostname not conforming to naming convention 
    #>
    
$subnets = @(
    '10.1.1.'
    '10.1.10.'
    '10.1.11.'
    '10.1.20.'
    '10.1.21.'
    '10.1.24.'
    '10.1.25.'
    '10.1.26.'
    '10.1.29.'
    '10.1.36.'
    '10.1.40.'
    '10.1.41.'
    '10.1.42.'
    '10.1.43.'
    '10.1.44.'
    '10.1.45.'
    '10.1.46.'
    '10.1.49.'
    '10.1.73.'
    '10.1.80.'
    '10.1.83.'
    '10.1.84.'
    '10.1.85.'
    '10.1.86.'
    '10.1.90.'
    '10.1.121.'
    '10.1.122.'
    '10.1.240.'
    '10.1.241.'
    '10.1.242.'
    '10.1.243.'
    '10.1.244.'
    '10.1.245.'
    '10.1.248.'
    '10.1.255.'
    )



# Use PowerNetBox module (recommended)
# Instead of raw API:  https://github.com/ctrl-alt-automate/PowerNetbox

Import-Module PowerNetbox

# Load the PSPHPIPAM module
Import-Module PSPHPIPAM

function Get-phpIPAMSession {
    <#
    .SYNOPSIS
    Authenticates to phpIPAM API.
    #>
    param(
        [string]$Url,
        [string]$AppId,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $response = New-PhpIpamSession -UseCredAuth `
        -PhpIpamApiUrl $Url `
        -AppID $AppId `
        -Username $Cred.UserName `
        -Password $Cred.GetNetworkCredential().Password
        if( $response){
           Write-Host "Authentication successful."
        } 
        else {
            Write-Error "Authentication failed. No token received."
            exit 1
        }   
    }
    catch {
        Write-Error "Authentication request failed: $_"
        exit 1
    }
}

function Get-NetboxSession{

    $secureToken = Get-Content $netboxTokenPath -Raw | ConvertTo-SecureString -AsPlainText -Force
    $nbcred = [pscredential]::new('admin', $securetoken)
    Connect-NBApi -Uri $netboxBaseUrl -Credential $nbcred -SkipCertificateCheck

}


# Main execution
try {
    # open the connection to the Netbox
    Get-NetboxSession
    Get-NBversion | Write-Host
    # Get phpIPAM session 
    $securePassword = Get-Content '.\phpIPAM.token' | ConvertTo-SecureString -AsPlainText -Force
    $phpcred = [pscredential]::new('morpheus', $securePassword)
    Get-phpIPAMSession -Url $phpIPAMUrl -AppId $AppId -Cred $phpcred
    
    # Work the subnet list
    foreach ($sub in $subnets) {
        # Get phpIPAM DNS Entries of the subnet.
        $dnsRecords = @()
        $dnsRecords = Get-PhpIpamAddresses | Where-Object { $_.ip.StartsWith($sub)}
        # Output results 
        Write-Host "Retrieved $($dnsRecords.Count) DNS records in subnet $($sub)."
        foreach ($dns in $dnsRecords) {
            # Check if IP Address already exists in Netbox
            $existing = Get-NBIPAMAddress -Address $dns.ip
            if( -not $existing){
                # Check if an owner is assigned
                if($dns.owner -eq $null){
                     # No existing owner, just create the IP address without owner
                    Write-Host "$($dns.ip) does not exist yet, creating ..."
                    $result = New-NBIPAMAddress -Address ($dns.ip + "/24") -Dns_name $dns.hostname -Description $dns.description                   
                } else {
                    # Get Owner ID
                    $owner = Get-NBOwner -Name $dns.owner
                    if( -not $owner ) {
                        Write-Host "$($dns.owner) does not exist yet, creating ..."
                        $owner = New-NBOwner -Name $dns.owner -Group 1
                        # Write-Host $owner
                    }
                    Write-Host "$($dns.ip) does not exist yet, creating ..."
                    $result = New-NBIPAMAddress -Address ($dns.ip + "/24") -Dns_name $dns.hostname -Description $dns.description  -Owner $owner.id                                        
                }      
            } else {
                Write-Host "IP Address already exists: $($dns.ip) - updating the DNS record ..."    
                $result = Set-NBIPAMAddress -Address ($dns.ip + "/24") -Dns_name $dns.hostname -Description $dns.description -Id $existing.id 
            }
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
