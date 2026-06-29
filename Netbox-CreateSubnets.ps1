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
    [string]$phpIpamToken = '.\phpIPAM.token',
    [string]$netboxBaseUrl = "http://10.1.44.18:8080/api",
    [string]$netboxTokenPath = '.\netbox.token'
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
    
    # Get DNS subnets
    $subnets = @()
    $subnets =  Get-PhpIpamAllSubnets    

    foreach ($net in $subnets) {
        # Only check on 10.1.x.x networks, ignore all other ones
        if( $net.subnet.StartsWith("10.1.")){  
            $vlan = ($net.subnet -split '\.')[2]
            $prefix = $net.subnet + "/" + $net.mask
            # Check if prefix exists
            $existing = Get-NBIPAMPrefix | Where-Object { $_.prefix -eq $prefix}
            if( -not $existing ){
                Write-Host "Prefix $prefix does not exist, creating ..."
                New-NBIPAMPrefix -prefix $prefix -status "active" -description $net.description
            } else {
                Write-Host "Prefix already exists: $($existing.prefix)"
            }
            #Write-Host $prefix $vlan
            #Write-Host $net.subnet $net.mask $net.description $vlan $prefix
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
