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
Optional pre-generated API token instead of using AppId and ApiKey.

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
    [string]$phpIPAMUrl = "http://suo04ctcinf7.demo.local/administration/api/",
    [string]$AppId = "DNS",
    [System.Management.Automation.PSCredential] $Credential,
    [string]$ExportPath = "./output/dnsrecords.csv",
    [ValidateSet('CSV', 'JSON')]
    [string]$ExportFormat = 'CSV'
)

# Load the PSPHPIPAM module
Import-Module PSPHPIPAM

# Suppress certificate validation warnings if needed (not recommended for production)
if ($PSVersionTable.PSVersion.Major -eq 5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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
        New-PhpIpamSession -UseCredAuth `
        -PhpIpamApiUrl $Url `
        -AppID $AppId `
        -Username $Cred.UserName `
        -Password $Cred.GetNetworkCredential().Password
        
    }
    catch {
        Write-Error "Authentication request failed: $_"
        exit 1
    }
}

# Main execution
try {
    <# Validate parameters
    if (-not $Credential) {
        Write-Error "Credential must be provided."
        exit 1
    }
 
    $Credential = Get-Credential -UserName "morpheus"
    
    # Convert plain text password to SecureString
    $securePassword = ConvertTo-SecureString "We95sms!!" -AsPlainText -Force
    # Create the PSCredential object
    $credential = New-Object System.Management.Automation.PSCredential ("morpheus", $securePassword)
    #>
    $Credential = Get-Credential -UserName "morpheus"

    # Get authentication session 
    Get-phpIPAMSession -Url $phpIPAMUrl -AppId $AppId -Cred $Credential

    # Get DNS subnets
    $subnets = @()
    $subnets =  Get-PhpIpamAllSubnets

    # Get all DNS records
    
    $dnsRecords = @()
    $dnsRecords = Get-PhpIpamAddresses
       
    # Output results 
    Write-Host "Retrieved $($dnsRecords.Count) DNS records."
    
    if ($dnsRecords.Count -gt 0) { 
        # Display first 10 records
        Write-Host "`nShowing first 10 records:"
        $dnsRecords | Select-Object -First 10 | Format-Table -AutoSize
        
        # Export if requested
        if ($ExportPath) {
            try {
                if ($ExportFormat -eq 'CSV') {
                    $dnsRecords | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                    Write-Host "Records exported to CSV: $ExportPath"
                }
                else {
                    $dnsRecords | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportPath -Force
                    Write-Host "Records exported to JSON: $ExportPath"
                }
            }
            catch {
                Write-Error "Failed to export records: $_"
            }
        } 

        # Export subnets list if requested
        if ($ExportPath -and $ExportFormat -eq 'CSV') {   
            $subnets | Export-Csv -Path ($ExportPath -replace '\.csv$', '-subnets.csv') -NoTypeInformation -Force
            Write-Host "Subnets exported to CSV: $($ExportPath -replace '\.csv$', '-subnets.csv')"
        }

        # Export Subnet specific DNS records
        foreach ($subnet in $subnets) {
            $subnetDnsRecords = $dnsRecords | Where-Object { $_.subnetId -eq $subnet.id }
            if ($subnetDnsRecords.Count -gt 0) {
                $subnetExportPath = $ExportPath -replace '\.csv$', "-$($subnet.subnet).csv"
                $subnetDnsRecords | Export-Csv -Path $subnetExportPath -NoTypeInformation -Force
                Write-Host "Subnet specific DNS records exported to CSV: $subnetExportPath"
            }
        }   
    }    
    # Return all records to pipeline
    #$dnsRecords
     
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
