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
    [Parameter(Mandatory=$true)]
    [string]$phpIPAMUrl,
    
    [string]$AppId,
    
    [string]$ApiKey,
    
    [string]$Token,
    
    [string]$ZoneName,
    
    [string]$RecordType,
    
    [string]$ExportPath,
    
    [ValidateSet('CSV', 'JSON')]
    [string]$ExportFormat = 'JSON'
)

# Suppress certificate validation warnings if needed (not recommended for production)
if ($PSVersionTable.PSVersion.Major -eq 5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

function Get-phpIPAMAuthToken {
    <#
    .SYNOPSIS
    Authenticates to phpIPAM API and returns an auth token.
    #>
    param(
        [string]$Url,
        [string]$AppId,
        [string]$ApiKey
    )
    
    $authUrl = "$Url/user/"
    
    try {
        $response = Invoke-RestMethod -Uri $authUrl `
            -Method Post `
            -ContentType 'application/json' `
            -Headers @{
                'phpipam-app-id' = $AppId
            } `
            -Body (ConvertTo-Json @{ token = $ApiKey })
        
        if ($response.success) {
            return $response.data.token
        }
        else {
            Write-Error "Authentication failed: $($response.message)"
            exit 1
        }
    }
    catch {
        Write-Error "Authentication request failed: $_"
        exit 1
    }
}

function Invoke-phpIPAMRequest {
    <#
    .SYNOPSIS
    Makes an authenticated request to the phpIPAM API.
    #>
    param(
        [string]$Endpoint,
        [string]$Token,
        [string]$Method = 'Get'
    )
    
    try {
        $response = Invoke-RestMethod -Uri $Endpoint `
            -Method $Method `
            -ContentType 'application/json' `
            -Headers @{
                'phpipam-app-id' = $Token
            }
        
        return $response
    }
    catch {
        Write-Error "API request failed: $_"
        $null
    }
}

# Main execution
try {
    # Validate parameters
    if (-not $Token -and (-not $AppId -or -not $ApiKey)) {
        Write-Error "Either -Token or both -AppId and -ApiKey must be provided."
        exit 1
    }
    
    # Get authentication token if not provided
    if (-not $Token) {
        Write-Verbose "Authenticating to phpIPAM..."
        $Token = Get-phpIPAMAuthToken -Url $phpIPAMUrl -AppId $AppId -ApiKey $ApiKey
        Write-Verbose "Authentication successful."
    }
    
    # Retrieve DNS zones
    Write-Verbose "Retrieving DNS zones..."
    $zonesEndpoint = "$phpIPAMUrl/dns/"
    $zonesResponse = Invoke-phpIPAMRequest -Endpoint $zonesEndpoint -Token $Token
    
    if (-not $zonesResponse.success) {
        Write-Error "Failed to retrieve DNS zones: $($zonesResponse.message)"
        exit 1
    }
    
    $zones = $zonesResponse.data
    if (-not $zones) {
        Write-Warning "No DNS zones found."
        $zones = @()
    }
    
    # Filter zones if specified
    if ($ZoneName) {
        $zones = $zones | Where-Object { $_.name -like "*$ZoneName*" }
        if (-not $zones) {
            Write-Warning "No zones matching filter '$ZoneName' found."
            $zones = @()
        }
    }
    
    $dnsRecords = @()
    
    # Retrieve DNS records for each zone
    foreach ($zone in $zones) {
        Write-Verbose "Processing zone: $($zone.name) (ID: $($zone.id))"
        
        $recordsEndpoint = "$phpIPAMUrl/dns/$($zone.id)/records/"
        $recordsResponse = Invoke-phpIPAMRequest -Endpoint $recordsEndpoint -Token $Token
        
        if ($recordsResponse.success) {
            $records = $recordsResponse.data
            if ($records) {
                # Filter by record type if specified
                if ($RecordType) {
                    $records = $records | Where-Object { $_.type -eq $RecordType }
                }
                
                # Add zone name to each record for context
                foreach ($record in $records) {
                    $record | Add-Member -NotePropertyName 'ZoneName' -NotePropertyValue $zone.name
                    $dnsRecords += $record
                }
                
                Write-Verbose "Found $($records.Count) records in zone $($zone.name)"
            }
        }
        else {
            Write-Warning "Failed to retrieve records for zone $($zone.name): $($recordsResponse.message)"
        }
    }
    
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
    }
    
    # Return all records to pipeline
    $dnsRecords
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
