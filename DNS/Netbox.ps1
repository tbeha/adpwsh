# ================= CONFIG =================
$phpipamBaseUrl = "https://phpipam.local/api"
$phpipamAppId   = "myapp"
$phpipamToken   = "your_phpipam_token"

$netboxBaseUrl  = "https://netbox.local/api"
$netboxToken    = "nbt_xxxxxxxxxxxxxxxxx"

$subnetId       = 5   # phpIPAM subnet ID

$logFile = "C:\Logs\ipam_sync.log"
# =========================================

function Write-Log {
    param($Message, $Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Tee-Object -FilePath $logFile -Append
}

function Get-PhpIpamAddresses {
    param (
        [int]$SubnetId
    )

    $headers = @{
        "token" = $phpipamToken
    }

    $url = "$phpipamBaseUrl/$phpipamAppId/subnets/$SubnetId/addresses/"

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        Write-Log "Retrieved $($response.data.Count) IPs from phpIPAM"
        return $response.data
    }
    catch {
        Write-Log "Failed to retrieve IPs from phpIPAM: $_" "ERROR"
        throw
    }
}

function Get-NetBoxIP {
    param (
        [string]$IPAddress
    )

    $headers = @{
        "Authorization" = "Token $netboxToken"
        "Content-Type"  = "application/json"
    }

    $url = "$netboxBaseUrl/ipam/ip-addresses/?address=$IPAddress"

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        if ($resp.count -gt 0) {
            return $true
        }
        return $false
    }
    catch {
        Write-Log "Error checking IP $IPAddress in NetBox: $_" "ERROR"
        return $false
    }
}

function Add-NetBoxIP {
    param (
        [string]$IPAddress,
        [string]$Description
    )

    $headers = @{
        "Authorization" = "Token $netboxToken"
        "Content-Type"  = "application/json"
    }

    $body = @{
        address     = $IPAddress
        status      = "active"
        description = $Description
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Uri "$netboxBaseUrl/ipam/ip-addresses/" -Headers $headers -Method Post -Body $body
        Write-Log "Created IP $IPAddress in NetBox"
    }
    catch {
        Write-Log "Failed to create IP $IPAddress : $_" "ERROR"
    }
}

function Test-NetBoxPrefixExists {
    param(
        [string]$Prefix
    )

    $headers = @{
        "Authorization" = "Token $NetboxToken"
    }

    $url = "$NetboxUrl/ipam/prefixes/?prefix=$Prefix"

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
        return ($resp.count -gt 0)
    }
    catch {
        Write-Log "Error checking prefix $Prefix : $_" "ERROR"
        return $false
    }
}

function New-NetBoxPrefix {
    param(
        [string]$Prefix,
        [string]$Description,
        [string]$Site = $null,
        [string]$Tenant = $null
    )

    $headers = @{
        "Authorization" = "Token $NetboxToken"
        "Content-Type"  = "application/json"
    }

    $body = @{
        prefix      = $Prefix
        status      = "active"
        description = $Description
    }

    if ($Site)   { $body.site   = $Site }
    if ($Tenant) { $body.tenant = $Tenant }

    $json = $body | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Uri "$NetboxUrl/ipam/prefixes/" `
            -Method POST -Headers $headers -Body $json

        Write-Log "Created prefix $Prefix"
    }
    catch {
        Write-Log "Failed to create prefix $Prefix : $_" "ERROR"
    }
}


$ips = Get-PhpIpamAddresses -SubnetId $subnetId

foreach ($ip in $ips) {

    # Normalize address format (NetBox requires CIDR)
    $cidr = "$($ip.ip)/$($ip.mask)"

    Write-Log "Processing $cidr"

    $exists = Get-NetBoxIP -IPAddress $cidr

    if (-not $exists) {
        Add-NetBoxIP -IPAddress $cidr -Description $ip.description
    }
    else {
        Write-Log "IP $cidr already exists in NetBox - skipping"
    }
}
