# . Minimal Working PowerShell Example

$baseUrl = "https://netbox.example.com"
$apiToken = "YOUR_API_TOKEN"

$headers = @{
    "Authorization" = "Token $apiToken"
    "Content-Type"  = "application/json"
}

$body = @{
    address     = "192.168.100.10/24"
    status      = "active"
    description = "AD Server"
    dns_name    = "dc01.corp.local"
} | ConvertTo-Json

$response = Invoke-RestMethod -Method POST `
    -Uri "$baseUrl/api/ipam/ip-addresses/" `
    -Headers $headers `
    -Body $body

$response
``

#################################
# 3. Idempotent Version (Recommended)
# Since you’re usually automating (AD → NetBox sync), you must avoid duplicates:

function Get-NetBoxIP {
    param ($Address)

    $uri = "$baseUrl/api/ipam/ip-addresses/?address=$Address"

    try {
        (Invoke-RestMethod -Method GET -Uri $uri -Headers $headers).results
    } catch {
        throw "Failed to query NetBox: $_"
    }
}

function New-NetBoxIP {
    param (
        [string]$Address,
        [string]$DnsName,
        [string]$Description = "Imported from AD"
    )

    $existing = Get-NetBoxIP -Address $Address

    if ($existing.count -gt 0) {
        Write-Host "IP already exists: $Address"
        return $existing[0]
    }

    $body = @{
        address     = $Address
        status      = "active"
        dns_name    = $DnsName
        description = $Description
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Method POST `
            -Uri "$baseUrl/api/ipam/ip-addresses/" `
            -Headers $headers `
            -Body $body
    } catch {
        throw "Failed to create IP $Address : $_"
    }
}


###########################################################
# 4. Example: Sync AD DNS records → NetBox
# Typical real-world flow (fits your AD/DNS automation work):

Import-Module ActiveDirectory

Get-ADComputer -Filter * -Properties DNSHostName | ForEach-Object {

    if ($_.DNSHostName) {
        try {
            $ip = [System.Net.Dns]::GetHostAddresses($_.DNSHostName) |
                  Where-Object {$_.AddressFamily -eq "InterNetwork"} |
                  Select-Object -First 1

            if ($ip) {
                New-NetBoxIP `
                    -Address "$($ip.IPAddressToString)/24" `
                    -DnsName $_.DNSHostName `
                    -Description "Imported from AD: $($_.Name)"
            }
        }
        catch {
            Write-Warning "Failed for $($_.Name): $_"
        }
    }
}


################################################################
# 5. Advanced (Enterprise-grade Enhancements)

$apiToken = Get-Content "C:\secure\netbox.token" | ConvertTo-SecureString
``

# Use PowerNetBox module (recommended)
# Instead of raw API:  https://github.com/ctrl-alt-automate/PowerNetbox

Install-Module PowerNetbox

$token = "YOUR_TOKEN"
$nb = Connect-NBApi -Url "https://netbox.example.com" -Token $token

New-NBIPAMAddress `
    -Address "192.168.100.10/24" `
    -Status active `
    -Description "AD Server"
