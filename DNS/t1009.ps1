#Requires -Version 7.2
#Requires -Modules DnsServer

<#
.SYNOPSIS
Allocates the next available IPv4 address from a NetBox prefix and
registers the address in NetBox and Microsoft DNS.

.DESCRIPTION
Workflow:
  1. Find an exact prefix in NetBox.
  2. Atomically allocate the next available IP using the NetBox
     prefix available-ips endpoint.
  3. Store the FQDN in the NetBox IP address dns_name field.
  4. Create Microsoft DNS A and PTR records.
  5. Roll back the NetBox allocation and any DNS A record if DNS
     registration fails.

The NetBox API token is read from an environment variable by default.
Do not embed API tokens directly in this script.

.EXAMPLE
$env:NETBOX_API_TOKEN = Get-Content C:\Secure\NetBoxToken.txt

.\Register-NetBoxDnsAddress.ps1 `
    -NetBoxUrl "https://netbox.example.com" `
    -Prefix "192.168.100.0/24" `
    -HostName "server01.example.com" `
    -DnsServer "dns01.example.com" `
    -DnsZone "example.com" `
    -Description "Application server"

.EXAMPLE
.\Register-NetBoxDnsAddress.ps1 `
    -NetBoxUrl "https://netbox.example.com" `
    -Prefix "10.1.44.0/24" `
    -HostName "dmoapp001.dmo.ctc.int.hpe.com" `
    -DnsServer "dmodc01.dmo.ctc.int.hpe.com" `
    -DnsZone "dmo.ctc.int.hpe.com" `
    -NetBoxToken $env:NETBOX_API_TOKEN `
    -DnsCredential (Get-Credential) `
    -AgeRecord
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$NetBoxUrl,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F:.]+/\d{1,3}$')]
    [string]$Prefix,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')]
    [string]$HostName,

    [Parameter(Mandatory)]
    [string]$DnsServer,

    [Parameter(Mandatory)]
    [string]$DnsZone,

    [Parameter()]
    [string]$NetBoxToken = $env:NETBOX_API_TOKEN,

    [Parameter()]
    [pscredential]$DnsCredential,

    [Parameter()]
    [ValidateSet('active', 'reserved', 'deprecated', 'dhcp', 'slaac')]
    [string]$NetBoxStatus = 'active',

    [Parameter()]
    [string]$Description = 'Allocated by PowerShell',

    [Parameter()]
    [ValidateRange(60, 86400)]
    [int]$DnsTtlSeconds = 3600,

    [Parameter()]
    [switch]$AgeRecord
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NetBoxRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post', 'Patch', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory)]
        [uri]$Uri,

        [Parameter()]
        [object]$Body
    )

    $headers = @{
        Authorization = "Token $NetBoxToken"
        Accept        = 'application/json'
    }

    $parameters = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 10
    }

    try {
        Invoke-RestMethod @parameters
    }
    catch {
        $statusCode = $null
        $responseBody = $null

        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode

            try {
                $responseBody = $_.ErrorDetails.Message
            }
            catch {
                $responseBody = $null
            }
        }

        $message = "NetBox API request failed: $Method $Uri"

        if ($statusCode) {
            $message += " HTTP status: $statusCode."
        }

        if ($responseBody) {
            $message += " Response: $responseBody"
        }

        throw $message
    }
}

function Get-DnsRelativeName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Fqdn,

        [Parameter(Mandatory)]
        [string]$Zone
    )

    $normalizedFqdn = $Fqdn.TrimEnd('.').ToLowerInvariant()
    $normalizedZone = $Zone.TrimEnd('.').ToLowerInvariant()

    if ($normalizedFqdn -eq $normalizedZone) {
        return '@'
    }

    $zoneSuffix = ".$normalizedZone"

    if (-not $normalizedFqdn.EndsWith($zoneSuffix)) {
        throw "Hostname '$Fqdn' is not contained in DNS zone '$Zone'."
    }

    return $normalizedFqdn.Substring(
        0,
        $normalizedFqdn.Length - $zoneSuffix.Length
    )
}

function Get-ExistingDnsARecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $parameters = @{
        ComputerName = $DnsServer
        ZoneName     = $DnsZone
        Name         = $Name
        RRType       = 'A'
        ErrorAction  = 'SilentlyContinue'
    }

    if ($DnsCredential) {
        $cimSession = New-CimSession `
            -ComputerName $DnsServer `
            -Credential $DnsCredential

        try {
            $parameters.Remove('ComputerName')
            $parameters.CimSession = $cimSession
            return @(Get-DnsServerResourceRecord @parameters)
        }
        finally {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }

    return @(Get-DnsServerResourceRecord @parameters)
}

# ---------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------

$NetBoxUrl = $NetBoxUrl.TrimEnd('/')
$HostName  = $HostName.TrimEnd('.').ToLowerInvariant()
$DnsZone   = $DnsZone.TrimEnd('.').ToLowerInvariant()

if ([string]:: {
    throw @"
No NetBox API token was supplied.

Set it for the current process with:
`$env:NETBOX_API_TOKEN = '<token>'

For production use, retrieve it from a secret vault rather than storing
it in the script or in a plaintext profile.
"@
}

try {
    $prefixNetwork = [System.Net.IPNetwork]::Parse($Prefix)
}
catch {
    throw "Prefix '$Prefix' is not a valid IP prefix."
}

if ($prefixNetwork.AddressFamily -ne
    [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'This script currently creates IPv4 A records only.'
}

$relativeDnsName = Get-DnsRelativeName `
    -Fqdn $HostName `
    -Zone $DnsZone

$dnsTtl = [TimeSpan]::FromSeconds($etBoxObject = $null
$dnsARecordCreated = $false
$dnsCimSession = $null

try {
    # -----------------------------------------------------------------
    # 1. Verify that the DNS hostname does not already exist
    # -----------------------------------------------------------------

    $existingDnsRecords = Get-ExistingDnsARecord -Name $relativeDnsName

    if ($existingDnsRecords.Count -gt 0) {
        $existingAddresses = @(
            $existingDnsRecords |
                ForEach-Object {
                    $_.RecordData.IPv4Address.IPAddressToString
                }
        )

        throw (
            "DNS name '$HostName' already has an A record: {0}" -f
            ($existingAddresses -join ', ')
        )
    }

    # -----------------------------------------------------------------
    # 2. Find the exact prefix in NetBox
    # -----------------------------------------------------------------

    $encodedPrefix = [uri]::
    $prefixLookupUri =
        "$NetBoxUrl/api/ipam/prefixes/?prefix=$encodedPrefix"

    Write-Verbose "Looking up NetBox prefix '$Prefix'."

    $prefixResult = Invoke-NetBoxRestMethod `
        -Method Get `
        -Uri $prefixLookupUri

    if ($prefixResult.count -eq 0) {
        throw "Prefix '$Prefix' was not found in NetBox."
    }

    if ($prefixResult.count -gt 1) {
        $matchingPrefixes = @(
            $prefixResult.results |
                Where-Object { $_.prefix -eq $Prefix }
        )

        if ($matchingPrefixes.Count -ne 1) {
            throw @"
NetBox returned multiple prefixes for '$Prefix'.
Use a unique prefix or extend the lookup with a VRF filter.
"@
        }

        $netBoxPrefix = $matchingPrefixes[0]
    }
    else {
        $netBoxPrefix = $prefixResult.results[0]
    }

    if ($netBoxPrefix.prefix -ne $Prefix) {
        throw (
            "NetBox returned prefix '{0}' instead of exact prefix '{1}'." -f
            $netBoxPrefix.prefix,
            $Prefix
        )
    }

    # -----------------------------------------------------------------
    # 3. Allocate the next available IP in NetBox
    #
    # Posting directly to available-ips avoids a separate GET followed
    # by CREATE sequence and reduces the allocation race window.
    # -----------------------------------------------------------------

    $allocationUri =
        "$NetBoxUrl/api/ipam/prefixes/$($netBoxPrefix.id)/available-ips/"

    $allocationBody = @{
        status      = $NetBoxStatus
        dns_name    = $HostName
        description = $Description
    }

    if (-not $PSCmdlet.ShouldProcess(
        "$Prefix / $HostName",
        'Allocate the next available NetBox IP and create DNS records'
    )) {
        return
    }

    Write-Verbose "Allocating next available IP from '$Prefix'."

    $allocatedNetBoxObject = Invoke-NetBoxRestMethod `
        -Method Post `
        -Uri $allocationUri `
        -Body $allocationBody

    if (-not $allocatedNetBoxObject.id) {
        throw 'NetBox returned no ID for the allocated IP address.'
    }

    if (-not $allocatedNetBoxObject.address) {
        throw 'NetBox returned no address for the allocated IP object.'
    }

    $allocatedAddress =
        ($allocatedNetBoxObject.address -split '/', 2)[0]

    $ipAddress = [System.Net.IPAddress]::Parse($allocatedAddress)

    if ($ipAddress.AddressFamily -ne
        [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw (
            "NetBox allocated '$allocatedAddress', which is not IPv4."
        )
    }

    Write-Verbose (
        "NetBox allocated '{0}' with object ID {1}." -f
        $allocatedAddress,
        $allocatedNetBoxObject.id
    )

    # -----------------------------------------------------------------
    # 4. Ensure the allocated address is not already present in DNS
    #
    # This catches inconsistent DNS data under another owner name.
    # -----------------------------------------------------------------

    $zoneARecordsParameters = @{
        ZoneName    = $DnsZone
        RRType      = 'A'
        ErrorAction = 'Stop'
    }

    if ($DnsCredential) {
        $dnsCimSession = New-CimSession `
            -ComputerName $DnsServer `
            -Credential $DnsCredential

        $zoneARecordsParameters.CimSession = $dnsCimSession
    }
    else {
        $zoneARecordsParameters.ComputerName = $DnsServer
    }

    $conflictingRecord = Get-DnsServerResourceRecord `
        @zoneARecordsParameters |
        Where-Object {
            $_.RecordData.IPv4Address.IPAddressToString -eq
                $allocatedAddress
        } |
        Select-Object -First 1

    if ($conflictingRecord) {
        throw (
            "Allocated IP '$allocatedAddress' is already present in DNS " +
            "as '$($conflictingRecord.HostName).$DnsZone'."
        )
    }

    # -----------------------------------------------------------------
    # 5. Create A and PTR records
    # -----------------------------------------------------------------

    $addDnsParameters = @{
        ZoneName   = $DnsZone
        Name       = $relativeDnsName
        IPv4Address = $ipAddress
        TimeToLive = $dnsTtl
        CreatePtr  = $true
        PassThru   = $true
        ErrorAction = 'Stop'
    }

    if ($AgeRecord) {
        $addDnsParameters.AgeRecord = $true
    }

    if ($dnsCimSession) {
        $addDnsParameters.CimSession = $dnsCimSession
    }
    else {
        $addDnsParameters.ComputerName = $DnsServer
    }

    Write-Verbose (
        "Creating DNS A and PTR records for '{0}' as '{1}'." -f
        $HostName,
        $allocatedAddress
    )

    $createdDnsRecord = Add-DnsServerResourceRecordA @addDnsParameters
    $dnsARecordCreated = $true

    # -----------------------------------------------------------------
    # 6. Verify forward resolution from the selected DNS server
    # -----------------------------------------------------------------

    $resolvedAddress = Resolve-DnsName `
        -Name $HostName `
        -Type A `
        -Server $DnsServer `
        -DnsOnly `
        -ErrorAction Stop |
        Where-Object { $_.Type -eq 'A' } |
        Select-Object -ExpandProperty IPAddress

    if ($allocatedAddress -notin @($resolvedAddress)) {
        throw (
            "Forward DNS verification failed. Expected '$allocatedAddress' " +
            "for '$HostName', received '$($resolvedAddress -join ', ')'."
        )
    }

    # -----------------------------------------------------------------
    # Result
    # -----------------------------------------------------------------

    [pscustomobject]@{
        HostName       = $HostName
        IPAddress      = $allocatedAddress
        Prefix         = $Prefix
        NetBoxPrefixId = $netBoxPrefix.id
        NetBoxIpId     = $allocatedNetBoxObject.id
        NetBoxStatus   = $allocatedNetBoxObject.status.value
        DnsServer      = $DnsServer
        DnsZone        = $DnsZone
        ARecord        = $true
        PtrRequested   = $true
        ForwardVerified = $true
    }
}
catch {
    $originalError = $_

    Write-Error "Registration failed: $($originalError.Exception.Message)"

    # -------------------------------------------------------------
    # Compensating transaction: remove DNS A record if it was added
    # -------------------------------------------------------------

    if ($dnsARecordCreated) {
        try {
            $removeDnsParameters = @{
                ZoneName    = $DnsZone
                Name        = $relativeDnsName
                RRType      = 'A'
                Force       = $true
                ErrorAction = 'Stop'
            }

            if ($dnsCimSession) {
                $removeDnsParameters.CimSession = $dnsCimSession
            }
            else {
                $removeDnsParameters.ComputerName = $DnsServer
            }

            Remove-DnsServerResourceRecord @removeDnsParameters

            Write-Warning (
                "Rollback: removed DNS A record '$HostName'. " +
                'Check whether an automatically created PTR record remains.'
            )
        }
        catch {
            Write-Warning (
                "Rollback could not remove DNS A record '$HostName': " +
                $_.Exception.Message
            )
        }
    }

    # -------------------------------------------------------------
    # Compensating transaction: release NetBox allocation
    # -------------------------------------------------------------

    if ($allocatedNetBoxObject -and $allocatedNetBoxObject.id) {
        try {
            $deleteUri =
                "$NetBoxUrl/api/ipam/ip-addresses/" +
                "$($allocatedNetBoxObject.id)/"

            Invoke-NetBoxRestMethod `
                -Method Delete `
                -Uri $deleteUri

            Write-Warning (
                "Rollback: deleted NetBox IP object ID " +
                "$($allocatedNetBoxObject.id)."
            )
        }
        catch {
            Write-Warning (
                "Rollback could not delete NetBox IP object ID " +
                "$($allocatedNetBoxObject.id): " +
                $_.Exception.Message
            )
        }
    }

    throw $originalError
}
finally {
    if ($dnsCimSession) {
        Remove-CimSession `
            -CimSession $dnsCimSession `
            -ErrorAction SilentlyContinue
    }
}