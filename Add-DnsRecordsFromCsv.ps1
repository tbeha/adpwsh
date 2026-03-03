<#
.SYNOPSIS
  Adds A and PTR records from a CSV to Microsoft DNS (forward + reverse zones).

.DESCRIPTION
  Reads a CSV with Hostname, IPAddress, ZoneName, [ReverseZoneName], [TTL]
  Creates A records in the forward zone and PTR records in the reverse zone.
  Idempotent: checks for existing records before creating.
  Supports -WhatIf / -Confirm.

.PARAMETER CsvPath
  Path to the CSV file.

.PARAMETER DnsServer
  DNS server to target. Defaults to localhost.

.PARAMETER CreatePtrWithA
  If set, uses -CreatePtr on the A record where possible (IPv4) and
  uses -PtrZoneName if ReverseZoneName is provided.

.EXAMPLE
  .\Add-DnsRecordsFromCsv.ps1 -CsvPath .\records.csv -DnsServer dc01.corp.contoso.com -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath = ".\output\dns_dmo.csv",

    [Parameter(Mandatory = $false)]
    [string]$DnsServer = "dmodc1.dmo.ctc.int.hpe.com",

    [switch]$CreatePtrWithA = $false
)

function Test-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Throw "Required module '$Name' is not available. Please install RSAT DNS tools or run on a DNS server."
    }
}

function Get-ReverseZoneNameFromIPv4 {
    param([Parameter(Mandatory = $true)][string]$IPv4)
    # Expecting a.b.c.d -> reverse zone a.b.c => c.b.a.in-addr.arpa (class C default)
    # Many orgs use /24 reverse zones; for different boundaries, provide ReverseZoneName in CSV.
    $ip = $IPv4.Trim()
    [IPAddress]$ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$ipObj)) {
        throw "Invalid IP address: $IPv4"
    }
    if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 is supported by auto-derive in this script. Provide ReverseZoneName or extend for IPv6."
    }
    $octets = $ip.Split('.')
    # Default to /24 reverse zone
    return "{0}.{1}.{2}.in-addr.arpa" -f $octets[2], $octets[1], $octets[0]
}

function Get-PtrRecordNameFromIPv4 {
    param([Parameter(Mandatory = $true)][string]$IPv4)
    $octets = $IPv4.Split('.')
    # last octet is the node under the reverse zone
    return $octets[3]
}

function Test-ARecordExists {
    param(
        [string]$DnsServer,
        [string]$ZoneName,
        [string]$Hostname,
        [string]$IPAddress
    )
    try {
        $existing = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ZoneName -Name $Hostname -RRType A -ErrorAction Stop
        if ($existing) {
            # If any A record at this name matches IP, treat as exists
            foreach ($rec in $existing) {
                if ($rec.RecordData.IPv4Address.IPAddressToString -eq $IPAddress) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        # If not found, Get-DnsServerResourceRecord may throw; treat as not existing
        return $false
    }
}

function Test-PtrRecordExists {
    param(
        [string]$DnsServer,
        [string]$ReverseZoneName,
        [string]$PtrNode,
        [string]$FqdnTarget
    )
    try {
        $existing = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ReverseZoneName -Name $PtrNode -RRType PTR -ErrorAction Stop
        if ($existing) {
            foreach ($rec in $existing) {
                if ($rec.RecordData.PtrDomainName.TrimEnd('.') -eq $FqdnTarget.TrimEnd('.')) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

# Ensure DnsServer module is available
Test-Module -Name 'DnsServer'

Write-Verbose "Reading CSV from: $CsvPath"
$rows = Import-Csv -Path $CsvPath

if (-not $rows -or $rows.Count -eq 0) {
    throw "CSV file appears empty or unreadable: $CsvPath"
}

$results = New-Object System.Collections.Generic.List[PSObject]

foreach ($row in $rows) {
    # Normalize inputs
    $Hostname        = $row.Hostname.Trim()
    $IPAddress       = $row.ip.Trim()
    $ZoneName        = "dmo.ctc.int.hpe.com" #$row.ZoneName.Trim()
    $ReverseZoneName = $row.PSObject.Properties.Match('ReverseZoneName').Count -gt 0 -and $row.ReverseZoneName ? $row.ReverseZoneName.Trim() : $null
    $TTL             = $row.PSObject.Properties.Match('TTL').Count -gt 0 -and $row.TTL ? $row.TTL.Trim() : $null

    if ([string]::IsNullOrWhiteSpace($Hostname) -or
        [string]::IsNullOrWhiteSpace($IPAddress) -or
        [string]::IsNullOrWhiteSpace($ZoneName)) {
        Write-Warning "Skipping row with missing Hostname, IPAddress, or ZoneName: $($row | ConvertTo-Json -Compress)"
        continue
    }

    # Validate IP
    [IPAddress]$ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ipObj)) {
        Write-Warning "Invalid IP, skipping: $IPAddress for $Hostname"
        continue
    }

    $fqdn = if ($Hostname -like "*.$ZoneName") { $Hostname } else { "$Hostname.$ZoneName" }

    # Determine reverse zone + PTR node (IPv4 only here)
    if (-not $ReverseZoneName) {
        if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            try {
                $ReverseZoneName = Get-ReverseZoneNameFromIPv4 -IPv4 $IPAddress
            } catch {
                Write-Warning $_.Exception.Message
                continue
            }
        } else {
            Write-Warning "IPv6 auto-derive not implemented. Provide ReverseZoneName for $IPAddress ($Hostname)."
            continue
        }
    }
    $ptrNode = if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        Get-PtrRecordNameFromIPv4 -IPv4 $IPAddress
    } else {
        Write-Warning "IPv6 PTR node calculation not implemented for $IPAddress ($Hostname)."
        continue
    }

    # Optional TTL handling
    $ttlSpan = $null
    if ($TTL) {
        try {
            $ttlSpan = [System.TimeSpan]::Parse($TTL)
        } catch {
            Write-Warning "Invalid TTL '$TTL' for $Hostname. Use hh:mm:ss (e.g., 01:00:00). Proceeding with DNS default."
            $ttlSpan = $null
        }
    }

    # A record
    $aExists = Test-ARecordExists -DnsServer $DnsServer -ZoneName $ZoneName -Hostname $Hostname -IPAddress $IPAddress
    $aAction = $null

    if (-not $aExists) {
        $params = @{
            ComputerName = $DnsServer
            ZoneName     = $ZoneName
            Name         = $Hostname
            IPv4Address  = $IPAddress
            ErrorAction  = 'Stop'
        }
        if ($ttlSpan) { $params['TimeToLive'] = $ttlSpan }

        if ($CreatePtrWithA -and $ipObj.AddressFamily -eq 'InterNetwork') {
            # Allow DNS to create PTR automatically if the reverse zone exists
            $params['CreatePtr'] = $true
            if ($ReverseZoneName) { $params['PtrZoneName'] = $ReverseZoneName }
        }

        if ($PSCmdlet.ShouldProcess("$fqdn (A $IPAddress) on $DnsServer in zone $ZoneName", "Add A record")) {
            try {
                Add-DnsServerResourceRecordA @params -CreatePtr | Out-Null
                $aAction = 'Created'
            } catch {
                Write-Warning "Failed to create A record for $fqdn -> $IPAddress : $($_.Exception.Message)"
                $aAction = 'Error'
            }
        } else {
            $aAction = 'WhatIf'
        }
    } else {
        $aAction = 'Exists'
    }

    # PTR record (create explicitly when -CreatePtrWithA not used or to ensure idempotency)
    $ptrExists = Test-PtrRecordExists -DnsServer $DnsServer -ReverseZoneName $ReverseZoneName -PtrNode $ptrNode -FqdnTarget $fqdn
    $ptrAction = $null
    if (-not $ptrExists) {
        $ptrParams = @{
            ComputerName = $DnsServer
            ZoneName     = $ReverseZoneName
            Name         = $ptrNode
            PtrDomainName = $fqdn
            ErrorAction  = 'Stop'
        }
        if ($ttlSpan) { $ptrParams['TimeToLive'] = $ttlSpan }

        if ($PSCmdlet.ShouldProcess("$ptrNode.$ReverseZoneName (PTR $fqdn) on $DnsServer", "Add PTR record")) {
            try {
                Add-DnsServerResourceRecordPtr @ptrParams | Out-Null
                $ptrAction = 'Created'
            } catch {
                Write-Warning "Failed to create PTR record $ptrNode.$ReverseZoneName -> $fqdn : $($_.Exception.Message)"
                $ptrAction = 'Error'
            }
        } else {
            $ptrAction = 'WhatIf'
        }
    } else {
        $ptrAction = 'Exists'
    }

    $results.Add([pscustomobject]@{
        Hostname        = $Hostname
        FQDN            = $fqdn
        IPAddress       = $IPAddress
        ZoneName        = $ZoneName
        ReverseZoneName = $ReverseZoneName
        ARecord         = $aAction
        PTRRecord       = $ptrAction
    })
}

# Output summary table
$results | Sort-Object ZoneName, Hostname | Format-Table -AutoSize

# Exit code: non-zero if any Error occurred
if ($results.PTRRecord -contains 'Error' -or $results.ARecord -contains 'Error') {
    exit 1
}