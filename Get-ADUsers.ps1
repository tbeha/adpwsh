<#
#.SYNOPSIS
Gets last logon time for Active Directory users, optionally from a remote domain/controller.

.PARAMETER Accurate
If specified, queries all domain controllers and returns the most recent `lastLogon` value (accurate but slower).

.PARAMETER ExportPath
Optional path to export results as CSV.

.PARAMETER Server
Optional remote domain controller or domain to target (passed to AD cmdlets' `-Server`).

.PARAMETER Credential
Optional PSCredential to authenticate against the remote `-Server`.

.PARAMETER Filter
LDAP filter for `Get-ADUser`. Defaults to `*` (all users).

.EXAMPLE
Get-ADUsersLastLogon.ps1 -Server dc01.corp.contoso.com -Credential (Get-Credential) -ExportPath C:\temp\ad-lastlogon.csv

Get-ADUsersLastLogon.ps1 -Accurate -Server corp.contoso.com -ExportPath C:\temp\ad-lastlogon-accurate.csv
#>

[CmdletBinding()]
param(
    [switch]$Accurate,
    [string]$ExportPath="c:\temp\ad-user.csv",
    [string]$Server="suo04ctcw005.demo.local",
    [System.Management.Automation.PSCredential]
    $Credential = $Cred,
    [string]
    $Filter = '*'
)

function Ensure-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module not found. Install RSAT or the ActiveDirectory module and run again."
        exit 1
    }
}

function Convert-FileTimeToDateTime {
    param([object]$fileTime)
    if (-not $fileTime) { return $null }
    try {
        $val = [Int64]$fileTime
        if ($val -eq 0) { return $null }
        return [DateTime]::FromFileTimeUtc($val)
    } catch {
        return $null
    }
}

Ensure-ADModule

if ($Accurate) {
    try {
        if ($Server) {
            $dcs = Get-ADDomainController -Filter * -Server $Server | Select-Object -ExpandProperty HostName
        } else {
            $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        }
    } catch {
        Write-Error "Failed to enumerate domain controllers: $_"
        exit 1
    }
    if (-not $dcs) {
        Write-Error "No domain controllers found."
        exit 1
    }
}

#$getUserParams = @{ Filter = $Filter; Properties = @('SamAccountName','Name','DistinguishedName','LastLogonDate') }
$getUserParams = @{ Filter = $Filter}
if ($Server) { $getUserParams.Server = $Server }
if ($Credential) { $getUserParams.Credential = $Credential }

$users = Get-ADUser @getUserParams

$results = foreach ($u in $users) {
    if ($Accurate) {
        $best = $null
        foreach ($dc in $dcs) {
            try {
                $params = @{ Identity = $u.DistinguishedName; Properties = 'lastLogon'; Server = $dc; ErrorAction = 'Stop' }
                if ($Credential) { $params.Credential = $Credential }
                $uDC = Get-ADUser @params
                $dt = Convert-FileTimeToDateTime $uDC.lastLogon
                if ($dt -and ($best -eq $null -or $dt -gt $best)) { $best = $dt }
            } catch {
                continue
            }
        }
        $last = $best
    } else {
        $last = $u.LastLogonDate
    }

    [PSCustomObject]@{
        SamAccountName    = $u.SamAccountName
        Name              = $u.Name
        DistinguishedName = $u.DistinguishedName
        LastLogon         = $last
    }
}

$ordered = $results | Sort-Object @{Expression={$_.LastLogon};Descending=$true}, SamAccountName

if ($ExportPath) {
    try {
        $ordered | Select-Object SamAccountName,Name,DistinguishedName,@{Name='LastLogon';Expression={if ($_.LastLogon){$_.LastLogon.ToString('u')}else{'Never'}}} | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Output "Exported results to $ExportPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
} else {
    $ordered | Select-Object SamAccountName,Name,DistinguishedName,@{Name='LastLogon';Expression={if ($_.LastLogon){$_.LastLogon.ToString('u')}else{'Never'}}} | Format-Table -AutoSize
}
