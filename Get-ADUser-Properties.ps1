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
#$getUserParams = @{ Filter = $Filter}
if ($Server) { $getUserParams.Server = $Server }
if ($Credential) { $getUserParams.Credential = $Credential }

$properties = Get-ADUser -Identity abehat -Server $Server -Credential $Credential -Properties * |
Get-Member -MemberType Properties |
Select-Object -ExpandProperty Name |
Sort-Object
$properties | Format-List 