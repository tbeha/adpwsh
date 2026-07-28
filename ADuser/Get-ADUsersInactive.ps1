<#
.SYNOPSIS
Lists AD users who have not logged on for a specified number of months (default 6), optionally targeting a remote domain/controller.

.PARAMETER Months
Number of months of inactivity to check for. Default is 6.

.PARAMETER IncludeDisabled
If specified, include disabled accounts in the results.

.PARAMETER ExportPath
Optional path to export results as CSV.

.PARAMETER Server
Optional remote domain controller or domain to target (passed to AD cmdlets' `-Server`).

.PARAMETER Credential
Optional PSCredential to authenticate against the remote `-Server`.

.PARAMETER Filter
LDAP filter for `Get-ADUser`. Defaults to `*` (all users).

.EXAMPLE
# Show users inactive for 6 months (default)
.\Get-ADUsersInactive.ps1

# Export users inactive for 12 months
.\Get-ADUsersInactive.ps1 -Months 12 -ExportPath C:\temp\inactive-users.csv

# Include disabled accounts too
.\Get-ADUsersInactive.ps1 -Months 6 -IncludeDisabled
#>

[CmdletBinding()]
param(
    [int]$Months=6,
    [switch]$IncludeDisabled=$true,
    [string]$ExportPath="c:\temp\inactive-users.csv",
    [string]$Server="suo04ctcw005.demo.local",
    [System.Management.Automation.PSCredential]
    $Credential,
    [string]
    $Filter = '*'
)

function Ensure-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module not found. Install RSAT or the ActiveDirectory module and run again."
        exit 1
    }
}

Ensure-ADModule


$threshold = (Get-Date).AddMonths(-$Months)

$getUserParams = @{ Filter = $Filter; Properties = @('LastLogonDate','Enabled','DistinguishedName','Name','SamAccountName') }
if ($Server) { $getUserParams.Server = $Server }
if ($Credential) { $getUserParams.Credential = $Credential }

$users = Get-ADUser @getUserParams

$filtered = $users | Where-Object {
    $isEnabled = $_.Enabled -eq $true
    if (-not $IncludeDisabled -and -not $isEnabled) { return $false }

    # If LastLogonDate is null (never logged on), treat as inactive
    if (-not $_.LastLogonDate) { return $true }

    return ($_.LastLogonDate -lt $threshold)
}

$results = $filtered | Select-Object SamAccountName,Name,Enabled,DistinguishedName,@{Name='LastLogon';Expression={ if ($_.LastLogonDate){$_.LastLogonDate.ToString('u')} else {'Never'} }} | Sort-Object @{Expression={ if ($_.LastLogon -eq 'Never' ){ [datetime]::MinValue } else {[datetime]::Parse($_.LastLogon)} };Descending=$false}, SamAccountName

if ($ExportPath) {
    try {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Output "Exported $($results.Count) accounts to $ExportPath"
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
} else {
    $results | Format-Table -AutoSize
}
