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
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxTokenPath = '..\DNS\netbox.token',
    [securestring]$Password 
)


# Use PowerNetBox module (recommended)
# Instead of raw API:  https://github.com/ctrl-alt-automate/PowerNetbox

Import-Module PowerNetbox

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

function Get-NetboxSession{

    $secureToken = Get-Content $netboxTokenPath -Raw | ConvertTo-SecureString -AsPlainText -Force
    $nbcred = [pscredential]::new('ctcadmin', $securetoken)
    Connect-NBApi -Uri $netboxBaseUrl -Credential $nbcred -SkipCertificateCheck

}


try{
    # open the connection to the Netbox
    Get-NetboxSession
    $Password = ConvertTo-SecureString "HPE.ctc.2026!bbn" -AsPlainText -Force

    $results = Get-NBuser -ALL

    Write-Output "Retrieved $($results.Count) users from Netbox."
    Write-Output "Usernames:"
    $results | ForEach-Object { Write-Output $_.Username }    
}
catch {
    Write-Error "An error occurred: $_"
}