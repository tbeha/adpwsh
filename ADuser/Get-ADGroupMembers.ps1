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
    [string]$ExportPath="../ADGroupMembers.csv",
    [string]$Server="dmodc1.dmo.ctc.int.hpe.com",
    [System.Management.Automation.PSCredential]
    $Credential=$Cred,
    [string]$Identity = 'DemoAdmins',
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxTokenPath = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
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
    Ensure-ADModule
    #$Credential = Get-Credential -ErrorAction Stop -ErrorVariable credError

    #$getUserParams = @{ Filter = $Filter; Properties = @('SamAccountName','Name','DistinguishedName','LastLogonDate') }
    $getUserParams = @{ Identity = $Identity }
    if ($Server) { $getUserParams.Server = $Server }
    if ($Credential) { $getUserParams.Credential = $Credential }

    $groupmembers = Get-ADGroupMember @getUserParams

    # open the connection to the Netbox
    Get-NetboxSession
    $Password = ConvertTo-SecureString "HPE.ctc.2026!bbn" -AsPlainText -Force

    foreach ($m in $groupmembers) {

        $getUserParams.Identity = $m.SamAccountName
        $user = Get-ADUser @getUserParams
        
        $NewUser = New-NBUser -username $user.SamAccountName -First_Name $user.GivenName -Last_Name $user.Surname -Password $Password -Is_Active $true -Is_Superuser $false -Group 2
        Write-Output "Created user $($NewUser.Username) in Netbox."
    }

}
catch {
    Write-Error "An error occurred: $_"
}