<#
.SYNOPSIS
    Bulk Migration of AD user from a source domain to a target domain and re-applies group memberships if possible.

.DESCRIPTION
    - Reads the list of users out of a CSV file (e.g. "users.csv")
    - Source user are identified by sAMAccountName, UPN, or DN from Source AD (specific DC + credentials).
    - Creates the user in the Target AD (specific DC + credentials) with selected attributes.
    - Resolves source group memberships (direct by default; nested optional) and maps them to target groups.
      * Checks if the group exists on the target before adding the user.
      * Optional group name mapping CSV (SourceGroup -> TargetGroup).
      * Optional auto-create of missing target groups.
    - Excludes privileged/built-in groups by default (Domain Admins, etc.) unless -IncludePrivilegedGroups is provided.
    - Supports -WhatIf/-Confirm and produces a clear summary.

.PARAMETER SourceServer
    FQDN/NetBIOS of source DC (e.g., "dc01.src.contoso.com").

.PARAMETER SourceCredential
    PSCredential for source domain (e.g., Get-Credential 'SRC\adadmin').

.PARAMETER TargetServer
    FQDN/NetBIOS of target DC (e.g., "dc01.tgt.contoso.com").

.PARAMETER TargetCredential
    PSCredential for target domain (e.g., Get-Credential 'TGT\adadmin').

.PARAMETER CSVpath
    Path to CSV file with list of users to migrate. Must contain a column "SourceIdentity".

.PARAMETER TargetOU
    DN of OU in target domain to create user, e.g., "OU=Employees,DC=tgt,DC=contoso,DC=com".

.PARAMETER TargetUpnSuffix
    Optional UPN suffix to use in target (e.g., "tgt.contoso.com"). Defaults to target domain DNS root.

.PARAMETER TargetSamAccountName
    Optional target sAMAccountName. Defaults to source sAMAccountName.

.PARAMETER IncludeNestedGroups
    If set, uses nested memberships from Get-ADPrincipalGroupMembership instead of direct MemberOf DNs.

.PARAMETER GroupMapCsv
    Optional CSV path with columns: SourceGroup,TargetGroup — for renaming/mapping groups between domains.

.PARAMETER CreateMissingGroups
    If set, will create missing target groups as Global Security groups in the target OU of the group’s container or under a specified GroupCreationOU.

.PARAMETER GroupCreationOU
    Optional DN of OU in target where new groups will be created when -CreateMissingGroups is used.

.PARAMETER IncludePrivilegedGroups
    If set, does not exclude privileged/built-in groups during membership replication (use carefully).

.PARAMETER InitialPassword
    SecureString for the new user’s initial password. If omitted, you’ll be prompted.

.EXAMPLE
    $srcCred = Get-Credential 'SRC\adadmin'
    $tgtCred = Get-Credential 'TGT\adadmin'

    .\Migrate-AdUser-CrossForest.ps1 `
      -SourceServer 'dc01.src.contoso.com' -SourceCredential $srcCred `
      -TargetServer 'dc01.tgt.contoso.com' -TargetCredential $tgtCred `
      -SourceIdentity 'jdoe' `
      -TargetOU 'OU=Employees,DC=tgt,DC=contoso,DC=com' `
      -TargetUpnSuffix 'tgt.contoso.com' `
      -IncludeNestedGroups `
      -GroupMapCsv '.\groupMap.csv' `
      -WhatIf

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$SourceServer="suo04ctcw005.demo.local",
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$SourceCredential,

    [string]$TargetServer="dmodc1.dmo.ctc.int.hpe.com",g
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$TargetCredential,

    #[Parameter(Mandatory=$true)]
    [string]$CSVpath='.\output\test-users.csv',

    [string]$TargetOU="OU=Users,OU=Democenter,DC=dmo,DC=ctc,DC=int,DC=hpe,DC=com",

    [string]$TargetUpnSuffix="dmo.ctc.int.hpe.com",
    [string]$TargetSamAccountName,

    [switch]$IncludeNestedGroups,

    [string]$GroupMapCsv=".\groupMap.csv",
    [switch]$CreateMissingGroups=$false,
    [string]$GroupCreationOU,

    [switch]$IncludePrivilegedGroups,

    [System.Security.SecureString]$InitialPassword=(ConvertTo-SecureString "HPE.ctc.2026!bbn" -AsPlainText -Force)
)

process{
    Import-Csv $CSVpath | ForEach-Object {
        $user = $_.SamAccountName
        Write-Host "Migrating user: $user"
        .\Migrate-AdUser-CrossForest.ps1 `
            -SourceIdentity $user `
    }
}