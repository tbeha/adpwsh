<#
.SYNOPSIS
    Migrates an AD user from a source domain to a target domain and re-applies group memberships.

.DESCRIPTION
    - Reads a source user by sAMAccountName, UPN, or DN from Source AD (specific DC + credentials).
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

.PARAMETER SourceIdentity
    Source user identifier (sAMAccountName, UPN, or DN).

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
    [System.Management.Automation.PSCredential]$SourceCredential=$Cred0,

    [string]$TargetServer="dmocd1.dmo.ctc.int.hpe.com",
    [System.Management.Automation.PSCredential]$TargetCredential=$Cred1,

    [string]$SourceIdentity="abehat",

    [string]$TargetOU="OU=Users,OU=Democenter,DC=dmo,DC=ctc,DC=int,DC=hpe,DC=com",

    [string]$TargetUpnSuffix="dmo.ctc.int.hpe.com",
    [string]$TargetSamAccountName,

    [switch]$IncludeNestedGroups,

    [string]$GroupMapCsv=".\groupMap.csv",
    [switch]$CreateMissingGroups=$false,
    [string]$GroupCreationOU,

    [switch]$IncludePrivilegedGroups,

    [System.Security.SecureString]$InitialPassword=(ConvertTo-SecureString "CTC12345!" -AsPlainText -Force)
)

begin {
    function Write-Info($msg){ Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
    function Write-Warn($msg){ Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
    function Write-Err($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT on a domain-joined admin host."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    # Default attribute set to copy (safe business/profile attributes only)
    $script:AttrsToCopy = @(
        'EmailAddress','Description'
    )

    # For safety, exclude privileged/built-in groups unless explicitly allowed
    $script:PrivilegedGroupNames = @(
        'Administrators','Domain Admins','Enterprise Admins','Schema Admins',
        'Account Operators','Server Operators','Backup Operators','Print Operators',
        'Domain Controllers','Read-only Domain Controllers','Enterprise Key Admins','Key Admins',
        'DnsAdmins','Cert Publishers','Group Policy Creator Owners'
    )

    # Load optional mapping CSV
    $script:GroupMap = @{}
    if ($GroupMapCsv) {
        if (-not (Test-Path $GroupMapCsv)) { throw "GroupMapCsv not found: $GroupMapCsv" }
        Import-Csv -Path $GroupMapCsv | ForEach-Object {
            if ($_.SourceGroup -and $_.TargetGroup) {
                $script:GroupMap[$_.SourceGroup.ToLower()] = $_.TargetGroup
            }
        }
        Write-Info "Loaded group mapping entries: $($script:GroupMap.Count)"
    }

    # Prompt for password if not provided
    if (-not $InitialPassword) {
        $InitialPassword = Read-Host -Prompt "Enter initial password for target user" -AsSecureString
    }

    # Helper to fetch domain DNS root (for default target UPN suffix)
    function Get-DomainDnsRoot([string]$Server, [pscredential]$Credential) {
        (Get-ADDomain -Server $Server -Credential $Credential -ErrorAction Stop).DNSRoot
    }

    # Escape for LDAP filter
    function Escape-Ldap([string]$value) {
        if ($null -eq $value) { return $null }
        $value -replace '([\\\*\(\)\0])', {'\' + ('{0:X2}' -f [int][char]$args[0].Groups[1].Value)}
    }

    # Get a user from source by Identity or filter
    function Get-SourceUser([string]$identity) {
        try {
            return Get-ADUser -Identity $identity -Server $SourceServer -Credential $SourceCredential `
                -Properties MemberOf,PrimaryGroupID,EmailAddress,Description,Name,SID -ErrorAction Stop
        } catch {
            $usr = Get-ADUser -Filter { (SamAccountName -eq $identity) -or (UserPrincipalName -eq $identity) } `
                -Server $SourceServer -Credential $SourceCredential `
                -Properties MemberOf,PrimaryGroupID,$AttrsToCopy -ErrorAction SilentlyContinue
            return $usr
        }
    }

    # Resolve groups for a user on source domain
    function Get-SourceGroups([Microsoft.ActiveDirectory.Management.ADUser]$user, [switch]$Nested) {
        if ($Nested) {
            try {
                return Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName `
                    -Server $SourceServer -Credential $SourceCredential -ErrorAction Stop
            } catch {
                Write-Warn "Nested group enumeration failed, falling back to direct groups."
            }
        }

        $groups = @()
        if ($user.MemberOf) {
            foreach ($gdn in $user.MemberOf) {
                try {
                    $grp = Get-ADGroup -Identity $gdn -Server $SourceServer -Credential $SourceCredential -ErrorAction Stop
                    $groups += $grp
                } catch {
                    Write-Warn "Could not resolve group DN '$gdn' on source."
                }
            }
        }
        return $groups
    }

    # Determine primary group DN (so we don't attempt to remove or add it)
    function Get-PrimaryGroupDN($user) {
        try {
            $rid = $user.PrimaryGroupID
            $primarySid = ($user.SID.Value -replace '-\d+$','') + "-$rid"
            $pg = Get-ADGroup -Filter { objectSID -eq $primarySid } -Server $SourceServer -Credential $SourceCredential -ErrorAction SilentlyContinue
            return $pg?.DistinguishedName
        } catch { return $null }
    }

    # Given a source group, figure target group name/identity
    function Map-GroupName($srcGroup) {
        # Use mapping CSV first (name-based)
        $key = $srcGroup.Name.ToLower()
        if ($GroupMap.ContainsKey($key)) { return $GroupMap[$key] }
        # Default: same name
        return $srcGroup.Name
    }

    # Resolve or optionally create a target group by name
    function Get-OrCreate-TargetGroup([string]$groupName) {
        $tg = $null
        try {
            # Try identity by name (sAM/CN) via LDAP
            $safe = Escape-Ldap $groupName
            $ldap = "(|(sAMAccountName=$safe)(cn=$safe))"
            $found = Get-ADGroup -LDAPFilter $ldap -Server $TargetServer -Credential $TargetCredential -ErrorAction SilentlyContinue
            if ($found -is [System.Array]) { $tg = $found | Select-Object -First 1 } else { $tg = $found }
        } catch { $tg = $null }

        if (-not $tg -and $CreateMissingGroups) {
            $createParams = @{
                Name        = $groupName
                SamAccountName = $groupName
                GroupScope  = 'Global'
                GroupCategory = 'Security'
                Server      = $TargetServer
                Credential  = $TargetCredential
            }
            if ($GroupCreationOU) { $createParams['Path'] = $GroupCreationOU }
            if ($PSCmdlet.ShouldProcess("Target group '$groupName'","Create")) {
                try {
                    New-ADGroup @createParams -ErrorAction Stop
                    $tg = Get-ADGroup -Identity $groupName -Server $TargetServer -Credential $TargetCredential -ErrorAction Stop
                    Write-Info "Created target group '$groupName'."
                } catch {
                    Write-Err "Failed to create target group '$groupName': $($_.Exception.Message)"
                }
            }
        }

        return $tg
    }
}

process {
    try {
        Write-Info "Resolving source user '$SourceIdentity' on $SourceServer ..."
        $srcUser = Get-SourceUser -identity $SourceIdentity
        if (-not $srcUser) { throw "Source user '$SourceIdentity' not found." }
        Write-Info "Found source user: $($srcUser.Name) (sAM: $($srcUser.SamAccountName))"
        $srcUser | Format-List *
    } catch {
        Write-Err $_.Exception.Message
        return
    }   
}