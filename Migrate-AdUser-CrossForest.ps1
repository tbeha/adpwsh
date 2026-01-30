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
    [Parameter(Mandatory=$true)]
    [string]$SourceServer,
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$SourceCredential,

    [Parameter(Mandatory=$true)]
    [string]$TargetServer,
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$TargetCredential,

    [Parameter(Mandatory=$true)]
    [string]$SourceIdentity,

    [Parameter(Mandatory=$true)]
    [string]$TargetOU,

    [string]$TargetUpnSuffix,
    [string]$TargetSamAccountName,

    [switch]$IncludeNestedGroups,

    [string]$GroupMapCsv,
    [switch]$CreateMissingGroups,
    [string]$GroupCreationOU,

    [switch]$IncludePrivilegedGroups,

    [System.Security.SecureString]$InitialPassword
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
        'givenName','sn','displayName','description',
        'mail','userPrincipalName','department','title',
        'telephoneNumber','mobile','ipPhone',
        'physicalDeliveryOfficeName','streetAddress','l','st','postalCode','company',
        'employeeID','employeeNumber'
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
                -Properties MemberOf,PrimaryGroupID,$AttrsToCopy -ErrorAction Stop
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

        # Decide target sAM and UPN
        if ([string]::IsNullOrWhiteSpace($TargetSamAccountName)) {
            $TargetSamAccountName = $srcUser.SamAccountName
        }
        if ([string]::IsNullOrWhiteSpace($TargetUpnSuffix)) {
            $TargetUpnSuffix = Get-DomainDnsRoot -Server $TargetServer -Credential $TargetCredential
        }
        $targetUPN = "$TargetSamAccountName@$TargetUpnSuffix"

        # Check whether target user already exists
        $existingTgt = $null
        try {
            $existingTgt = Get-ADUser -Identity $TargetSamAccountName -Server $TargetServer -Credential $TargetCredential -ErrorAction SilentlyContinue
            if (-not $existingTgt) {
                $existingTgt = Get-ADUser -Filter { UserPrincipalName -eq $targetUPN } -Server $TargetServer -Credential $TargetCredential -ErrorAction SilentlyContinue
            }
        } catch { }

        if ($existingTgt) {
            Write-Warn "Target user already exists: $($existingTgt.DistinguishedName). Will only synchronize group memberships."
        } else {
            # Build attribute map (copy only safe attributes if they exist on source)
            $newUserParams = @{
                Name                  = $srcUser.DisplayName
                SamAccountName        = $TargetSamAccountName
                UserPrincipalName     = $targetUPN
                AccountPassword       = $InitialPassword
                ChangePasswordAtLogon = $true
                Enabled               = $false
                Path                  = $TargetOU
                Server                = $TargetServer
                Credential            = $TargetCredential
            }

            foreach ($a in $AttrsToCopy) {
                $val = $srcUser.$a
                if ($null -ne $val -and $val -ne '') {
                    switch ($a) {
                        'userPrincipalName' { # override with target UPN
                            $newUserParams['UserPrincipalName'] = $targetUPN
                        }
                        default {
                            # map common AD param names when available
                            switch ($a) {
                                'mail'   { $newUserParams['EmailAddress'] = $val }
                                'sn'     { $newUserParams['Surname']      = $val }
                                default  { $newUserParams[$a] = $val }
                            }
                        }
                    }
                }
            }

            if ($PSCmdlet.ShouldProcess("Target user '$TargetSamAccountName'","Create")) {
                try {
                    New-ADUser @newUserParams -ErrorAction Stop
                    Write-Info "Created target user '$TargetSamAccountName'."
                    # Optionally enable now or leave disabled until group replication completes
                    Enable-ADAccount -Identity $TargetSamAccountName -Server $TargetServer -Credential $TargetCredential -ErrorAction Stop
                    Write-Info "Enabled target user '$TargetSamAccountName'."
                } catch {
                    Write-Err "Failed to create/enable target user: $($_.Exception.Message)"
                    return
                }
            }
        }

        # Ensure we have a fresh target reference (created or pre-existing)
        $tgtUser = Get-ADUser -Identity $TargetSamAccountName -Server $TargetServer -Credential $TargetCredential -ErrorAction Stop

        # Collect source groups
        Write-Info "Collecting source group memberships (Nested: $IncludeNestedGroups) ..."
        $primaryGroupDN = Get-PrimaryGroupDN -user $srcUser
        $srcGroups = Get-SourceGroups -user $srcUser -Nested:$IncludeNestedGroups

        # Filter out primary group and privileged groups (unless allowed)
        $groupsToProcess = @()
        foreach ($g in $srcGroups) {
            if (-not $g) { continue }
            if ($primaryGroupDN -and ($g.DistinguishedName -eq $primaryGroupDN)) { continue }

            if (-not $IncludePrivilegedGroups) {
                if ($PrivilegedGroupNames -contains $g.Name) {
                    Write-Warn "Skipping privileged/built-in group '$($g.Name)'. Use -IncludePrivilegedGroups to include."
                    continue
                }
            }
            $groupsToProcess += $g
        }

        if (-not $groupsToProcess -or $groupsToProcess.Count -eq 0) {
            Write-Info "No eligible groups to migrate."
        } else {
            Write-Info "Preparing to migrate $($groupsToProcess.Count) groups..."
        }

        $added    = New-Object System.Collections.Generic.List[string]
        $missing  = New-Object System.Collections.Generic.List[string]
        $skipped  = New-Object System.Collections.Generic.List[string]
        $exists   = New-Object System.Collections.Generic.List[string]

        foreach ($sg in $groupsToProcess) {
            $targetName = Map-GroupName -srcGroup $sg
            $tg = Get-OrCreate-TargetGroup -groupName $targetName

            if (-not $tg) {
                Write-Warn "Target group missing: '$targetName' (mapped from '$($sg.Name)')"
                $missing.Add($targetName) | Out-Null
                continue
            }

            # Check if already member
            $isMember = $false
            try {
                $isMember = (Get-ADGroupMember -Identity $tg.DistinguishedName -Server $TargetServer -Credential $TargetCredential -Recursive -ErrorAction Stop |
                             Where-Object { $_.objectClass -eq 'user' -and $_.SamAccountName -eq $tgtUser.SamAccountName } |
                             Select-Object -First 1) -ne $null
            } catch { $isMember = $false }

            if ($isMember) {
                $exists.Add($tg.Name) | Out-Null
                continue
            }

            if ($PSCmdlet.ShouldProcess("Group '$($tg.Name)'","Add member '$($tgtUser.SamAccountName)'")) {
                try {
                    Add-ADGroupMember -Identity $tg.DistinguishedName -Members $tgtUser.DistinguishedName `
                        -Server $TargetServer -Credential $TargetCredential -ErrorAction Stop
                    $added.Add($tg.Name) | Out-Null
                    Write-Info "Added to target group: $($tg.Name)"
                } catch {
                    Write-Err "Failed to add '$($tgtUser.SamAccountName)' to '$($tg.Name)': $($_.Exception.Message)"
                    $skipped.Add($tg.Name) | Out-Null
                }
            }
        }

        # Summary
        Write-Host ""
        Write-Host "===== MIGRATION SUMMARY =====" -ForegroundColor Green
        Write-Host ("Source User:  {0}  (sAM: {1})" -f $srcUser.Name, $srcUser.SamAccountName)
        Write-Host ("Target User:  {0}  (sAM: {1})" -f $tgtUser.Name, $tgtUser.SamAccountName)
        if ($added.Count)   { Write-Host ("Added to groups:        " + ($added   -join ', ')) }
        if ($exists.Count)  { Write-Host ("Already member of:      " + ($exists  -join ', ')) }
        if ($missing.Count) { Write-Host ("Missing target groups:  " + ($missing -join ', ')) }
        if ($skipped.Count) { Write-Host ("Failed/Skipped groups:  " + ($skipped -join ', ')) }
        Write-Host "=============================" -ForegroundColor Green

        Write-Info "Done."
    }
    catch {
        Write-Err "Unhandled error: $($_.Exception.Message)"
        throw
    }
}