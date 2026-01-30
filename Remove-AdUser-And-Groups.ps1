<#
.SYNOPSIS
    Removes an AD user from all AD groups and optionally deletes or quarantines the account.

.DESCRIPTION
    - Locates a user by sAMAccountName, UPN, or distinguishedName.
    - Enumerates all group memberships and removes the user from each non-primary group.
    - Can:
        * Disable the account (-DisableOnly),
        * Move to a quarantine OU (-QuarantineOU),
        * Or fully delete the account (-Delete).
    - Handles ProtectedFromAccidentalDeletion (clears it if needed).
    - Supports -WhatIf / -Confirm and robust error handling.

.PARAMETER Identity
    User identifier: sAMAccountName (e.g., jdoe), UPN (e.g., jdoe@contoso.com), or DN.

.PARAMETER QuarantineOU
    DN of an OU to move the user to instead of deletion, e.g. "OU=Leavers,DC=contoso,DC=com".

.PARAMETER Delete
    Switch to fully delete the user object after removing group memberships.

.PARAMETER DisableOnly
    Switch to only disable the account (no move or delete). Mutually exclusive with -Delete and -QuarantineOU.

.PARAMETER ExcludeGroups
    One or more group names (sAMAccountName or CN) to never remove (e.g., license or baseline groups).
    Primary group is always excluded regardless.

.PARAMETER SkipLargeGroupEnumeration
    If set, will NOT enumerate nested memberships for very large groups and will remove only direct memberships (faster/safer in big environments).

.EXAMPLE
    .\Remove-AdUser-And-Groups.ps1 -Identity "jdoe" -Delete

.EXAMPLE
    .\Remove-AdUser-And-Groups.ps1 -Identity "asmith@contoso.com" -QuarantineOU "OU=Leavers,DC=contoso,DC=com"

.EXAMPLE
    .\Remove-AdUser-And-Groups.ps1 -Identity "tbeha" -DisableOnly

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(Mandatory=$false)]
    [string]$QuarantineOU,

    [switch]$Delete,

    [switch]$DisableOnly,

    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeGroups,

    [switch]$SkipLargeGroupEnumeration
)

begin {
    function Write-Info($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
    function Write-Warn($msg)  { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
    function Write-Err($msg)   { Write-Host "[ERROR] $msg" -ForegroundColor Red }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT or run on a domain-joined admin host."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    if ($Delete -and $DisableOnly) {
        throw "Parameters -Delete and -DisableOnly are mutually exclusive."
    }
    if ($Delete -and $QuarantineOU) {
        throw "Parameters -Delete and -QuarantineOU are mutually exclusive."
    }
}

process {
    try {
        # Resolve user object
        $user = $null
        try {
            # Try direct identity first
            $user = Get-ADUser -Identity $Identity -Properties MemberOf,PrimaryGroupID,ProtectedFromAccidentalDeletion -ErrorAction Stop
        } catch {
            # Try sAMAccountName or UPN filter
            $user = Get-ADUser -Filter { (SamAccountName -eq $Identity) -or (UserPrincipalName -eq $Identity) } -Properties MemberOf,PrimaryGroupID,ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue
        }

        if (-not $user) {
            Write-Err "User '$Identity' not found."
            return
        }

        Write-Info "Resolved user: $($user.Name) (sAM:$($user.SamAccountName)) DN: $($user.DistinguishedName)"

        # Determine primary group DN to avoid removing it
        $domain = Get-ADDomain -ErrorAction Stop
        $primaryGroupRID = $user.PrimaryGroupID
        $primaryGroupSID = ($user.SID.Value -replace '-\d+$','') + "-$primaryGroupRID"
        $primaryGroup = Get-ADGroup -Filter { objectSID -eq $primaryGroupSID } -ErrorAction SilentlyContinue

        $primaryGroupDN = $primaryGroup?.DistinguishedName
        if ($primaryGroupDN) {
            Write-Info "Primary group: $($primaryGroup.Name) (will not remove)."
        } else {
            Write-Warn "Could not resolve primary group from PrimaryGroupID=$primaryGroupRID. Will skip removal by DN check."
        }

        # Build exclusion set
        $excludeSet = @{}
        if ($ExcludeGroups) {
            foreach ($g in $ExcludeGroups) { if ($g) { $excludeSet[$g.ToLower()] = $true } }
        }
        if ($primaryGroupDN) { $excludeSet[$primaryGroupDN.ToLower()] = $true }

        # Gather groups
        Write-Info "Collecting group memberships..."
        $groups = @()

        # Direct memberships from MemberOf
        $directGroupDNs = @()
        if ($user.MemberOf) {
            $directGroupDNs = @($user.MemberOf)
        }

        if ($SkipLargeGroupEnumeration) {
            # Only use direct groups
            foreach ($gdn in $directGroupDNs) {
                try {
                    $grp = Get-ADGroup -Identity $gdn -ErrorAction Stop
                    $groups += $grp
                } catch {
                    Write-Warn "Failed to resolve group '$gdn' (direct). $_"
                }
            }
        } else {
            # Use Get-ADPrincipalGroupMembership (includes nested)
            try {
                $groups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -ErrorAction Stop
            } catch {
                Write-Warn "Falling back to direct memberships due to error enumerating nested groups: $($_.Exception.Message)"
                foreach ($gdn in $directGroupDNs) {
                    try {
                        $grp = Get-ADGroup -Identity $gdn -ErrorAction Stop
                        $groups += $grp
                    } catch {
                        Write-Warn "Failed to resolve group '$gdn' (direct). $_"
                    }
                }
            }
        }

        if (-not $groups -or $groups.Count -eq 0) {
            Write-Info "User is not a member of any (enumerated) groups."
        } else {
            Write-Info "Found $($groups.Count) groups."
        }

        # Remove from groups (excluding primary + ExcludeGroups)
        $removed = @()
        $skipped = @()

        foreach ($grp in $groups) {
            if (-not $grp) { continue }

            $skip = $false
            if ($primaryGroupDN -and ($grp.DistinguishedName -eq $primaryGroupDN)) { $skip = $true }
            if (-not $skip) {
                # Name- or CN-based exclusion
                if ($excludeSet.ContainsKey($grp.Name.ToLower()) -or $excludeSet.ContainsKey($grp.SamAccountName.ToLower())) { $skip = $true }
                if ($excludeSet.ContainsKey($grp.DistinguishedName.ToLower())) { $skip = $true }
            }

            if ($skip) {
                $skipped += $grp.Name
                continue
            }

            $actionTarget = "Remove '$($user.SamAccountName)' from group '$($grp.Name)'"
            if ($PSCmdlet.ShouldProcess($grp.Name, "Remove member $($user.SamAccountName)")) {
                try {
                    Remove-ADGroupMember -Identity $grp.DistinguishedName -Members $user.DistinguishedName -Confirm:$false -ErrorAction Stop
                    Write-Info "Removed from group: $($grp.Name)"
                    $removed += $grp.Name
                } catch {
                    Write-Err "Failed to remove from group '$($grp.Name)': $($_.Exception.Message)"
                }
            }
        }

        # Disable / Move to quarantine / Delete
        if ($DisableOnly) {
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Disable account")) {
                try {
                    Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
                    Write-Info "Account disabled."
                } catch {
                    Write-Err "Failed to disable account: $($_.Exception.Message)"
                }
            }
        }
        elseif ($QuarantineOU) {
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Move to quarantine OU")) {
                try {
                    # Ensure accidental deletion protection is cleared so move succeeds
                    try {
                        Set-ADObject -Identity $user.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                    } catch {
                        Write-Warn "Could not clear ProtectedFromAccidentalDeletion before move: $($_.Exception.Message)"
                    }

                    Move-ADObject -Identity $user.DistinguishedName -TargetPath $QuarantineOU -ErrorAction Stop
                    Write-Info "Moved user to: $QuarantineOU"
                    try {
                        Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction SilentlyContinue
                    } catch { }
                } catch {
                    Write-Err "Failed to move user to quarantine OU: $($_.Exception.Message)"
                }
            }
        }
        elseif ($Delete) {
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Delete user object")) {
                try {
                    # Clear accidental deletion protection if set
                    if ($user.ProtectedFromAccidentalDeletion) {
                        try {
                            Set-ADObject -Identity $user.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                            Write-Info "Cleared ProtectedFromAccidentalDeletion."
                        } catch {
                            Write-Warn "Could not clear ProtectedFromAccidentalDeletion: $($_.Exception.Message)"
                        }
                    }
                    Remove-ADUser -Identity $user.DistinguishedName -Confirm:$false -ErrorAction Stop
                    Write-Info "User deleted."
                } catch {
                    Write-Err "Failed to delete user: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Info "No terminal action specified. Use -DisableOnly, -QuarantineOU, or -Delete."
        }

        # Summary
        Write-Host ""
        Write-Host "===== SUMMARY =====" -ForegroundColor Green
        Write-Host "User: $($user.SamAccountName)"
        Write-Host "Removed from groups: " + (($removed | Sort-Object) -join ', ')
        if ($skipped.Count -gt 0) {
            Write-Host "Skipped groups: " + (($skipped | Sort-Object) -join ', ')
        }
        Write-Host "===================" -ForegroundColor Green
    }
    catch {
        Write-Err "Unhandled error: $($_.Exception.Message)"
        throw
    }
}