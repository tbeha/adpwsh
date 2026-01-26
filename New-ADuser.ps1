
<#
.SYNOPSIS
    Creates an AD user and adds them to specified groups (verifying groups exist first),
    connecting to a specified Domain Controller using a supplied credential.

.DESCRIPTION
    - Creates a new AD user with common attributes in a chosen OU.
    - Checks that each group exists before attempting to add.
    - Adds only to valid groups; logs missing/failed groups.
    - Supports -WhatIf / -Confirm.
    - All AD operations are executed against a specific DC (-Server) with given -Credential.

.PARAMETER Server
    The Domain Controller to target, e.g. "dc01.contoso.com".

.PARAMETER Credential
    A domain admin credential (PSCredential), e.g. (Get-Credential contoso\adadmin).

.PARAMETER SamAccountName
    The user's sAMAccountName (logon name).

.PARAMETER GivenName
    First name.

.PARAMETER Surname
    Last name.

.PARAMETER DisplayName
    Optional. Defaults to "GivenName Surname".

.PARAMETER UserPrincipalName
    Optional. Defaults to "SamAccountName@<forest UPN suffix or domain DNS root>".

.PARAMETER OU
    Distinguished Name (DN) of the OU to create the user in, e.g. "OU=Employees,DC=contoso,DC=com".
    If omitted, the user is created in the default Users container.

.PARAMETER InitialPassword
    Initial password (SecureString). If omitted, you will be prompted.

.PARAMETER Email
    User's mail (EmailAddress) attribute.

.PARAMETER Department
    Department attribute.

.PARAMETER Title
    Title attribute.

.PARAMETER Groups
    One or more AD group identifiers (sAMAccountName, DN, SID, or GUID). Each is checked before add.

.PARAMETER Enabled
    Switch to enable the account after creation.

.EXAMPLE
    $cred = Get-Credential contoso\adadmin
    .\New-AdUser-With-Groups-ServerCred.ps1 `
      -Server "dc01.contoso.com" -Credential $cred `
      -SamAccountName "tbeha" -GivenName "Thomas" -Surname "Beha" `
      -UserPrincipalName "tbeha@contoso.com" `
      -OU "OU=Employees,OU=Germany,DC=contoso,DC=com" `
      -Email "thomas.beha@contoso.com" -Department "IT" -Title "Systems Engineer" `
      -Groups "GG-Employees","GG-IT","GG-VPN-Access" `
      -Enabled
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$GivenName,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Surname,

    [Parameter(Mandatory=$false)]
    [string]$DisplayName,

    [Parameter(Mandatory=$false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$false)]
    [string]$OU, # e.g. "OU=Employees,DC=contoso,DC=com"

    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]$InitialPassword,

    [Parameter(Mandatory=$false)]
    [string]$Email,

    [Parameter(Mandatory=$false)]
    [string]$Department,

    [Parameter(Mandatory=$false)]
    [string]$Title,

    [Parameter(Mandatory=$false)]
    [string[]]$Groups,

    [switch]$Enabled
)

begin {
    function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
    function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
    function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }

    # Ensure the ActiveDirectory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT or run on a domain-joined admin host."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    # Helper to escape LDAP filter values when falling back to -LDAPFilter
    function Escape-LdapFilterValue([string]$value) {
        if ($null -eq $value) { return $null }
        return ($value -replace '([\\\*\(\)\0])', {'\' + ('{0:X2}' -f [int][char]$args[0].Groups[1].Value)})
    }

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        $DisplayName = "$GivenName $Surname"
    }

    # Derive default UPN suffix if not provided
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        try {
            $forest = Get-ADForest -Server $Server -Credential $Credential -ErrorAction Stop
            $defaultSuffix = $forest.UpnSuffixes | Select-Object -First 1
            if ([string]::IsNullOrWhiteSpace($defaultSuffix)) {
                $domain = Get-ADDomain -Server $Server -Credential $Credential -ErrorAction Stop
                $defaultSuffix = $domain.DNSRoot
            }
            $UserPrincipalName = "$SamAccountName@$defaultSuffix"
        } catch {
            throw "Could not determine default UPN suffix. Provide -UserPrincipalName explicitly. Details: $($_.Exception.Message)"
        }
    }

    if (-not $InitialPassword) {
        $InitialPassword = Read-Host -Prompt "Enter initial password for $SamAccountName" -AsSecureString
    }
}

process {
    try {
        # Abort if user already exists
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -Server $Server -Credential $Credential -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Warn "User '$SamAccountName' already exists (DN: $($existingUser.DistinguishedName)). Aborting creation."
            return
        }

        # Build New-ADUser params
        $userParams = @{
            Name                   = $DisplayName
            GivenName              = $GivenName
            Surname                = $Surname
            SamAccountName         = $SamAccountName
            UserPrincipalName      = $UserPrincipalName
            DisplayName            = $DisplayName
            AccountPassword        = $InitialPassword
            ChangePasswordAtLogon  = $true
            Enabled                = $false # enable after creation if -Enabled provided
            Server                 = $Server
            Credential             = $Credential
        }
        if ($OU)         { $userParams['Path']          = $OU }
        if ($Email)      { $userParams['EmailAddress']  = $Email }
        if ($Department) { $userParams['Department']    = $Department }
        if ($Title)      { $userParams['Title']         = $Title }

        if ($PSCmdlet.ShouldProcess("AD User '$SamAccountName'","Create")) {
            Write-Info "Creating user '$SamAccountName' ($DisplayName) on $Server ..."
            New-ADUser @userParams -ErrorAction Stop
            Write-Info "User '$SamAccountName' created."
        }

        if ($Enabled.IsPresent) {
            if ($PSCmdlet.ShouldProcess("AD User '$SamAccountName'","Enable")) {
                Enable-ADAccount -Identity $SamAccountName -Server $Server -Credential $Credential -ErrorAction Stop
                Write-Info "User '$SamAccountName' enabled."
            }
        }

        # Add to groups if provided
        if ($Groups -and $Groups.Count -gt 0) {
            Write-Info "Processing group memberships on $Server ..."
            $missing = @()
            $added   = @()
            $skippedAlreadyMember = @()

            foreach ($grp in $Groups) {
                if ([string]::IsNullOrWhiteSpace($grp)) { continue }

                # Try by -Identity (supports sAM, DN, GUID, SID)
                $group = $null
                try {
                    $group = Get-ADGroup -Identity $grp -Server $Server -Credential $Credential -ErrorAction Stop
                } catch {
                    # Fallback to search by sAMAccountName or CN using LDAP filter
                    $safe = Escape-LdapFilterValue $grp
                    $ldap = "(|(sAMAccountName=$safe)(cn=$safe))"
                    $group = Get-ADGroup -LDAPFilter $ldap -Server $Server -Credential $Credential -ErrorAction SilentlyContinue
                    # If multiple results, pick first
                    if ($group -is [System.Array]) { $group = $group | Select-Object -First 1 }
                }

                if (-not $group) {
                    Write-Warn "Group '$grp' not found on $Server. Skipping."
                    $missing += $grp
                    continue
                }

                # Check membership efficiently (best-effort)
                $isMember = $false
                try {
                    $isMember = (Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -Server $Server -Credential $Credential -ErrorAction Stop |
                                 Where-Object { $_.objectClass -eq 'user' -and $_.SamAccountName -eq $SamAccountName } |
                                 Select-Object -First 1) -ne $null
                } catch {
                    # On very large groups or restricted enumeration, we'll attempt to add and handle duplicate gracefully
                    $isMember = $false
                }

                if ($isMember) {
                    Write-Info "Already a member: '$($group.Name)'."
                    $skippedAlreadyMember += $group.Name
                    continue
                }

                if ($PSCmdlet.ShouldProcess("Group '$($group.Name)'","Add member '$SamAccountName'")) {
                    try {
                        Add-ADGroupMember -Identity $group.DistinguishedName -Members $SamAccountName -Server $Server -Credential $Credential -ErrorAction Stop
                        Write-Info "Added to group: '$($group.Name)'."
                        $added += $group.Name
                    } catch {
                        # If already a member because enumeration failed, treat as info
                        if ($_.Exception.Message -match 'is already a member') {
                            Write-Info "Reported already a member: '$($group.Name)'."
                            $skippedAlreadyMember += $group.Name
                        } else {
                            Write-Err "Failed to add to '$($group.Name)': $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Summary
            Write-Host ""
            Write-Host "===== GROUP SUMMARY =====" -ForegroundColor Green
            if ($added.Count) { Write-Host ("Added: " + ($added -join ", ")) }
            if ($skippedAlreadyMember.Count) { Write-Host ("Already member: " + ($skippedAlreadyMember -join ", ")) }
            if ($missing.Count) { Write-Host ("Missing groups: " + ($missing -join ", ")) }
            Write-Host "=========================" -ForegroundColor Green
        } else {
            Write-Info "No groups specified."
        }

        Write-Info "Completed for '$SamAccountName'."
    }
    catch {
        Write-Err "Unhandled error: $($_.Exception.Message)"
        throw
    }
}


