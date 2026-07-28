<# 
.SYNOPSIS
Exports all groups from a given AD OU to CSV, optionally including member details.

.PARAMETER OuDistinguishedName
The DN of the OU (e.g., "OU=Groups,OU=Corp,DC=contoso,DC=com").

.PARAMETER CsvPath
Path to the output CSV file.

.PARAMETER IncludeMembers
If set, expands group members and outputs one row per member (with group metadata).

.PARAMETER DomainController
(Optional) Specific DC to query.

.PARAMETER UseStoredCredential
If set, uses a stored credential from an encrypted password file (recommended).

.PARAMETER CredUser
Username for the credential (e.g., "CONTOSO\svc.reader"). Used with -UseStoredCredential or -InsecureCreds.

.PARAMETER EncryptedPasswordPath
Path to the encrypted password file created with ConvertFrom-SecureString (used with -UseStoredCredential).

.PARAMETER InsecureCreds
If set, uses the provided plain-text password (not recommended).

.PARAMETER PlainTextPassword
Plain text password used with -InsecureCreds (not recommended).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OuDistinguishedName = 'OU=Democenter,DC=demo,DC=local',

    [Parameter(Mandatory=$false)]
    [string]$CsvPath = ".\ad_groups_export.csv",

    [Parameter(Mandatory=$false)]
    [switch]$IncludeMembers = $false,

    [Parameter(Mandatory=$false)]
    [string]$DomainController = 'suo04ctcw005.demo.local',

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential] $Credential
)

begin {
    # Ensure AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Throw "The 'ActiveDirectory' module is not available. Install RSAT or AD DS tools first."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    # Build credential if requested
    #$Credential = Get-Credential 


    # Build common parameters for AD cmdlets
    $adParams = @{
        SearchBase   = $OuDistinguishedName
        SearchScope  = 'Subtree'
        Server       = $DomainController
        Credential   = $Credential
        ErrorAction  = 'Stop'
    }

    <# Remove null entries (Server/Credential may be null)
    $adParams = $adParams.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object {
        @{ ($_.Key) = $_.Value }
    } | ForEach-Object { $_ }
    $adParams = [hashtable]::new( $adParams )
    #>

    # Prepare output folder
    $outDir = Split-Path -Path $CsvPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }
}

process {
    try {
        Write-Host "Querying groups under OU: $OuDistinguishedName ..." -ForegroundColor Cyan

        # Get groups with useful properties
        $groups = Get-ADGroup @adParams -LDAPFilter '(objectClass=group)' -Properties `
            displayName, description, groupCategory, groupScope, whenCreated, whenChanged, managedBy, member

        if (-not $groups) {
            Write-Warning "No groups found under OU: $OuDistinguishedName"
            return
        }

        if (-not $IncludeMembers) {
            # One row per group
            $result = $groups | Select-Object `
                @{n='OU';e={$OuDistinguishedName}},
                Name,
                SamAccountName,
                DistinguishedName,
                GroupCategory,
                GroupScope,
                DisplayName,
                Description,
                ManagedBy,
                WhenCreated,
                WhenChanged,
                @{n='MemberCount';e={($_.member | Measure-Object).Count}}

            $result | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Exported $(($result | Measure-Object).Count) groups to $CsvPath" -ForegroundColor Green
        }
        else {
            # One row per group member (expansion), keeping group metadata
            $output = New-Object System.Collections.Generic.List[object]

            $i = 0
            foreach ($g in $groups) {
                $i++
                Write-Progress -Activity "Expanding group members" -Status $g.Name -PercentComplete (($i / $groups.Count) * 100)

                $members = @()
                try {
                    $members = Get-ADGroupMember -Credential $Credential -server $DomainController -Identity $g.Name -Recursive |
                                Where-Object { $_.objectClass -eq 'user' }
                }
                catch {
                    Write-Warning "Failed to enumerate members for '$($g.Name)': $($_.Exception.Message)"
                }

                if (-not $members -or $members.Count -eq 0) {
                    # Output at least the group row with no member
                    $output.Add([pscustomobject]@{
                        OU                 = $OuDistinguishedName
                        GroupName          = $g.Name
                        GroupSamAccount    = $g.SamAccountName
                        GroupDN            = $g.DistinguishedName
                        GroupCategory      = $g.GroupCategory
                        GroupScope         = $g.GroupScope
                        GroupDisplayName   = $g.DisplayName
                        GroupDescription   = $g.Description
                        GroupManagedBy     = $g.ManagedBy
                        GroupWhenCreated   = $g.WhenCreated
                        GroupWhenChanged   = $g.WhenChanged
                        MemberType         = $null
                        MemberName         = $null
                        MemberSamAccount   = $null
                        MemberDN           = $null
                        MemberObjectGUID   = $null
                    })
                    continue
                }

                foreach ($m in $members) {
                    # Try to enrich members with sAMAccountName where possible
                    $memberSam = $null
                    try {
                        if ($m.objectClass -in @('user','computer','group','msDS-GroupManagedServiceAccount','serviceAccount')) {
                            $mFull = Get-ADObject @adParams -Identity $m.DistinguishedName -Properties sAMAccountName
                            $memberSam = $mFull.sAMAccountName
                        }
                    }
                    catch { }

                    $output.Add([pscustomobject]@{
                        OU                 = $OuDistinguishedName
                        GroupName          = $g.Name
                        GroupSamAccount    = $g.SamAccountName
                        GroupDN            = $g.DistinguishedName
                        GroupCategory      = $g.GroupCategory
                        GroupScope         = $g.GroupScope
                        GroupDisplayName   = $g.DisplayName
                        GroupDescription   = $g.Description
                        GroupManagedBy     = $g.ManagedBy
                        GroupWhenCreated   = $g.WhenCreated
                        GroupWhenChanged   = $g.WhenChanged
                        MemberType         = $m.objectClass
                        MemberName         = $m.Name
                        MemberSamAccount   = $memberSam
                        MemberDN           = $m.DistinguishedName
                        MemberObjectGUID   = $m.ObjectGUID
                    })
                }
            }

            $output | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Exported $($output.Count) rows (group + member details) to $CsvPath" -ForegroundColor Green
        }

    }
    catch {
        Write-Error "Export failed: $($_.Exception.Message)"
        throw
    }
}
