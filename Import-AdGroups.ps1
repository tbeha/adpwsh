<#

Run example:


# Dry run first
.\Import-AdGroups.ps1 `
  -TargetDomainController dc1.target.corp `
  -DefaultTargetOU "OU=Groups,DC=target,DC=corp" `
  -GroupsCsvPath .\groups.csv `
  -MembersCsvPath .\group_members.csv `
  -WhatIf

# Apply for real (remove -WhatIf)
.\Import-AdGroups.ps1 `
  -TargetDomainController dc1.target.corp `
  -DefaultTargetOU "OU=Groups,DC=target,DC=corp" `
  -GroupsCsvPath .\groups.csv `
  -MembersCsvPath .\group_members.csv


OU Mapping example:


$map = @{
  "OU=HQ,OU=Groups,DC=source,DC=corp"     = "OU=HQ,OU=Groups,DC=target,DC=corp"
  "OU=Branch,OU=Groups,DC=source,DC=corp" = "OU=Branch,OU=Groups,DC=target,DC=corp"
}
.\Import-AdGroups.ps1 -TargetDomainController dc1.target.corp `
  -DefaultTargetOU "OU=Groups,DC=target,DC=corp" `
  -GroupsCsvPath .\groups.csv -MembersCsvPath .\group_members.csv `
  -OUMap $map
``



#>


[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TargetDomainController,          # e.g. dc1.target.corp
    [Parameter(Mandatory)]
    [string]$DefaultTargetOU,                 # e.g. "OU=Groups,DC=target,DC=corp"
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$GroupsCsvPath,                   # from export
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$MembersCsvPath,                  # from export

    # Optional: map source OU paths to target OU paths
    # Keys: Source OU distinguished fragments (as exported in OUPath column)
    # Values: Target OU distinguished names
    [hashtable]$OUMap = @{},                 

    # Optional: how to map members between forests (choose one main strategy)
    [ValidateSet('SamAccountName','UPN','CN')]
    [string]$MemberMatchKey = 'SamAccountName',

    [switch]$WhatIf
)

Import-Module ActiveDirectory -ErrorAction Stop

function Resolve-TargetOU {
    param(
        [Parameter(Mandatory)][string]$SourceOUPath
    )
    # If OU mapping provided and match exists, return mapped target OU, else default
    if ($OUMap.ContainsKey($SourceOUPath)) {
        return $OUMap[$SourceOUPath]
    }
    return $DefaultTargetOU
}

# Load data
$groups  = Import-Csv -Path $GroupsCsvPath
$members = Import-Csv -Path $MembersCsvPath

# ---- PASS 1: Create/Upsert groups (without members) ----
$resultsGroups = @()
foreach ($g in $groups) {
    $targetOU = Resolve-TargetOU -SourceOUPath $g.OUPath
    $sam      = $g.SamAccountName
    $exists   = $null

    try {
        $exists = Get-ADGroup -Filter "SamAccountName -eq '$sam'" -Server $TargetDomainController -ErrorAction SilentlyContinue
        if ($exists) {
            # Update key fields if desired
            $setParams = @{
                Server      = $TargetDomainController
                Identity    = $exists.DistinguishedName
                Description = $g.Description
            }
            if ($g.ManagedBy) { $setParams['ManagedBy'] = $g.ManagedBy } # ensure DN is valid in target or transform if needed
            if ($PSCmdlet.ShouldProcess($sam, "Update-ADGroup")) {
                Set-ADGroup @setParams
            }
            $resultsGroups += [pscustomobject]@{ Sam=$sam; Action='Updated'; Path=$exists.DistinguishedName; Scope=$exists.GroupScope; Category=$exists.GroupCategory; Message='Exists -> Updated' }
        }
        else {
            # Create new group
            $newParams = @{
                Server        = $TargetDomainController
                Name          = $g.Name
                SamAccountName= $sam
                GroupScope    = $g.GroupScope
                GroupCategory = $g.GroupCategory
                Path          = $targetOU
                Description   = $g.Description
            }
            if ($g.ManagedBy) { $newParams['ManagedBy'] = $g.ManagedBy } # if DN differs across forests, consider mapping
            if ($PSCmdlet.ShouldProcess($sam, "New-ADGroup in $targetOU")) {
                $created = New-ADGroup @newParams -PassThru
                $resultsGroups += [pscustomobject]@{ Sam=$sam; Action='Created'; Path=$created.DistinguishedName; Scope=$g.GroupScope; Category=$g.GroupCategory; Message='Created' }
            }
        }
    }
    catch {
        $resultsGroups += [pscustomobject]@{ Sam=$sam; Action='Error'; Path=$targetOU; Scope=$g.GroupScope; Category=$g.GroupCategory; Message=$_.Exception.Message }
        Write-Warning "Group $sam failed: $($_.Exception.Message)"
    }
}

# ---- PASS 2: Add memberships ----
# Build quick lookup of groups that now exist in target
$targetGroups = @{}
Get-ADGroup -Filter * -SearchBase $DefaultTargetOU -Server $TargetDomainController -Properties SamAccountName |
    ForEach-Object { $targetGroups[$_.SamAccountName.ToLower()] = $_.DistinguishedName }

# Helper for principal lookup by chosen key
function Find-TargetPrincipal {
    param(
        [Parameter(Mandatory)][string]$KeyValue,  # sam/upn/cn value
        [Parameter(Mandatory)][ValidateSet('user','group','computer')][string]$Type
    )
    $filter = switch ($MemberMatchKey) {
        'SamAccountName' { "(SamAccountName -eq '$KeyValue')" }
        'UPN'            { "(UserPrincipalName -eq '$KeyValue')" }
        'CN'             { "(Name -eq '$KeyValue')" }
    }

    $cmd = if ($Type -eq 'group') { 'Get-ADGroup' } else { 'Get-ADUser' }
    if ($Type -eq 'computer') { $cmd = 'Get-ADComputer' }

    try {
        return & $cmd -Filter $filter -Server $TargetDomainController -ErrorAction Stop
    }
    catch {
        return $null
    }
}

$resultsMembers = @()
# Only process members whose target group exists (by SAM)
$byGroup = $members | Group-Object GroupSamAccountName
foreach ($chunk in $byGroup) {
    $groupSam = $chunk.Name
    $groupDn  = $targetGroups[$groupSam.ToLower()]
    if (-not $groupDn) {
        $resultsMembers += [pscustomobject]@{ Group=$groupSam; Member='(n/a)'; Action='Skip'; Message='Target group not found' }
        continue
    }

    foreach ($row in $chunk.Group) {
        $memberType = $row.MemberObjectClass.ToLower()  # user | group | computer | contact ...
        if ($memberType -notin @('user','group','computer')) {
            $resultsMembers += [pscustomobject]@{ Group=$groupSam; Member=$row.MemberSamAccountName; Action='Skip'; Message="Unsupported member type: $memberType" }
            continue
        }

        # Choose match key value
        $keyVal = switch ($MemberMatchKey) {
            'SamAccountName' { $row.MemberSamAccountName }
            'UPN'            { ($row.MemberDistinguishedName -match 'userprincipalname=') ? ($row.MemberDistinguishedName) : $row.MemberSamAccountName } # fallback
            'CN'             { ($row.MemberDistinguishedName -replace '^CN=([^,]+),.*$','$1') }
        }

        $targetMember = Find-TargetPrincipal -KeyValue $keyVal -Type $memberType
        if (-not $targetMember) {
            $resultsMembers += [pscustomobject]@{ Group=$groupSam; Member=$keyVal; Action='Missing'; Message='Member not found in target' }
            continue
        }

        try {
            if ($PSCmdlet.ShouldProcess("$groupSam <- $($targetMember.SamAccountName)", "Add-ADGroupMember")) {
                Add-ADGroupMember -Identity $groupDn -Members $targetMember.DistinguishedName -Server $TargetDomainController -ErrorAction Stop
            }
            $resultsMembers += [pscustomobject]@{ Group=$groupSam; Member=$targetMember.SamAccountName; Action='Added'; Message='OK' }
        }
        catch {
            $resultsMembers += [pscustomobject]@{ Group=$groupSam; Member=$targetMember.SamAccountName; Action='Error'; Message=$_.Exception.Message }
            Write-Warning "Add member failed ($groupSam <- $($targetMember.SamAccountName)): $($_.Exception.Message)"
        }
    }
}

# ---- Output summaries ----
"=== GROUPS SUMMARY ==="
$resultsGroups | Sort-Object Action, Sam | Format-Table -AutoSize

"=== MEMBERSHIP SUMMARY ==="
$resultsMembers | Group-Object Action | ForEach-Object {
    "{0,-10} {1,5}" -f $_.Name, $_.Count
}

# Save logs
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultsGroups  | Export-Csv -NoTypeInformation ".\import_groups_result_$stamp.csv"
$resultsMembers | Export-Csv -NoTypeInformation ".\import_members_result_$stamp.csv"
Write-Host "Logs written: import_groups_result_$stamp.csv, import_members_result_$stamp.csv" -ForegroundColor Yellow
