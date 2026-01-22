<#
Run example:


.\Export-AdGroups.ps1 -SourceDomainController dc1.source.corp `
  -SearchBase "OU=Groups,DC=source,DC=corp" `
  -GroupsCsvPath .\groups.csv -MembersCsvPath .\group_members.csv


#>


[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceDomainController,           # e.g. dc1.source.corp
    [Parameter(Mandatory)]
    [string]$SearchBase,                       # e.g. "OU=Groups,DC=source,DC=corp"
    [string]$GroupsCsvPath   = ".\groups.csv",
    [string]$MembersCsvPath  = ".\group_members.csv",

    # Optional filter to exclude default/built-in groups; adjust as needed.
    [string[]]$ExcludeSamLike = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                                  'Users','Guests','Pre-Windows 2000*','*DnsAdmins*','*Enterprise Key Admins*')
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Exporting groups from $SearchBase on $SourceDomainController ..." -ForegroundColor Cyan

# 1) Export group objects & key attributes
$groups = Get-ADGroup -Filter * -SearchBase $SearchBase -Server $SourceDomainController -Properties Description,ManagedBy,whenCreated |
    Where-Object {
        $gName = $_.SamAccountName
        -not ($ExcludeSamLike | Where-Object { $gName -like $_ })
    } |
    Select-Object `
        Name,
        SamAccountName,
        DistinguishedName,
        GroupCategory,
        GroupScope,
        @{n='OUPath';e={ ($_.DistinguishedName -replace '^CN=[^,]+,','') }},
        Description,
        ManagedBy

$groups | Export-Csv -NoTypeInformation -Path $GroupsCsvPath -Encoding UTF8
Write-Host "Exported $($groups.Count) groups to $GroupsCsvPath" -ForegroundColor Green

# 2) Export direct membership (users and groups)
$memberRows = foreach ($g in $groups) {
    try {
        $members = Get-ADGroupMember -Identity $g.DistinguishedName -Server $SourceDomainController -ErrorAction Stop
        foreach ($m in $members) {
            [pscustomobject]@{
                GroupSamAccountName  = $g.SamAccountName
                GroupDN              = $g.DistinguishedName
                MemberSamAccountName = $m.SamAccountName
                MemberDistinguishedName = $m.DistinguishedName
                MemberObjectClass    = $m.objectClass  # user / group / computer / etc
            }
        }
    }
    catch {
        Write-Warning "Unable to get members for group $($g.SamAccountName): $($_.Exception.Message)"
    }
}

$memberRows | Export-Csv -NoTypeInformation -Path $MembersCsvPath -Encoding UTF8
Write-Host "Exported $($memberRows.Count) membership rows to $MembersCsvPath" -ForegroundColor Green
