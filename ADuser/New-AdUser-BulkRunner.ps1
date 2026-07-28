<#
.SYNOPSIS
    Bulk creates new AD users from a CSV file.  

.DESCRIPTION    
    - Reads user details from a CSV file.
    - For each user, calls New-AdUser-With-Groups.ps1 to create the user and add to groups.
    - Prompts for an initial password to set for all users.
    - Supports enabling/disabling accounts based on CSV data.   
    
.PARAMETER CsvPath
    Path to the CSV file containing user details.           

.EXAMPLE
    .\New-AdUser-BulkRunner.ps1 -CsvPath .\users.csv    


CSV Format:

SamAccountName,GivenName,Surname,UserPrincipalName,OU,Email,Department,Title,Groups,Enabled
jdoe,John,Doe,jdoe@contoso.com,"OU=Employees,DC=contoso,DC=com",john.doe@contoso.com,IT,"Systems Engineer","GG-Employees|GG-IT|GG-VPN-Access",True
asmith,Anna,Smith,asmith@contoso.com,"OU=Employees,DC=contoso,DC=com",anna.smith@contoso.com,Finance,"Analyst","GG-Employees|GG-Fin
ance",False

#>
$pwd = Read-Host "Enter initial password for all users" -AsSecureString
Import-Csv .\users.csv | ForEach-Object {
    $groups = @()
    if ($_.Groups) { $groups = $_.Groups -split '\|' | Where-Object { $_ -and $_.Trim() -ne '' } }

    .\New-AdUser-With-Groups.ps1 `
        -SamAccountName $_.SamAccountName `
        -GivenName $_.GivenName `
        -Surname $_.Surname `
        -UserPrincipalName $_.UserPrincipalName `
        -OU $_.OU `
        -Email $_.Email `
        -Department $_.Department `
        -Title $_.Title `
        -Groups $groups `
        -InitialPassword $pwd `
        -Enabled:([bool]::Parse($_.Enabled))
}
