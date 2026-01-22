# https://www.powershellgallery.com/packages/PSPHPIPAM/1.3.10
Import-Module PSPHPIPAM

# Your settings
$ApiUrl = "http://suo04ctcinf7.demo.local/api/"  # must include trailing slash
$AppId  = "DNS"                         # the App ID you created
$Cred   = Get-Credential -UserName "morpheus"  # phpIPAM user



# Open the session (token-based)
$result = New-PhpIpamSession -UseCredAuth `
  -PhpIpamApiUrl $ApiUrl `
  -AppID $AppId `
  -Username $Cred.UserName `
  -Password ($Cred.GetNetworkCredential().Password)

# Get All Subnets and their Addresses
$subnets =  Get-PhpIpamAllSubnets
$subnets | Format-Table
$addresses = Get-PhpIpamAddresses
foreach ($subnet in $subnets) {
    Write-Host "Subnet: $($subnet.description) ($($subnet.subnet))/($($subnet.mask)) - ID: $($subnet.id)"
    $subnetaddresses = $addresses | Where-Object { $_.subnetid -eq $subnet.id }
    $subnetaddresses | Format-Table
}

exit(0)
 