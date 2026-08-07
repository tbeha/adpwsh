
[CmdletBinding()]
param(
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxTokenPath = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token'
)

# Use PowerNetBox module (recommended)
# Instead of raw API:  https://github.com/ctrl-alt-automate/PowerNetbox

Import-Module PowerNetbox
function Get-NetboxSession{

    $secureToken = Get-Content $netboxTokenPath -Raw | ConvertTo-SecureString -AsPlainText -Force
    $nbcred = [pscredential]::new('admin', $securetoken)
    Connect-NBApi -Uri $netboxBaseUrl -Credential $nbcred -SkipCertificateCheck

}

function Get-SubnetFilter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$cidr
    )
  
    if($cidr -match "^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\/(\d{1,2})$") {
        # Replace last octet with a wildcard for filtering
        $wildcard = "$($matches[1]).*"
    }
    else {
        throw "Invalid CIDR format: $cidr"
    }

    return $wildcard
}

# Main execution
try {

    # open the connection to the Netbox
    Get-NetboxSession

    Get-NBversion | Write-Host

    $subnets = Get-NBIPAMPrefix -All -ErrorAction Stop
    $addresses = Get-NBIPAMAddress -All -ErrorAction Stop
    Write-Host "Successfully retrieved $($subnets.Count) IP prefixes from NetBox and saved to netbox_ipam_prefixes.json"
    foreach ($prefix in $subnets) {
        Write-Host "Retrieve IP Addresses for Subnet: $($prefix.prefix), Tags: $($prefix.tags.name)"
        $filter =   Get-SubnetFilter -cidr $prefix.prefix
        $subnetsAddresses = $addresses | Where-Object { $_.address -like "$filter*" }
        foreach ($address in $subnetsAddresses) {
            Write-Host "IP Address: $($address.address), DNS Name: $($address.dns_name), Status: $($address.status.value), Tags: $($prefix.tags.name)"
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}    




