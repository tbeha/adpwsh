
[CmdletBinding()]
param(
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string[]]$ForwardZones = @("dmo.ctc.int.hpe.com"),
    [string]$NetBoxStatus = "active",
    [int]$PageLimit = 1000,
    [Boolean]$CreatePtr = $true,
    [Boolean]$UpdateExisting = $true,
    [Boolean]$RemoveStaleRecords = $true,
    [Boolean]$WhatIfMode = $true,
    [string]$LogPath = ".\NetBox-DNS-Sync.log",
    [string]$CsvReportPath = ".\NetBox-DNS-Sync-Report.csv"
)


# Iomport PowerShell modules
Import-Module DnsServer -ErrorAction Stop
Import-Module PowerNetbox

function Get-NetboxSession{

    $secureToken = Get-Content $netboxToken -Raw | ConvertTo-SecureString -AsPlainText -Force
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
    Write-Log -Level INFO -Message "Connected to NetBox: $(Get-NBVersion)"

    # Get the list of Subnets for the specified domain from Netbox

    $addresses = Get-NBIPAMAddress -All -ErrorAction Stop
    $subnets = Get-NBIPAMPrefix -All -ErrorAction Stop | Where-Object { $_.tags.name -contains $ForwardZones[0] }
    $desiredAddresses = @()
    foreach($sub in $subnets) {
        $subnetFilter = Get-SubnetFilter -cidr $sub.prefix
        #$addresses = Get-NBIPAMAddress -All -ErrorAction Stop | Where-Object { $_.address -like "$subnetFilter*" }
        $desiredAddresses += $addresses | Where-Object { $_.address -like "$subnetFilter*" }    
    }

}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}    




