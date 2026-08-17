
[CmdletBinding()]
param(
    [string]$netboxBaseUrl = "https://admtb1008.adm.ctc.int.hpe.com/api",
    [string]$netboxToken = 'C:\Users\thomasb\Documents\adpwsh\DNS\netbox.token',
    [string]$DnsServer = "dmodc2.dmo.ctc.int.hpe.com",
    [string[]]$ForwardZones = @("dmo.ctc.int.hpe.com"),
    [string]$NetBoxStatus = "active",
    [string]$LogPath = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-DNS-Sync",
    [string]$CsvReportPath = "C:\Users\thomasb\Documents\adpwsh\Logs\NetBox-DNS-Sync-Report",
    [string]$dnsMismatches = "C:\Users\thomasb\Documents\adpwsh\Logs\dnsmismatches"
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

function Get-Hostname{
    param(
        [Parameter(Mandatory = $true)]
        [string]$fqdn
    )
    $parts = $fqdn -split '\.', 2
    $hostname = $parts[0]

    return $hostname
}




# Main execution
try {

    $host1 = Get-Hostname -fqdn "host1.dmo.ctc.int.hpe.com"
    $host2 = Get-Hostname -fqdn "host2"
    Write-Host "$($host1) , $($host2)"

}   
catch {
    Write-Error "An error occurred: $_"
    exit 1
}    




