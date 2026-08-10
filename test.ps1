
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

# Main execution
try {
    $dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $LogPath = "$LogPath-$dt.log"
    $CsvReportPath = "$CsvReportPath-$dt.csv"  
    $dnsMismatches = "$dnsMismatches-$dt.json"
    Write-Host "$($Logpath)"
    Write-Host "$($CsvReportPath)"
    Write-Host "$($dnsMismatches)"
}   
catch {
    Write-Error "An error occurred: $_"
    exit 1
}    




