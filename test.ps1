$path = '.\netbox.token'

if (Test-Path $path) {
    try {
        $content = Get-Content $path -Raw -ErrorAction Stop
        Write-Output $content
    }
    catch {
        Write-Error "Failed to read file: $($_.Exception.Message)"
    }
}
else {
    Write-Warning "File not found: $path"
}

foreach ($i in 140..200){
    $zoneName = "$i.1.10.in-addr.arpa"
    Write-Host "Deleting reverse lookup zone: $zoneName"
}

