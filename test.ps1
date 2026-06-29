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

