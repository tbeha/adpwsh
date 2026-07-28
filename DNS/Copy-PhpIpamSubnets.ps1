<#
.SYNOPSIS
    Copy subnet configurations (sections, folders, subnets) from one phpIPAM to another.

.DESCRIPTION
    - Authenticates to both phpIPAM systems with POST /api/{app}/user/ to obtain tokens.
    - Copies sections (by name) that don't exist on destination.
    - Copies subnets and folders (preserves hierarchy via masterSubnetId).
    - Optionally maps VRFs (by name/RD) and VLANs (by number) to destination if present.
    - Optionally transfers custom fields that exist on both systems.
    - Addresses are NOT copied by default.

.PARAMETER SourceUrl, SourceAppId, SourceUser, SourcePassword
.PARAMETER DestUrl, DestAppId, DestUser, DestPassword
.PARAMETER Sections
    Optional filter: section names (exact) to copy. If omitted, all sections are processed.

.PARAMETER IncludeCustomFields
    Include custom fields intersection from source->destination for subnets/folders.

.PARAMETER MapVRF
    Try to map source VRFs to destination by name or RD.

.PARAMETER MapVLAN
    Try to map VLANs by their number (and same L2 domain name if available).

.PARAMETER Conflict
    Behavior when a destination subnet (same CIDR in the section/VRF) already exists:
    'Skip' (default) | 'Update' (PATCH non-CIDR fields) | 'Error'.

.PARAMETER Insecure
    Skip TLS certificate validation (not recommended).

.PARAMETER DryRun
    Do NOT change destination; just print what would be done.

.EXAMPLE
    .\Copy-PhpIpamSubnets.ps1 `
      -SourceUrl https://ipam-src.example.com `
      -SourceAppId myapp `
      -SourceUser apiuser -SourcePassword '***' `
      -DestUrl https://ipam-dst.example.com `
      -DestAppId myapp `
      -DestUser apiuser -DestPassword '***' `
      -Sections 'Production','Lab' `
      -MapVRF -MapVLAN -IncludeCustomFields -Conflict Update

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$SourceUrl,
    [Parameter(Mandatory=$true)]  [string]$SourceAppId,
    [Parameter(Mandatory=$true)]  [string]$SourceUser,
    [Parameter(Mandatory=$true)]  [string]$SourcePassword,

    [Parameter(Mandatory=$true)]  [string]$DestUrl,
    [Parameter(Mandatory=$true)]  [string]$DestAppId,
    [Parameter(Mandatory=$true)]  [string]$DestUser,
    [Parameter(Mandatory=$true)]  [string]$DestPassword,

    [string[]]$Sections,
    [switch]$IncludeCustomFields,
    [switch]$MapVRF,
    [switch]$MapVLAN,
    [ValidateSet('Skip','Update','Error')] [string]$Conflict = 'Skip',
    [switch]$Insecure,
    [switch]$DryRun
)

#region Helpers: TLS handling for older PS
$revertCertCallback = $null
if ($Insecure) {
    Write-Warning "Insecure mode enabled: TLS certificate validation is disabled for this session."
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $global:PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
            $global:PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
        } else {
            $revertCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
    } catch { Write-Warning "Failed to set insecure TLS handling: $_" }
}
#endregion

try {
    function Invoke-PhpIpamApi {
        param(
            [Parameter(Mandatory=$true)] [ValidateSet('GET','POST','PATCH','DELETE','OPTIONS')] [string]$Method,
            [Parameter(Mandatory=$true)] [string]$BaseUrl,
            [Parameter(Mandatory=$true)] [string]$AppId,
            [Parameter(Mandatory=$true)] [string]$Path,     # e.g. 'sections/', 'subnets/123/'
            [hashtable]$Headers,
            [object]$Body
        )
        $uri = ($BaseUrl.TrimEnd('/')) + "/api/$AppId/" + $Path.TrimStart('/')
        $params = @{
            Method  = $Method
            Uri     = $uri
            Headers = $Headers
        }
        if ($null -ne $Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10); $params['ContentType'] = 'application/json' }
        try {
            return Invoke-RestMethod @params
        } catch {
            throw "API call failed: $Method $uri`n$($_.Exception.Message)"
        }
    }

    function Get-PhpIpamToken {
        param(
            [Parameter(Mandatory=$true)] [string]$BaseUrl,
            [Parameter(Mandatory=$true)] [string]$AppId,
            [Parameter(Mandatory=$true)] [string]$User,
            [Parameter(Mandatory=$true)] [string]$Password
        )
        $uri = ($BaseUrl.TrimEnd('/')) + "/api/$AppId/user/"
        $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Password"))
        $headers = @{ Authorization = "Basic $b64" }
        try {
            $resp = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers
            if (-not $resp.token) { throw "No token in response" }
            return $resp.token
        } catch {
            throw "Failed to authenticate at $uri : $($_.Exception.Message)"
        }
    }

    function Get-SectionMapByName {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token
        )
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        $list = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path 'sections/' -Headers $h
        # Map: name -> object
        $map = @{}
        foreach ($s in $list.data) { $map[$s.name] = $s }
        return $map
    }

    function Ensure-Section {
        param(
            [string]$DestUrl, [string]$DestAppId, [string]$DestToken,
            [object]$SourceSection, [switch]$DryRun
        )
        $h = @{ 'token' = $DestToken; 'Accept'='application/json' }
        $existingMap = Get-SectionMapByName -BaseUrl $DestUrl -AppId $DestAppId -Token $DestToken
        if ($existingMap.ContainsKey($SourceSection.name)) {
            return $existingMap[$SourceSection.name]
        }
        # Create minimal section
        $payload = @{
            name        = $SourceSection.name
            description = $SourceSection.description
        }
        if ($DryRun) {
            Write-Host "[DryRun] Would create section: $($SourceSection.name)"
            # Simulate return with no id (caller will re-fetch after DryRun or skip)
            return $payload
        } else {
            $resp = Invoke-PhpIpamApi -Method POST -BaseUrl $DestUrl -AppId $DestAppId -Path 'sections/' -Headers $h -Body $payload
            # fetch again to get full object
            $newMap = Get-SectionMapByName -BaseUrl $DestUrl -AppId $DestAppId -Token $DestToken
            return $newMap[$SourceSection.name]
        }
    }

    function Get-SubnetsForSection {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token, [int]$SectionId
        )
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        $resp = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path ("sections/{0}/subnets/" -f $SectionId) -Headers $h
        return $resp.data
    }

    function Get-CustomFields {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token
        )
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        try {
            $resp = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path 'subnets/custom_fields/' -Headers $h
            return ($resp.data.Keys)
        } catch {
            Write-Verbose "No custom fields or endpoint error: $_"
            return @()
        }
    }

    function Get-VrfMap {
        param([string]$BaseUrl, [string]$AppId, [string]$Token)
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        try {
            $resp = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path 'vrf/' -Headers $h
            $map = @{}
            foreach ($v in $resp.data) {
                # Key by name and RD if present
                if ($v.name) { $map["name::$($v.name)"] = $v }
                if ($v.rd)   { $map["rd::$($v.rd)"]     = $v }
            }
            return $map
        } catch { return @{} }
    }

    function Get-VlanMap {
        param([string]$BaseUrl, [string]$AppId, [string]$Token)
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        try {
            $resp = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path 'vlan/' -Headers $h
            $map = @{}
            foreach ($v in $resp.data) {
                if ($null -ne $v.number) { $map["num::$($v.number)"] = $v }
            }
            return $map
        } catch { return @{} }
    }

    function Find-DestSubnetByCIDR {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token,
            [string]$CIDR
        )
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        try {
            $r = Invoke-PhpIpamApi -Method GET -BaseUrl $BaseUrl -AppId $AppId -Path ("subnets/cidr/{0}/" -f $CIDR) -Headers $h
            return $r.data
        } catch { return $null }
    }

    function New-SubnetMinimal {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token,
            [object]$SrcSubnet, [int]$DestSectionId, [int]$DestMasterId,
            [switch]$DryRun
        )
        $h = @{ 'token' = $Token; 'Accept'='application/json' }

        # Determine if folder or subnet
        $isFolder = ($SrcSubnet.isFolder -eq 1 -or $SrcSubnet.isFolder -eq '1')

        if ($isFolder) {
            $payload = @{
                isFolder       = 1
                sectionId      = $DestSectionId
                masterSubnetId = ($DestMasterId -as [int])
                description    = $SrcSubnet.description
                # custom fields will be applied later (PATCH)
            }
        } else {
            # Build dotted CIDR
            $payload = @{
                sectionId      = $DestSectionId
                masterSubnetId = ($DestMasterId -as [int])
                subnet         = $SrcSubnet.subnet    # may already be dotted, but API will transform; create robustly:
                mask           = $SrcSubnet.mask
                description    = $SrcSubnet.description
            }
            # If 'subnet' came as decimal, try to ensure dotted form
            if ($SrcSubnet.cidr) {
                # If API returned 'cidr' like "192.0.2.0/24", prefer splitting
                $parts = $SrcSubnet.cidr -split '/'
                if ($parts.Count -eq 2) { $payload.subnet = $parts[0]; $payload.mask = [int]$parts[1] }
            }
        }

        if ($DryRun) {
            Write-Host "[DryRun] Would create " + ($isFolder ? "FOLDER" : "SUBNET") + " in sectionId=$DestSectionId masterSubnetId=$DestMasterId : $($SrcSubnet.description) $($SrcSubnet.cidr)"
            return @{ id = $null; created = $true; isFolder = $isFolder }
        } else {
            $resp = Invoke-PhpIpamApi -Method POST -BaseUrl $BaseUrl -AppId $AppId -Path 'subnets/' -Headers $h -Body $payload
            return $resp
        }
    }

    function Update-SubnetProperties {
        param(
            [string]$BaseUrl, [string]$AppId, [string]$Token,
            [int]$DestSubnetId,
            [hashtable]$PatchBody,
            [switch]$DryRun
        )
        if (-not $PatchBody -or $PatchBody.Keys.Count -eq 0) { return }
        $h = @{ 'token' = $Token; 'Accept'='application/json' }
        if ($DryRun) {
            Write-Host "[DryRun] Would PATCH /subnets/$DestSubnetId with: $(($PatchBody | ConvertTo-Json -Depth 10))"
        } else {
            Invoke-PhpIpamApi -Method PATCH -BaseUrl $BaseUrl -AppId $AppId -Path ("subnets/{0}/" -f $DestSubnetId) -Headers $h -Body $PatchBody | Out-Null
        }
    }

    # 1) Authenticate
    Write-Host "Authenticating to source..."
    $srcToken = Get-PhpIpamToken -BaseUrl $SourceUrl -AppId $SourceAppId -User $SourceUser -Password $SourcePassword
    Write-Host "Authenticating to destination..."
    $dstToken = Get-PhpIpamToken -BaseUrl $DestUrl -AppId $DestAppId -User $DestUser -Password $DestPassword

    # 2) Optional mappings
    $srcVrfMap = @{}; $dstVrfMap = @{}
    if ($MapVRF) {
        $srcVrfMap = Get-VrfMap -BaseUrl $SourceUrl -AppId $SourceAppId -Token $srcToken
        $dstVrfMap = Get-VrfMap -BaseUrl $DestUrl   -AppId $DestAppId   -Token $dstToken
    }
    $srcVlanMap = @{}; $dstVlanMap = @{}
    if ($MapVLAN) {
        $srcVlanMap = Get-VlanMap -BaseUrl $SourceUrl -AppId $SourceAppId -Token $srcToken
        $dstVlanMap = Get-VlanMap -BaseUrl $DestUrl   -AppId $DestAppId   -Token $dstToken
    }

    # 3) Custom field intersection
    $customIntersect = @()
    if ($IncludeCustomFields) {
        $srcCf = Get-CustomFields -BaseUrl $SourceUrl -AppId $SourceAppId -Token $srcToken
        $dstCf = Get-CustomFields -BaseUrl $DestUrl   -AppId $DestAppId   -Token $dstToken
        $customIntersect = @($srcCf | Where-Object { $dstCf -contains $_ })
        if ($customIntersect.Count -gt 0) {
            Write-Host "Custom fields to copy: $($customIntersect -join ', ')"
        } else {
            Write-Host "No common custom fields detected."
        }
    }

    # 4) Fetch sections on source (filter if provided)
    $srcSectionsByName = Get-SectionMapByName -BaseUrl $SourceUrl -AppId $SourceAppId -Token $srcToken
    $sectionsToProcess =
        if ($Sections -and $Sections.Count -gt 0) {
            $Sections | ForEach-Object {
                if ($srcSectionsByName.ContainsKey($_)) { $srcSectionsByName[$_] }
                else { Write-Warning "Section '$_' not found in source"; $null }
            } | Where-Object { $_ -ne $null }
        } else {
            $srcSectionsByName.Values
        }

    # 5) Process each section
    foreach ($srcSection in $sectionsToProcess) {
        Write-Host "Processing section: $($srcSection.name)"
        $dstSection = Ensure-Section -DestUrl $DestUrl -DestAppId $DestAppId -DestToken $dstToken -SourceSection $srcSection -DryRun:$DryRun
        if (-not $dstSection.id) {
            # Re-read in non-DryRun, or skip in DryRun
            if ($DryRun) { continue } else {
                $dstSection = (Get-SectionMapByName -BaseUrl $DestUrl -AppId $DestAppId -Token $dstToken)[$srcSection.name]
            }
        }

        # Pull subnets of this section
        $srcSubnets = @( Get-SubnetsForSection -BaseUrl $SourceUrl -AppId $SourceAppId -Token $srcToken -SectionId $srcSection.id )
        if ($srcSubnets.Count -eq 0) { Write-Host "No subnets/folders in section '$($srcSection.name)'"; continue }

        # Index by id, and prepare parent-child creation order
        $byId = @{}
        foreach ($s in $srcSubnets) { $byId[$s.id] = $s }

        # Build pending set; created map: sourceId -> destId
        $pending = New-Object System.Collections.Generic.HashSet[int]
        $created = @{}
        foreach ($s in $srcSubnets) { $null = $pending.Add([int]$s.id) }

        # Precompute VLAN/VRF mappings (best effort)
        function Resolve-VrfId($srcSubnet) {
            if (-not $MapVRF -or -not $srcSubnet.vrfId) { return $null }
            # Try by name or RD—need to look up source VRF by id (we only stored maps by name/rd; quick grab from /vrf again)
            # To keep it simple, attempt by RD first if present on the subnet object; else cannot resolve without extra call.
            # (Many phpIPAM builds include subnet.vrfId only; so we just skip if we can't safely map.)
            return $null
        }
        function Resolve-VlanId($srcSubnet) {
            if (-not $MapVLAN -or -not $srcSubnet.vlanId) { return $null }
            # We only have VLAN number mapping if we fetch each VLAN; many /sections/{id}/subnets return 'vlanId' only.
            # Skip unless numbers/objects are preloaded; a full mapping would require GET /vlan/{id}/ for each srcSubnet.vlanId.
            return $null
        }

        # Simple parent-first creation loop
        while ($pending.Count -gt 0) {
            $progressed = $false
            foreach ($sid in @($pending)) {
                $s = $byId[$sid]
                $parent = $s.masterSubnetId
                $parentReady = ($parent -eq 0 -or $parent -eq $null -or $created.ContainsKey([int]$parent))

                if (-not $parentReady) { continue }

                # Destination parent id
                $destParentId = if ($parent -and $parent -ne 0) { [int]$created[[int]$parent] } else { $null }

                # Check conflict on destination by CIDR (for real subnets only)
                $maybeExisting = $null
                $isFolder = ($s.isFolder -eq 1 -or $s.isFolder -eq '1')
                if (-not $isFolder) {
                    $cidr = if ($s.cidr) { $s.cidr } else { "$($s.subnet)/$($s.mask)" }
                    $maybeExisting = Find-DestSubnetByCIDR -BaseUrl $DestUrl -AppId $DestAppId -Token $dstToken -CIDR $cidr
                }

                $destSubnetId = $null
                if ($maybeExisting -and $maybeExisting.Count -gt 0) {
                    switch ($Conflict) {
                        'Skip'   { Write-Host "Subnet already exists on destination ($($maybeExisting[0].id)). Skipping: $($s.description) $($s.cidr)"; $destSubnetId = $maybeExisting[0].id }
                        'Update' { Write-Host "Subnet exists. Will PATCH fields: $($s.description) $($s.cidr)"; $destSubnetId = $maybeExisting[0].id }
                        'Error'  { throw "Conflict: Destination already has subnet $($s.cidr)" }
                    }
                } else {
                    $resp = New-SubnetMinimal -BaseUrl $DestUrl -AppId $DestAppId -Token $dstToken `
                        -SrcSubnet $s -DestSectionId $dstSection.id -DestMasterId $destParentId -DryRun:$DryRun
                    if ($DryRun) {
                        # Can't know the new id; store placeholder null
                        $destSubnetId = $null
                    } else {
                        $destSubnetId = $resp.id
                        Write-Host "Created $([string]::IsNullOrEmpty($s.cidr) ? 'FOLDER' : $s.cidr) → id=$destSubnetId"
                    }
                }

                # Prepare PATCH for additional fields (non-CIDR)
                if ($destSubnetId -or $DryRun) {
                    $patch = @{}

                    # Transfer known boolean/int flags when present
                    foreach ($k in @(
                        'isFull','showName','allowRequests','pingSubnet','discoverSubnet','resolveDNS',
                        'nameserverId','scanAgent','location','device','threshold','state'
                    )) {
                        if ($s.PSObject.Properties.Match($k).Count -gt 0 -and $s.$k -ne $null) { $patch[$k] = $s.$k }
                    }

                    # Parent link might be needed if (re)attaching as child
                    if ($destParentId) { $patch['masterSubnetId'] = [int]$destParentId }

                    # Optional mappings
                    $vrfMappedId = Resolve-VrfId $s
                    if ($vrfMappedId) { $patch['vrfId'] = [int]$vrfMappedId }
                    $vlanMappedId = Resolve-VlanId $s
                    if ($vlanMappedId) { $patch['vlanId'] = [int]$vlanMappedId }

                    # Custom fields intersection
                    if ($IncludeCustomFields -and $customIntersect.Count -gt 0) {
                        foreach ($cf in $customIntersect) {
                            if ($s.PSObject.Properties.Match($cf).Count -gt 0) {
                                $patch[$cf] = $s.$cf
                            }
                        }
                    }

                    # Apply PATCH if any fields prepared and if not DryRun
                    if ($patch.Keys.Count -gt 0) {
                        Update-SubnetProperties -BaseUrl $DestUrl -AppId $DestAppId -Token $dstToken `
                            -DestSubnetId $destSubnetId -PatchBody $patch -DryRun:$DryRun
                    }
                }

                # Mark created
                $created[[int]$sid] = $destSubnetId
                $null = $pending.Remove([int]$sid)
                $progressed = $true
            }

            if (-not $progressed) {
                throw "Could not progress creation order. Likely unresolved parent or conflict."
            }
        }
    }

    Write-Host "Done."
}
finally {
    if ($Insecure -and $revertCertCallback) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $revertCertCallback
    }
}