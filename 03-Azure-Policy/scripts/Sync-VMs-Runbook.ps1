param(
    [string]$SubscriptionId,
    [string]$GroupId,
    [bool]$IncludeArc = $true
)

$ErrorActionPreference = "Stop"

Write-Output "==================================================================="
Write-Output "SYNC VMs TO M365 GROUP - Started: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Output "Subscription: $SubscriptionId | Group: $GroupId"
Write-Output "==================================================================="

Write-Output "[AUTH] Getting tokens..."
$armToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
$graphToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$armHeaders = @{"Authorization" = "Bearer $armToken"; "Content-Type" = "application/json" }
$graphHeaders = @{"Authorization" = "Bearer $graphToken"; "Content-Type" = "application/json" }

Write-Output "[INVENTORY] Fetching VMs..."
$vmsUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01"
$vms = (Invoke-RestMethod -Uri $vmsUri -Headers $armHeaders -Method Get).value
Write-Output "[OK] Found $($vms.Count) VMs"

if ($IncludeArc) {
    $arcUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.HybridCompute/machines?api-version=2023-06-20-preview"
    $vms += (Invoke-RestMethod -Uri $arcUri -Headers $armHeaders -Method Get).value
    Write-Output "[OK] Total: $($vms.Count)"
}

Write-Output "[GRAPH] Fetching devices..."
$devicesUri = "https://graph.microsoft.com/v1.0/devices"
$allDevices = @()
do {
    $dr = Invoke-RestMethod -Uri $devicesUri -Headers $graphHeaders -Method Get
    $allDevices += $dr.value
    $devicesUri = $dr.'@odata.nextLink'
} while ($devicesUri)
Write-Output "[OK] Found $($allDevices.Count) devices"

Write-Output "[GRAPH] Fetching group members..."
$membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
$currentMembers = @()
do {
    $mr = Invoke-RestMethod -Uri $membersUri -Headers $graphHeaders -Method Get
    $currentMembers += $mr.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }
    $membersUri = $mr.'@odata.nextLink'
} while ($membersUri)
$currentMemberIds = $currentMembers.id
Write-Output "[OK] Current: $($currentMembers.Count)"

Write-Output "[MAPPING] Processing..."
$matched = 0
$devicesToAdd = @()

foreach ($vm in $vms) {
    $vmName = $vm.name
    $device = $null
    
    # Strategy 1: Tag-based lookup
    if ($vm.tags) {
        $did = if ($vm.tags.deviceId) { $vm.tags.deviceId }
        elseif ($vm.tags.mdm_device_id) { $vm.tags.mdm_device_id }
        elseif ($vm.tags.intune_device_id) { $vm.tags.intune_device_id }
        else { $null }
        
        if ($did) {
            $device = $allDevices | Where-Object { $_.deviceId -eq $did } | Select-Object -First 1
        }
    }
    
    # Strategy 2: Exact name match
    if (-not $device) {
        $device = $allDevices | Where-Object { $_.displayName -eq $vmName } | Select-Object -First 1
    }
    
    # Strategy 3: Partial name match
    if (-not $device) {
        $device = $allDevices | Where-Object { $_.displayName.StartsWith($vmName, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    }
    
    if ($device) {
        $matched++
        if ($currentMemberIds -notcontains $device.id) {
            $devicesToAdd += $device.id
            Write-Output "  MATCH: $vmName -> $($device.displayName)"
        }
    }
}

Write-Output "[SUMMARY] Matched: $matched/$($vms.Count) | To add: $($devicesToAdd.Count)"

if ($devicesToAdd.Count -gt 0) {
    Write-Output "[GRAPH] Adding..."
    $addUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
    foreach ($did in $devicesToAdd) {
        try {
            $body = @{"@odata.id" = "https://graph.microsoft.com/v1.0/devices/$did" } | ConvertTo-Json
            Invoke-RestMethod -Uri $addUri -Headers $graphHeaders -Method Post -Body $body
            Write-Output "  [OK] $did"
        }
        catch {
            Write-Output "  [ERR] $did"
        }
    }
}

Write-Output "==================================================================="
Write-Output "COMPLETED: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Output "==================================================================="
