<#
.SYNOPSIS
    Intelligent VM tagging based on Entra ID device matching
.DESCRIPTION
    Analyzes VMs and Entra ID devices, finds matches, and applies correct deviceId tags.
    Uses similarity algorithms for matching.
.NOTES
    Author: Rafael França
    Version: 5.0.0
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [switch]$DryRun,
    
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  INTELLIGENT VM-TO-DEVICE TAG UPDATER" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "DRY RUN MODE: No changes will be made" -ForegroundColor Yellow
    Write-Host ""
}

# Set subscription
az account set --subscription $SubscriptionId | Out-Null
Write-Host "Subscription: $SubscriptionId" -ForegroundColor Green
Write-Host ""

# Get VMs
Write-Host "[1/3] Fetching Azure VMs..." -ForegroundColor Cyan
$vms = az vm list --query "[].{name:name, id:id, resourceGroup:resourceGroup, tags:tags}" | ConvertFrom-Json
Write-Host "  Found: $($vms.Count) VMs" -ForegroundColor Green
Write-Host ""

# Get Entra ID devices
Write-Host "[2/3] Fetching Entra ID devices..." -ForegroundColor Cyan
$devicesResponse = az rest --method GET --uri "https://graph.microsoft.com/v1.0/devices" | ConvertFrom-Json
$devices = $devicesResponse.value
Write-Host "  Found: $($devices.Count) devices" -ForegroundColor Green
Write-Host ""

# Simple matching function
function Test-NameMatch {
    param([string]$name1, [string]$name2)
    
    $n1 = $name1.ToLower()
    $n2 = $name2.ToLower()
    
    # Exact match
    if ($n1 -eq $n2) { return 100 }
    
    # Contains match
    if ($n1.Contains($n2) -or $n2.Contains($n1)) { return 85 }
    
    # Starts with
    if ($n1.StartsWith($n2) -or $n2.StartsWith($n1)) { return 75 }
    
    # Basic similarity (character overlap)
    $matches = 0
    $minLen = [Math]::Min($n1.Length, $n2.Length)
    for ($i = 0; $i -lt $minLen; $i++) {
        if ($n1[$i] -eq $n2[$i]) { $matches++ }
    }
    
    if ($matches -gt 0) {
        $similarity = [Math]::Round(($matches / $minLen) * 100, 0)
        return $similarity
    }
    
    return 0
}

# Match VMs to devices
Write-Host "[3/3] Matching VMs to devices..." -ForegroundColor Cyan
Write-Host ""

$matches = @()
$unmatched = @()

foreach ($vm in $vms) {
    $bestMatch = $null
    $bestScore = 0
    
    foreach ($device in $devices) {
        $score = Test-NameMatch -name1 $vm.name -name2 $device.displayName
        
        if ($score -gt $bestScore) {
            $bestScore = $score
            $bestMatch = $device
        }
    }
    
    if ($bestScore -ge 70) {
        $currentTag = $null
        if ($vm.tags -and $vm.tags.mde_device_id) {
            $currentTag = $vm.tags.mde_device_id
        }
        
        $needsUpdate = (-not $currentTag) -or ($currentTag -ne $bestMatch.deviceId)
        
        $matches += [PSCustomObject]@{
            VMName      = $vm.name
            VMID        = $vm.id
            DeviceName  = $bestMatch.displayName
            DeviceID    = $bestMatch.deviceId
            Similarity  = $bestScore
            CurrentTag  = $currentTag
            NeedsUpdate = $needsUpdate
        }
    }
    else {
        $unmatched += [PSCustomObject]@{
            VMName = $vm.name
            VMID   = $vm.id
            Score  = $bestScore
        }
    }
}

# Display matches
Write-Host "MATCHES FOUND: $($matches.Count)" -ForegroundColor Green
Write-Host ""

foreach ($match in $matches) {
    $marker = if ($match.NeedsUpdate) { "[UPDATE]" } else { "[OK]" }
    $color = if ($match.NeedsUpdate) { "Yellow" } else { "Green" }
    
    Write-Host "  $marker $($match.VMName)" -ForegroundColor $color
    Write-Host "    -> $($match.DeviceName)" -ForegroundColor $color
    Write-Host "    Similarity: $($match.Similarity)%" -ForegroundColor DarkGray
    Write-Host "    Device ID: $($match.DeviceID)" -ForegroundColor DarkGray
    
    if ($match.NeedsUpdate) {
        $currentDisplay = if ($match.CurrentTag) { $match.CurrentTag } else { "NOT SET" }
        Write-Host "    Current tag: $currentDisplay" -ForegroundColor DarkGray
        Write-Host "    New tag: $($match.DeviceID)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

if ($unmatched.Count -gt 0) {
    Write-Host "UNMATCHED VMs: $($unmatched.Count)" -ForegroundColor Red
    Write-Host ""
    
    foreach ($um in $unmatched) {
        Write-Host "  [NO MATCH] $($um.VMName)" -ForegroundColor Red
        Write-Host "    Best score: $($um.Score)%" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# Apply updates
$toUpdate = $matches | Where-Object { $_.NeedsUpdate }

if ($toUpdate.Count -eq 0) {
    Write-Host "NO UPDATES NEEDED - All VMs already have correct tags!" -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  $($toUpdate.Count) VMs NEED TAG UPDATES" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

if (-not $DryRun -and -not $Force) {
    $confirm = Read-Host "Apply these updates? (Y/n)"
    if ($confirm -eq 'n' -or $confirm -eq 'N') {
        Write-Host "Cancelled by user" -ForegroundColor Red
        exit 0
    }
}

if ($DryRun) {
    Write-Host "DRY RUN: Would update $($toUpdate.Count) VMs" -ForegroundColor Yellow
}
else {
    Write-Host "Updating VMs..." -ForegroundColor Cyan
    Write-Host ""
    
    $successCount = 0
    $failCount = 0
    
    foreach ($match in $toUpdate) {
        Write-Host "  Updating $($match.VMName)..." -NoNewline
        
        try {
            az vm update --ids $match.VMID --set tags.mde_device_id=$($match.DeviceID) 2>&1 | Out-Null
            Write-Host " OK" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            $failCount++
        }
    }
    
    Write-Host ""
    Write-Host "RESULTS:" -ForegroundColor Cyan
    Write-Host "  Success: $successCount" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed: $failCount" -ForegroundColor Red
    }
    else {
        Write-Host "  Failed: 0" -ForegroundColor Green
    }
    Write-Host ""
}

Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
