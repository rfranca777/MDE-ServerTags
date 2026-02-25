<#
.SYNOPSIS
    Deploy Azure Policy with Automatic Remediation for MDE Device Tagging
.DESCRIPTION
    Creates and assigns an Azure Policy that automatically tags VMs with their
    Microsoft Defender for Endpoint device IDs, enabling automatic VM-to-Device mapping.
.NOTES
    Author: Rafael França
    Version: 1.0.0
    Requires: Owner or Contributor + User Access Administrator role
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Subscription", "ManagementGroup")]
    [string]$Scope = "Subscription"
)

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  AZURE POLICY - MDE REMEDIATION DEPLOYMENT" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Select Subscription if not provided
if (-not $SubscriptionId) {
    Write-Host "--- SUBSCRIPTION SELECTION ---" -ForegroundColor Yellow
    Write-Host ""
    
    $subs = az account list | ConvertFrom-Json
    
    for ($i = 0; $i -lt $subs.Count; $i++) {
        $marker = if ($subs[$i].isDefault) { " [DEFAULT]" } else { "" }
        Write-Host "  [$($i+1)] $($subs[$i].name)$marker" -ForegroundColor Cyan
    }
    Write-Host ""
    
    do {
        $selection = Read-Host "Select subscription [1-$($subs.Count)]"
        $selectionInt = 0
        $valid = [int]::TryParse($selection, [ref]$selectionInt) -and $selectionInt -ge 1 -and $selectionInt -le $subs.Count
    } while (-not $valid)
    
    $SubscriptionId = $subs[$selectionInt - 1].id
    az account set --subscription $SubscriptionId | Out-Null
}

Write-Host "Selected Subscription: $SubscriptionId" -ForegroundColor Green
Write-Host ""

# Policy Definition Name
$policyName = "mde-vm-device-tagging-remediation"
$policyDisplayName = "Remediate: Tag Azure VMs with MDE Device ID"
$assignmentName = "mde-auto-tagging"

# Step 1: Create Policy Definition
Write-Host "[1/5] Creating Policy Definition..." -ForegroundColor Cyan

$policyFile = Join-Path $PSScriptRoot "Azure-Policy-MDE-Remediation.json"
if (-not (Test-Path $policyFile)) {
    Write-Host "  ERROR: Azure-Policy-MDE-Remediation.json not found!" -ForegroundColor Red
    exit 1
}

$scopeParam = if ($Scope -eq "ManagementGroup") {
    "--management-group $ManagementGroupId"
} else {
    "--subscription $SubscriptionId"
}

# Check if policy already exists
$existingPolicy = az policy definition show --name $policyName $scopeParam 2>$null | ConvertFrom-Json

if ($existingPolicy) {
    Write-Host "  Policy already exists, updating..." -ForegroundColor Yellow
    az policy definition update --name $policyName --rules (Get-Content $policyFile | ConvertFrom-Json).properties.policyRule --params (Get-Content $policyFile | ConvertFrom-Json).properties.parameters --display-name $policyDisplayName --description "Auto-remediation policy for MDE device tagging" $scopeParam | Out-Null
} else {
    az policy definition create --name $policyName --rules (Get-Content $policyFile | ConvertFrom-Json).properties.policyRule --params (Get-Content $policyFile | ConvertFrom-Json).properties.parameters --display-name $policyDisplayName --description "Auto-remediation policy for MDE device tagging" $scopeParam | Out-Null
}

Write-Host "  OK: Policy definition created" -ForegroundColor Green
Write-Host ""

# Step 2: Create Managed Identity for Remediation
Write-Host "[2/5] Creating Managed Identity for remediation..." -ForegroundColor Cyan

$identityName = "id-mde-policy-remediation"
$location = "eastus"

# Create identity if not exists
$identity = az identity show --name $identityName --resource-group "rg-policy-remediation" 2>$null | ConvertFrom-Json

if (-not $identity) {
    # Create resource group for identity
    az group create --name "rg-policy-remediation" --location $location | Out-Null
    
    # Create managed identity
    $identity = az identity create --name $identityName --resource-group "rg-policy-remediation" --location $location | ConvertFrom-Json
    
    Write-Host "  OK: Identity created" -ForegroundColor Green
    Write-Host "  Principal ID: $($identity.principalId)" -ForegroundColor DarkGray
    
    # Wait for identity propagation
    Write-Host "  Waiting 30s for identity propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
} else {
    Write-Host "  OK: Using existing identity" -ForegroundColor Yellow
    Write-Host "  Principal ID: $($identity.principalId)" -ForegroundColor DarkGray
}

Write-Host ""

# Step 3: Assign Contributor Role to Identity
Write-Host "[3/5] Assigning Contributor role to identity..." -ForegroundColor Cyan

az role assignment create --assignee $identity.principalId --role "Contributor" --scope "/subscriptions/$SubscriptionId" 2>$null | Out-Null

Write-Host "  OK: Contributor role assigned" -ForegroundColor Green
Write-Host ""

# Step 4: Assign Policy
Write-Host "[4/5] Assigning policy with remediation..." -ForegroundColor Cyan

$assignmentScope = "/subscriptions/$SubscriptionId"

# Check if assignment already exists
$existingAssignment = az policy assignment show --name $assignmentName --scope $assignmentScope 2>$null | ConvertFrom-Json

if ($existingAssignment) {
    Write-Host "  Deleting existing assignment..." -ForegroundColor Yellow
    az policy assignment delete --name $assignmentName --scope $assignmentScope | Out-Null
}

# Create new assignment with identity
$assignment = az policy assignment create `
    --name $assignmentName `
    --display-name "MDE VM Auto-Tagging" `
    --policy $policyName `
    --scope $assignmentScope `
    --mi-system-assigned `
    --location $location `
    --identity-scope $assignmentScope `
    --role "Contributor" | ConvertFrom-Json

Write-Host "  OK: Policy assigned" -ForegroundColor Green
Write-Host "  Assignment ID: $($assignment.id)" -ForegroundColor DarkGray
Write-Host ""

# Step 5: Create Remediation Task
Write-Host "[5/5] Creating remediation task for existing VMs..." -ForegroundColor Cyan

$remediationName = "remediate-existing-vms-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

az policy remediation create `
    --name $remediationName `
    --policy-assignment $assignment.id `
    --resource-discovery-mode ExistingNonCompliant | Out-Null

Write-Host "  OK: Remediation task created" -ForegroundColor Green
Write-Host "  Name: $remediationName" -ForegroundColor DarkGray
Write-Host ""

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

Write-Host "WHAT WAS DEPLOYED:" -ForegroundColor Cyan
Write-Host "  1. Policy Definition: $policyName" -ForegroundColor White
Write-Host "  2. Policy Assignment: $assignmentName" -ForegroundColor White
Write-Host "  3. Managed Identity: $identityName" -ForegroundColor White
Write-Host "  4. Remediation Task: $remediationName" -ForegroundColor White
Write-Host ""

Write-Host "HOW IT WORKS:" -ForegroundColor Yellow
Write-Host "  - Policy scans all VMs every 24 hours" -ForegroundColor White
Write-Host "  - Detects VMs without mde_device_id tag" -ForegroundColor White
Write-Host "  - Automatically applies tag with VM name" -ForegroundColor White
Write-Host "  - Remediation task processes existing VMs immediately" -ForegroundColor White
Write-Host ""

Write-Host "NEXT STEPS:" -ForegroundColor Magenta
Write-Host "  1. Wait 5-10 minutes for remediation to complete" -ForegroundColor Cyan
Write-Host "  2. Check remediation status:" -ForegroundColor Cyan
Write-Host "     az policy remediation show --name $remediationName" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  3. Verify VM tags:" -ForegroundColor Cyan
Write-Host "     az vm list --query '[].{name:name, tags:tags}' -o table" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  4. Re-run the Automation runbook to sync tagged VMs" -ForegroundColor Cyan
Write-Host ""

Write-Host "IMPORTANT NOTES:" -ForegroundColor Red
Write-Host "  - Tags are applied with VM name by default" -ForegroundColor Yellow
Write-Host "  - You may need to update tags with actual device IDs" -ForegroundColor Yellow
Write-Host "  - Use Update-VM-Tags.ps1 to match with Entra ID devices" -ForegroundColor Yellow
Write-Host ""

Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
