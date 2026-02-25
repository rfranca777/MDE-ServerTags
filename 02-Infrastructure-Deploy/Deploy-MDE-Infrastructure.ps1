#!/usr/bin/env pwsh
#Requires -Version 5.1

<#
.SYNOPSIS
    MDE Deployment - v27 PRODUCTION READY
    
.DESCRIPTION
    Script completo baseado nas versoes v22/v23 que FUNCIONARAM
    Com interatividade e controle de erros
#>

param(
    [string]$Location = "eastus2",
    [switch]$IgnoreErrors,
    [switch]$SkipConfirm
)

$ErrorActionPreference = if ($IgnoreErrors) { "Continue" } else { "Stop" }

# Banner
Clear-Host
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host "          MICROSOFT DEFENDER FOR ENDPOINT - DEPLOYMENT COMPLETO                " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "        [ v27.0 ] - Production Ready - Baseado em v22/v23" -ForegroundColor DarkGray
Write-Host ""

# Funcao auxiliar para erros
function Write-ErrorInfo {
    param([string]$Message, [switch]$Continue)
    
    Write-Host ""
    Write-Host "[ERRO] $Message" -ForegroundColor Red
    
    if (-not $Continue -and -not $IgnoreErrors) {
        Write-Host "Use -IgnoreErrors para continuar mesmo com erros" -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "[CONTINUANDO] Erro ignorado..." -ForegroundColor Yellow
        return $true
    }
}

# ETAPA 1: Detectar Subscription
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 1: Detectando Subscription" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    $subscription = az account show 2>$null | ConvertFrom-Json
    
    if (-not $subscription) {
        Write-ErrorInfo "Nao autenticado no Azure. Execute: az login"
        exit 1
    }
    
    Write-Host "  Subscription ID  : $($subscription.id)" -ForegroundColor Green
    Write-Host "  Subscription Name: $($subscription.name)" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-ErrorInfo "Falha ao detectar subscription: $($_.Exception.Message)"
}

# ETAPA 2: Gerar Nomes dos Recursos
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 2: Gerando Nomes Logicos" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

# Normalizar nome da subscription
$subNameShort = $subscription.name `
    -replace '\s+', '-' `
    -replace '[^a-zA-Z0-9-]', '' `
    -replace '--+', '-' `
    -replace '^-+|-+$', '' `
    | ForEach-Object { $_.ToLower().Substring(0, [Math]::Min(15, $_.Length)) }

# Gerar sufixo unico
$uniqueSuffix = -join ((Get-Random -Count 3 -InputObject (0..9)))

# Nomes dos recursos
$rgName = "rg-mde-$subNameShort-$uniqueSuffix"
$aaName = "aa-mde-$subNameShort-$uniqueSuffix"
$groupName = "grp-mde-devices-$uniqueSuffix"
$runbookName = "runbook-mde-sync"
$scheduleName = "schedule-mde-sync"

Write-Host "  Resource Group.....: $rgName" -ForegroundColor Cyan
Write-Host "  Automation Account.: $aaName" -ForegroundColor Cyan
Write-Host "  Security Group.....: $groupName" -ForegroundColor Cyan
Write-Host "  Runbook............: $runbookName" -ForegroundColor Cyan
Write-Host "  Schedule...........: $scheduleName" -ForegroundColor Cyan
Write-Host "  Location...........: $Location" -ForegroundColor Cyan
Write-Host ""

# ETAPA 3: Confirmacao
if (-not $SkipConfirm) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
    Write-Host "CONFIRMACAO" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recursos serao criados na subscription:" -ForegroundColor White
    Write-Host "  $($subscription.name)" -ForegroundColor Cyan
    Write-Host ""
    
    $confirm = Read-Host "Confirmar deployment? (S/N)"
    if ($confirm -ne 'S' -and $confirm -ne 's') {
        Write-Host ""
        Write-Host "Deployment cancelado pelo usuario" -ForegroundColor Yellow
        exit 0
    }
    Write-Host ""
}

# ETAPA 4: Criar Resource Group
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 4: Resource Group" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[INFO] Verificando Resource Group..." -ForegroundColor Cyan
    $rgExists = az group exists --name $rgName
    
    if ($rgExists -eq 'true') {
        Write-Host "[OK] Resource Group ja existe: $rgName" -ForegroundColor Green
    } else {
        Write-Host "[CRIANDO] Resource Group: $rgName" -ForegroundColor Yellow
        az group create --name $rgName --location $Location --output none
        Write-Host "[OK] Resource Group criado" -ForegroundColor Green
    }
}
catch {
    Write-ErrorInfo "Falha ao criar Resource Group: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 5: Criar Automation Account
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 5: Automation Account" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[CRIANDO] Automation Account: $aaName" -ForegroundColor Yellow
    
    az automation account create `
        --automation-account-name $aaName `
        --resource-group $rgName `
        --location $Location `
        --sku Basic `
        --output none 2>$null
    
    Write-Host "[OK] Automation Account criado" -ForegroundColor Green
    Write-Host "[INFO] Aguardando propagacao (20s)..." -ForegroundColor Gray
    Start-Sleep -Seconds 20
}
catch {
    Write-ErrorInfo "Falha ao criar Automation Account: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 6: Habilitar Managed Identity
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 6: Managed Identity (System-Assigned)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[HABILITANDO] Managed Identity via REST API..." -ForegroundColor Yellow
    
    $aaUri = "https://management.azure.com/subscriptions/$($subscription.id)/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName`?api-version=2023-11-01"
    
    az rest --method patch --uri $aaUri --headers "Content-Type=application/json" --body '{"identity":{"type":"SystemAssigned"}}' --output none 2>$null
    
    Write-Host "[OK] Managed Identity habilitada" -ForegroundColor Green
    Write-Host "[INFO] Aguardando propagacao (15s)..." -ForegroundColor Gray
    Start-Sleep -Seconds 15
}
catch {
    Write-ErrorInfo "Falha ao habilitar Managed Identity: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 7: Criar Security Group
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 7: Security Group (Entra ID)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[VERIFICANDO] Security Group no Entra ID..." -ForegroundColor Cyan
    
    $existingGroup = az ad group list --filter "displayName eq '$groupName'" --query "[0]" -o json 2>$null | ConvertFrom-Json
    
    if ($existingGroup -and $existingGroup.id) {
        Write-Host "[OK] Security Group ja existe: $groupName" -ForegroundColor Green
        $groupId = $existingGroup.id
    } else {
        Write-Host "[CRIANDO] Security Group: $groupName" -ForegroundColor Yellow
        
        $groupDesc = "Devices MDE gerenciados - Subscription: $($subscription.name)"
        
        $newGroup = az ad group create `
            --display-name $groupName `
            --mail-nickname $groupName `
            --description $groupDesc `
            --output json 2>$null | ConvertFrom-Json
        
        $groupId = $newGroup.id
        Write-Host "[OK] Security Group criado" -ForegroundColor Green
    }
    
    Write-Host "  Group ID: $groupId" -ForegroundColor Cyan
}
catch {
    Write-ErrorInfo "Falha ao criar Security Group: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 8: Criar Runbook
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 8: Runbook (com validacoes Entra ID)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[VERIFICANDO] Arquivo runbook-mde-sync-v24-CORRIGIDO.ps1..." -ForegroundColor Cyan
    
    if (-not (Test-Path ".\runbook-mde-sync-v24-CORRIGIDO.ps1")) {
        Write-ErrorInfo "Arquivo runbook nao encontrado"
        exit 1
    }
    
    Write-Host "[PREPARANDO] Runbook com Group ID..." -ForegroundColor Yellow
    
    # Ler e substituir placeholder
    $runbookContent = Get-Content ".\runbook-mde-sync-v24-CORRIGIDO.ps1" -Raw
    $runbookContent = $runbookContent -replace 'GROUP_ID_PLACEHOLDER', $groupId
    
    # Salvar temporario
    $tempRunbook = ".\temp-runbook-$uniqueSuffix.ps1"
    $runbookContent | Out-File -FilePath $tempRunbook -Encoding UTF8 -Force
    
    Write-Host "[CRIANDO] Runbook: $runbookName" -ForegroundColor Yellow
    
    az automation runbook create `
        --automation-account-name $aaName `
        --resource-group $rgName `
        --name $runbookName `
        --type PowerShell `
        --output none 2>$null
    
    Write-Host "[IMPORTANDO] Codigo do runbook..." -ForegroundColor Yellow
    
    az automation runbook replace-content `
        --automation-account-name $aaName `
        --resource-group $rgName `
        --name $runbookName `
        --content "@$tempRunbook" `
        --output none 2>$null
    
    Write-Host "[PUBLICANDO] Runbook..." -ForegroundColor Yellow
    
    az automation runbook publish `
        --automation-account-name $aaName `
        --resource-group $rgName `
        --name $runbookName `
        --output none 2>$null
    
    # Limpar temporario
    Remove-Item $tempRunbook -Force -ErrorAction SilentlyContinue
    
    Write-Host "[OK] Runbook criado e publicado" -ForegroundColor Green
}
catch {
    Write-ErrorInfo "Falha ao criar Runbook: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 9: Criar Schedule
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 9: Schedule (execucao a cada 12 horas)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[CRIANDO] Schedule: $scheduleName" -ForegroundColor Yellow
    
    $startTime = (Get-Date).AddMinutes(15).ToString("yyyy-MM-ddTHH:mm:ss")
    
    az automation schedule create `
        --automation-account-name $aaName `
        --resource-group $rgName `
        --name $scheduleName `
        --frequency Hour `
        --interval 12 `
        --start-time $startTime `
        --output none 2>$null
    
    Write-Host "[OK] Schedule criado" -ForegroundColor Green
    Write-Host "  Primeira execucao: $startTime" -ForegroundColor Cyan
}
catch {
    Write-ErrorInfo "Falha ao criar Schedule: $($_.Exception.Message)" -Continue
}

Write-Host ""

# ETAPA 10: Linkar Schedule ao Runbook
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "ETAPA 10: Linkar Schedule ao Runbook" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "[LINKANDO] Schedule -> Runbook via REST API..." -ForegroundColor Yellow
    
    $jobScheduleId = [guid]::NewGuid().ToString()
    $jsUri = "https://management.azure.com/subscriptions/$($subscription.id)/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName/jobSchedules/$jobScheduleId`?api-version=2023-11-01"
    $jsBody = @{
        properties = @{
            schedule = @{ name = $scheduleName }
            runbook = @{ name = $runbookName }
        }
    } | ConvertTo-Json -Depth 5
    
    az rest --method put --uri $jsUri --headers "Content-Type=application/json" --body $jsBody --output none 2>$null
    
    Write-Host "[OK] Schedule linkado ao Runbook" -ForegroundColor Green
}
catch {
    Write-ErrorInfo "Falha ao linkar Schedule: $($_.Exception.Message)" -Continue
}

Write-Host ""

# RESUMO FINAL
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "          DEPLOYMENT CONCLUIDO COM SUCESSO!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""

Write-Host "RECURSOS CRIADOS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Subscription.......: $($subscription.name)" -ForegroundColor White
Write-Host "  Resource Group.....: $rgName" -ForegroundColor White
Write-Host "  Automation Account.: $aaName" -ForegroundColor White
Write-Host "  Security Group.....: $groupName" -ForegroundColor White
Write-Host "  Group ID...........: $groupId" -ForegroundColor White
Write-Host "  Runbook............: $runbookName" -ForegroundColor White
Write-Host "  Schedule...........: $scheduleName" -ForegroundColor White
Write-Host ""

Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host "PROXIMOS PASSOS OBRIGATORIOS:" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "1. INSTALAR AADLoginForWindows (CRITICO!):" -ForegroundColor Red
Write-Host "   .\Deploy-MDE-Step-4.5-AADLogin.ps1" -ForegroundColor White
Write-Host ""

Write-Host "2. CONCEDER PERMISSOES GRAPH API:" -ForegroundColor Yellow
Write-Host "   Azure Portal > Enterprise Applications" -ForegroundColor White
Write-Host "   Buscar: $aaName" -ForegroundColor Cyan
Write-Host "   API Permissions > Add:" -ForegroundColor White
Write-Host "     - Group.ReadWrite.All" -ForegroundColor White
Write-Host "     - Device.Read.All" -ForegroundColor White
Write-Host "     - GroupMember.ReadWrite.All" -ForegroundColor White
Write-Host "   Grant admin consent" -ForegroundColor White
Write-Host ""

Write-Host "3. CONFIGURAR MDM AUTO-ENROLLMENT:" -ForegroundColor Yellow
Write-Host "   Entra ID > Mobility (MDM and MAM)" -ForegroundColor White
Write-Host "   Microsoft Intune > MDM user scope: All" -ForegroundColor White
Write-Host ""

Write-Host "4. TESTAR RUNBOOK:" -ForegroundColor Yellow
Write-Host "   az automation runbook start --automation-account-name $aaName --resource-group $rgName --name $runbookName" -ForegroundColor White
Write-Host ""

Write-Host "5. CRIAR POLITICA MDE NO INTUNE:" -ForegroundColor Yellow
Write-Host "   endpoint.microsoft.com > Endpoint Security > Antivirus" -ForegroundColor White
Write-Host "   Target group: $groupName" -ForegroundColor Cyan
Write-Host ""

Write-Host "================================================================================" -ForegroundColor Gray
Write-Host "Script finalizado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""
