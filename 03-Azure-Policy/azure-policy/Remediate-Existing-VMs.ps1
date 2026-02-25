<#
================================================================================
DEVELOPED BY: Rafael França
PROJECT: MDE ServerTags — Community Edition
NOME: Remediate-Existing-VMs.ps1
================================================================================
OBJETIVO
  Script para criar Remediation Tasks para VMs existentes que não estão em
  compliance com a Azure Policy de MDE Device Tag.

USO
  # Remediar todas as VMs da subscription
  .\Remediate-Existing-VMs.ps1 -PolicyAssignmentName "mde-tag-producao-20260121"

  # Remediar apenas Resource Group específico
  .\Remediate-Existing-VMs.ps1 -PolicyAssignmentName "mde-tag-producao-20260121" -ResourceGroupName "RG-Prod"

  # Monitorar remediação existente
  .\Remediate-Existing-VMs.ps1 -MonitorOnly -RemediationName "remediate-mde-tags-20260121-120000"
================================================================================
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$PolicyAssignmentName,

  [Parameter(Mandatory=$false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory=$false)]
  [switch]$MonitorOnly,

  [Parameter(Mandatory=$false)]
  [string]$RemediationName,

  [Parameter(Mandatory=$false)]
  [int]$MonitorIntervalSeconds = 30
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Magenta
Write-Host "Azure Policy Remediation - MDE Device Tag" -ForegroundColor Magenta
Write-Host "=" * 80 -ForegroundColor Magenta
Write-Host ""

# Conectar
$context = Get-AzContext
if (-not $context) {
  Connect-AzAccount
  $context = Get-AzContext
}
Write-Ok "Conectado: $($context.Subscription.Name)"

$subscriptionId = $context.Subscription.Id

if ($MonitorOnly) {
  # ===== MODO MONITOR =====
  if ([string]::IsNullOrWhiteSpace($RemediationName)) {
    throw "-RemediationName é obrigatório no modo -MonitorOnly"
  }
  
  Write-Info "Modo Monitor: $RemediationName"
  
  $scope = if ($ResourceGroupName) {
    (Get-AzResourceGroup -Name $ResourceGroupName).ResourceId
  } else {
    "/subscriptions/$subscriptionId"
  }
  
  Write-Info "Monitorando remediação (Ctrl+C para parar)...`n"
  
  try {
    do {
      $status = Get-AzPolicyRemediation -Name $RemediationName -Scope $scope -ErrorAction Stop
      
      $timestamp = Get-Date -Format 'HH:mm:ss'
      $successful = $status.DeploymentSummary.SuccessfulDeployments
      $failed = $status.DeploymentSummary.FailedDeployments
      $total = $status.DeploymentSummary.TotalDeployments
      $state = $status.ProvisioningState
      
      Write-Host "[$timestamp] Estado: $state | Sucesso: $successful/$total | Falha: $failed" -ForegroundColor Cyan
      
      if ($state -ne "Running") {
        Write-Host ""
        if ($state -eq "Succeeded") {
          Write-Ok "Remediation concluída com sucesso!"
        } else {
          Write-Warn "Remediation finalizada com estado: $state"
        }
        break
      }
      
      Start-Sleep -Seconds $MonitorIntervalSeconds
      
    } while ($true)
    
  } catch {
    Write-Warn "Erro ao monitorar: $_"
  }
  
  exit 0
}

# ===== MODO CRIAR REMEDIATION =====
if ([string]::IsNullOrWhiteSpace($PolicyAssignmentName)) {
  throw "-PolicyAssignmentName é obrigatório"
}

Write-Info "Buscando Policy Assignment: $PolicyAssignmentName"

# Buscar assignment
$assignment = Get-AzPolicyAssignment | Where-Object { $_.Name -eq $PolicyAssignmentName }

if (-not $assignment) {
  Write-Warn "Policy Assignment não encontrado. Listando disponíveis:"
  Get-AzPolicyAssignment | Where-Object { $_.Properties.DisplayName -like "*MDE*" } | 
    Select-Object Name, @{N='DisplayName';E={$_.Properties.DisplayName}}, @{N='Scope';E={$_.Properties.Scope}} |
    Format-Table -AutoSize
  exit 1
}

Write-Ok "Assignment encontrado: $($assignment.Properties.DisplayName)"

# Determinar scope
$scope = if ($ResourceGroupName) {
  (Get-AzResourceGroup -Name $ResourceGroupName).ResourceId
} else {
  $assignment.Properties.Scope
}

Write-Info "Scope da remediação: $scope"

# Verificar recursos não-compliant
Write-Host ""
Write-Info "Verificando recursos não-compliant..."

$nonCompliant = Get-AzPolicyState `
  -Filter "PolicyAssignmentId eq '$($assignment.ResourceId)' and ComplianceState eq 'NonCompliant'" `
  -Top 100

if (-not $nonCompliant) {
  Write-Ok "Nenhum recurso não-compliant encontrado!"
  Write-Info "Todos os recursos já estão em compliance."
  exit 0
}

Write-Warn "Recursos não-compliant encontrados: $($nonCompliant.Count)"
Write-Host ""
Write-Host "Exemplos de recursos que serão remediados:" -ForegroundColor Yellow
$nonCompliant | Select-Object -First 10 | ForEach-Object {
  Write-Host "  - $($_.ResourceId.Split('/')[-1]) ($($_.ResourceType))" -ForegroundColor Gray
}

if ($nonCompliant.Count -gt 10) {
  Write-Host "  ... e mais $($nonCompliant.Count - 10) recursos" -ForegroundColor Gray
}

# Confirmar
Write-Host ""
$confirm = Read-Host "Deseja iniciar a remediação destes recursos? (S/N)"
if ($confirm -ne 'S' -and $confirm -ne 's') {
  Write-Warn "Remediação cancelada pelo usuário."
  exit 0
}

# Criar Remediation Task
Write-Host ""
Write-Info "Criando Remediation Task..."

$remediationName = "remediate-mde-tags-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

try {
  $remediation = Start-AzPolicyRemediation `
    -Name $remediationName `
    -PolicyAssignmentId $assignment.ResourceId `
    -Scope $scope `
    -ResourceDiscoveryMode ReEvaluateCompliance
  
  Write-Ok "Remediation Task criada!"
  Write-Host ""
  Write-Host "Detalhes da Remediação:" -ForegroundColor Cyan
  Write-Host "  Nome:                $($remediation.Name)" -ForegroundColor White
  Write-Host "  Estado:              $($remediation.ProvisioningState)" -ForegroundColor White
  Write-Host "  Total de recursos:   $($remediation.DeploymentSummary.TotalDeployments)" -ForegroundColor White
  Write-Host "  Sucesso:             $($remediation.DeploymentSummary.SuccessfulDeployments)" -ForegroundColor White
  Write-Host "  Falha:               $($remediation.DeploymentSummary.FailedDeployments)" -ForegroundColor White
  
  # Oferecer monitoramento
  Write-Host ""
  $monitor = Read-Host "Deseja monitorar o progresso? (S/N)"
  
  if ($monitor -eq 'S' -or $monitor -eq 's') {
    Write-Info "Monitorando remediação (Ctrl+C para parar)...`n"
    
    do {
      Start-Sleep -Seconds $MonitorIntervalSeconds
      
      $status = Get-AzPolicyRemediation -Name $remediationName -Scope $scope
      
      $timestamp = Get-Date -Format 'HH:mm:ss'
      $successful = $status.DeploymentSummary.SuccessfulDeployments
      $failed = $status.DeploymentSummary.FailedDeployments
      $total = $status.DeploymentSummary.TotalDeployments
      $state = $status.ProvisioningState
      
      Write-Host "[$timestamp] Estado: $state | Sucesso: $successful/$total | Falha: $failed" -ForegroundColor Cyan
      
      if ($state -ne "Running") {
        Write-Host ""
        if ($state -eq "Succeeded") {
          Write-Ok "Remediação concluída com sucesso!"
        } else {
          Write-Warn "Remediação finalizada com estado: $state"
        }
        break
      }
      
    } while ($true)
  } else {
    Write-Host ""
    Write-Info "Para monitorar depois, execute:"
    Write-Host "  .\Remediate-Existing-VMs.ps1 -MonitorOnly -RemediationName '$remediationName'" -ForegroundColor Yellow
  }
  
} catch {
  Write-Warn "Erro ao criar Remediation Task: $_"
  exit 1
}

Write-Host ""
Write-Ok "Processo concluído!"
