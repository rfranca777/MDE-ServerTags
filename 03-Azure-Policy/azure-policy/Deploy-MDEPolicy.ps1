<#
================================================================================
DEVELOPED BY: Rafael França
PROJECT: MDE ServerTags — Community Edition
NOME: Deploy-MDEPolicy.ps1
================================================================================
OBJETIVO
  Script para criar e deployar Azure Policy customizada que aplica automaticamente
  Device Tags do Microsoft Defender for Endpoint em VMs Azure e Arc-enabled servers.

FUNCIONALIDADES
  - Cria Policy Definition no Azure
  - Cria Policy Assignment em Subscription ou Resource Group
  - Configura Managed Identity com permissões necessárias
  - Inicia Remediation Task para VMs existentes
  - Monitora o progresso de compliance

USO
  # Assignment na Subscription atual (key padrão: GROUP)
  .\Deploy-MDEPolicy.ps1 -MDETagValue "PRODUCAO" -AssignmentScope "Subscription"

  # Assignment com key customizada
  .\Deploy-MDEPolicy.ps1 -MDETagKey "Environment" -MDETagValue "PROD" -AssignmentScope "Subscription"

  # Assignment em Resource Group específico
  .\Deploy-MDEPolicy.ps1 -MDETagKey "Department" -MDETagValue "TI" -AssignmentScope "ResourceGroup" -ResourceGroupName "RG-Prod"

  # Modo audit (apenas reporta, não aplica)
  .\Deploy-MDEPolicy.ps1 -MDETagValue "DEV" -Effect "AuditIfNotExists"
================================================================================
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$MDETagKey = 'GROUP',

  [Parameter(Mandatory=$true)]
  [string]$MDETagValue,

  [Parameter(Mandatory=$false)]
  [ValidateSet('Subscription', 'ResourceGroup')]
  [string]$AssignmentScope = 'Subscription',

  [Parameter(Mandatory=$false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory=$false)]
  [ValidateSet('DeployIfNotExists', 'AuditIfNotExists', 'Disabled')]
  [string]$Effect = 'DeployIfNotExists',

  [Parameter(Mandatory=$false)]
  [string]$PolicyDefinitionPath = ".\azure-policy\policy-definition.json",

  [Parameter(Mandatory=$false)]
  [string]$Location = "brazilsouth",

  [switch]$SkipRemediation
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Magenta
Write-Host "Deploy Azure Policy - MDE Device Tag Automation" -ForegroundColor Magenta
Write-Host "Developed by: Rafael França | MDE ServerTags" -ForegroundColor Magenta
Write-Host "=" * 80 -ForegroundColor Magenta
Write-Host ""

# Validações
if ($AssignmentScope -eq 'ResourceGroup' -and [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  throw "ResourceGroupName é obrigatório quando AssignmentScope = 'ResourceGroup'"
}

if (-not (Test-Path $PolicyDefinitionPath)) {
  throw "Arquivo de definição não encontrado: $PolicyDefinitionPath"
}

# ===== PASSO 1: Conectar ao Azure =====
Write-Info "Conectando ao Azure..."
try {
  $context = Get-AzContext
  if (-not $context) {
    Connect-AzAccount
    $context = Get-AzContext
  }
  Write-Ok "Conectado: $($context.Account.Id)"
  Write-Ok "Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))"
} catch {
  throw "Falha ao conectar ao Azure: $_"
}

$subscriptionId = $context.Subscription.Id

# ===== PASSO 2: Criar Policy Definition =====
Write-Host ""
Write-Info "Criando Policy Definition..."

$policyName = "deploy-mde-device-tag-$(Get-Date -Format 'yyyyMMdd')"
$policyDisplayName = "Deploy MDE Device Tag - $MDETagValue"
$policyDescription = "Automatically applies Microsoft Defender for Endpoint Device Tag '$MDETagValue' to Azure VMs and Arc-enabled servers"

try {
  # Verificar se já existe
  $existingPolicy = Get-AzPolicyDefinition -Name $policyName -ErrorAction SilentlyContinue
  
  if ($existingPolicy) {
    Write-Warn "Policy Definition já existe: $policyName"
    Write-Info "Atualizando definição existente..."
    $policyDef = Set-AzPolicyDefinition `
      -Name $policyName `
      -DisplayName $policyDisplayName `
      -Description $policyDescription `
      -Policy (Get-Content $PolicyDefinitionPath -Raw) `
      -Mode Indexed `
      -Metadata '{"category":"Security","version":"1.0.0"}'
  } else {
    $policyDef = New-AzPolicyDefinition `
      -Name $policyName `
      -DisplayName $policyDisplayName `
      -Description $policyDescription `
      -Policy (Get-Content $PolicyDefinitionPath -Raw) `
      -Mode Indexed `
      -Metadata '{"category":"Security","version":"1.0.0"}'
  }
  
  Write-Ok "Policy Definition: $($policyDef.Name)"
  Write-Ok "ResourceId: $($policyDef.ResourceId)"
} catch {
  throw "Falha ao criar Policy Definition: $_"
}

# ===== PASSO 3: Determinar Scope do Assignment =====
Write-Host ""
Write-Info "Determinando scope do assignment..."

if ($AssignmentScope -eq 'Subscription') {
  $assignmentScope = "/subscriptions/$subscriptionId"
  Write-Ok "Scope: Subscription inteira"
} else {
  $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
  $assignmentScope = $rg.ResourceId
  Write-Ok "Scope: Resource Group '$ResourceGroupName'"
}

# ===== PASSO 4: Criar Policy Assignment =====
Write-Host ""
Write-Info "Criando Policy Assignment..."

$assignmentName = "mde-tag-$($MDETagValue.ToLower())-$(Get-Date -Format 'yyyyMMdd')"
$assignmentDisplayName = "MDE Device Tag - $MDETagValue"
$assignmentDescription = "Aplica automaticamente a TAG '$MDETagValue' do MDE"

try {
  $assignment = New-AzPolicyAssignment `
    -Name $assignmentName `
    -DisplayName $assignmentDisplayName `
    -Description $assignmentDescription `
    -PolicyDefinition $policyDef `
    -Scope $assignmentScope `
    -PolicyParameterObject @{
      mdeTagKey = $MDETagKey
      mdeTagValue = $MDETagValue
      effect = $Effect
    } `
    -Location $Location `
    -IdentityType "SystemAssigned"
  
  Write-Ok "Policy Assignment criado: $($assignment.Name)"
  Write-Ok "Managed Identity: $($assignment.Identity.PrincipalId)"
} catch {
  throw "Falha ao criar Policy Assignment: $_"
}

# ===== PASSO 5: Atribuir Permissões =====
Write-Host ""
Write-Info "Atribuindo permissões à Managed Identity..."

$principalId = $assignment.Identity.PrincipalId
$maxRetries = 5
$retryCount = 0

do {
  try {
    New-AzRoleAssignment `
      -ObjectId $principalId `
      -RoleDefinitionName "Virtual Machine Contributor" `
      -Scope $assignmentScope `
      -ErrorAction Stop | Out-Null
    
    Write-Ok "Permissão 'Virtual Machine Contributor' atribuída"
    break
  } catch {
    $retryCount++
    if ($retryCount -ge $maxRetries) {
      Write-Err "Falha ao atribuir permissões após $maxRetries tentativas"
      Write-Warn "Você pode precisar atribuir manualmente:"
      Write-Host "  New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName 'Virtual Machine Contributor' -Scope $assignmentScope" -ForegroundColor Yellow
      break
    }
    Write-Warn "Tentativa $retryCount/$maxRetries falhou. Aguardando propagação da Managed Identity..."
    Start-Sleep -Seconds 30
  }
} while ($retryCount -lt $maxRetries)

# ===== PASSO 6: Aguardar Propagação =====
Write-Host ""
Write-Info "Aguardando propagação de permissões (60 segundos)..."
Start-Sleep -Seconds 60

# ===== PASSO 7: Trigger Compliance Scan =====
Write-Host ""
Write-Info "Iniciando scan de compliance..."

try {
  if ($AssignmentScope -eq 'Subscription') {
    Start-AzPolicyComplianceScan -AsJob | Out-Null
  } else {
    Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -AsJob | Out-Null
  }
  Write-Ok "Scan de compliance iniciado (em background)"
} catch {
  Write-Warn "Falha ao iniciar scan: $_"
}

# ===== PASSO 8: Remediation Task =====
if (-not $SkipRemediation -and $Effect -eq 'DeployIfNotExists') {
  Write-Host ""
  Write-Info "Iniciando Remediation Task para recursos existentes..."
  
  try {
    $remediationName = "remediate-mde-tags-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    $remediation = Start-AzPolicyRemediation `
      -Name $remediationName `
      -PolicyAssignmentId $assignment.ResourceId `
      -Scope $assignmentScope `
      -ResourceDiscoveryMode ReEvaluateCompliance
    
    Write-Ok "Remediation Task criada: $($remediation.Name)"
    Write-Info "Status: $($remediation.ProvisioningState)"
    Write-Info "Total de recursos: $($remediation.DeploymentSummary.TotalDeployments)"
    
    Write-Host ""
    Write-Info "Monitorando remediação (30 segundos)..."
    Start-Sleep -Seconds 30
    
    $status = Get-AzPolicyRemediation -Name $remediationName -Scope $assignmentScope
    Write-Info "Sucesso: $($status.DeploymentSummary.SuccessfulDeployments)"
    Write-Info "Falha: $($status.DeploymentSummary.FailedDeployments)"
    
  } catch {
    Write-Warn "Falha ao criar Remediation Task: $_"
    Write-Info "Você pode criar manualmente depois com:"
    Write-Host "  Start-AzPolicyRemediation -PolicyAssignmentId '$($assignment.ResourceId)' -Scope '$assignmentScope'" -ForegroundColor Yellow
  }
}

# ===== RESUMO FINAL =====
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Green
Write-Host "DEPLOYMENT CONCLUÍDO COM SUCESSO!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Green
Write-Host ""
Write-Host "Informações do Deployment:" -ForegroundColor Cyan
Write-Host "  Policy Definition:  $($policyDef.Name)" -ForegroundColor White
Write-Host "  Policy Assignment:  $($assignment.Name)" -ForegroundColor White
Write-Host "  MDE Tag Key:        $MDETagKey" -ForegroundColor White
Write-Host "  MDE Tag Value:      $MDETagValue" -ForegroundColor White
Write-Host "  Effect:             $Effect" -ForegroundColor White
Write-Host "  Scope:              $assignmentScope" -ForegroundColor White
Write-Host "  Managed Identity:   $($assignment.Identity.PrincipalId)" -ForegroundColor White
Write-Host ""
Write-Host "Próximos Passos:" -ForegroundColor Cyan
Write-Host "  1. Aguarde 5-10 minutos para avaliação inicial de compliance" -ForegroundColor White
Write-Host "  2. Verifique compliance: Portal Azure → Policy → Compliance" -ForegroundColor White
Write-Host "  3. Novas VMs serão automaticamente taggeadas na criação" -ForegroundColor White
Write-Host "  4. VMs existentes serão remediadas pela Remediation Task" -ForegroundColor White
Write-Host ""
Write-Host "Verificar Compliance:" -ForegroundColor Cyan
Write-Host "  Get-AzPolicyStateSummary -PolicyAssignmentName '$($assignment.Name)'" -ForegroundColor Yellow
Write-Host ""
Write-Host "Monitorar Remediation:" -ForegroundColor Cyan
Write-Host "  Get-AzPolicyRemediation -Scope '$assignmentScope' | Select Name, ProvisioningState" -ForegroundColor Yellow
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Green
