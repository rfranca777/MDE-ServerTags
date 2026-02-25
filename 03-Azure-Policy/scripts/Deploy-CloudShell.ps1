<#
.SYNOPSIS
    Azure MDE Sync - Cloud Shell Edicao v8.3
.DESCRIPTION
    CLOUD SHELL OTIMIZADO - Deploy completo com verbosidade alta
    Projetado especificamente para limitacoes do Azure Cloud Shell
.NOTES
    Author: Rafael França
    Versao: 8.3.0-CloudShell-Portuguese
    Data: 2026-01-26
    
    Otimizacoes Cloud Shell:
    - Comandos nativos Azure CLI apenas
    - Retry inteligente para operacoes async
    - Parse JSON robusto com temp files
    - Validacao de exit code em operacoes criticas
    - Verbosidade alta para debug
#>

$ErrorActionPreference = "Continue"
$ScriptVersion = "8.3.0-CloudShell-PT"
$ExecutionId = (New-Guid).Guid
$StartTime = Get-Date

Clear-Host
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  AZURE MDE SYNC - CLOUD SHELL PRODUCAO" -ForegroundColor Cyan
Write-Host "  Versao $ScriptVersion" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# FUNCAO HELPER - Parse JSON seguro (otimizado Cloud Shell)
# ============================================================================
function Get-AzJsonOutput {
    param([string]$Command)
    
    $maxAttempts = 2
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $attempt++
        try {
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            Write-Host "  [DEBUG] Executando: $Command" -ForegroundColor DarkGray
            Invoke-Expression "$Command 2>`$null" | Out-File -FilePath $tempFile -Encoding UTF8 -Force
            
            if (Test-Path $tempFile) {
                $jsonContent = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                
                if (-not [string]::IsNullOrWhiteSpace($jsonContent)) {
                    $parsed = $jsonContent | ConvertFrom-Json -ErrorAction Stop
                    Write-Host "  [DEBUG] JSON parseado com sucesso" -ForegroundColor DarkGray
                    return $parsed
                }
            }
        }
        catch {
            if ($attempt -ge $maxAttempts) {
                Write-Host "  AVISO: Falha ao parsear JSON apos $maxAttempts tentativas" -ForegroundColor Yellow
                return $null
            }
            Write-Host "  [DEBUG] Tentativa $attempt falhou, tentando novamente..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 2
        }
        finally {
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    return $null
}

# ============================================================================
# PASSO 1: SELECAO DE SUBSCRIPTION
# ============================================================================
Write-Host "--- [1/3] SELECAO DE SUBSCRIPTION ---" -ForegroundColor Yellow
Write-Host ""

# Obter conta atual
Write-Host "Verificando login Azure..." -ForegroundColor Gray
$account = Get-AzJsonOutput -Command "az account show --output json"

if (-not $account) {
    Write-Host "ERRO: Nao esta logado no Azure ou falha ao obter info da conta" -ForegroundColor Red
    Write-Host "Cloud Shell deve estar auto-autenticado." -ForegroundColor Yellow
    Write-Host "Tente executar: az account show" -ForegroundColor Yellow
    exit 1
}

Write-Host "Logado como: $($account.user.name)" -ForegroundColor Green
Write-Host ""

# Obter todas subscriptions
Write-Host "Carregando subscriptions..." -ForegroundColor Gray
$subs = Get-AzJsonOutput -Command "az account list --output json"

if (-not $subs -or $subs.Count -eq 0) {
    Write-Host "ERRO: Nenhuma subscription encontrada!" -ForegroundColor Red
    exit 1
}

Write-Host "Subscriptions disponiveis:" -ForegroundColor Yellow
for ($i = 0; $i -lt $subs.Count; $i++) {
    $marker = if ($subs[$i].id -eq $account.id) { " [ATUAL]" } else { "" }
    Write-Host "  [$($i+1)] $($subs[$i].name)$marker" -ForegroundColor Cyan
    Write-Host "       ID: $($subs[$i].id)" -ForegroundColor DarkGray
}
Write-Host ""

do {
    $selection = Read-Host "Selecione a subscription [1-$($subs.Count)]"
    $selectionInt = 0
    $valid = [int]::TryParse($selection, [ref]$selectionInt) -and $selectionInt -ge 1 -and $selectionInt -le $subs.Count
    if (-not $valid) { Write-Host "ERRO: Selecao invalida" -ForegroundColor Red }
} while (-not $valid)

$selectedSub = $subs[$selectionInt - 1]
az account set --subscription $selectedSub.id 2>$null

$SubscriptionId = $selectedSub.id
$SubscriptionName = $selectedSub.name

Write-Host ""
Write-Host "SELECIONADO: $SubscriptionName" -ForegroundColor Green
Write-Host ""

# ============================================================================
# PASSO 2: CONFIGURACAO
# ============================================================================
Write-Host "--- [2/3] CONFIGURACAO ---" -ForegroundColor Yellow
Write-Host ""

$rgInput = Read-Host "Resource Group (padrao: rg-mde-automation-prod)"
$ResourceGroupName = if ([string]::IsNullOrWhiteSpace($rgInput)) { "rg-mde-automation-prod" } else { $rgInput }

$locInput = Read-Host "Localizacao (padrao: eastus)"
$Location = if ([string]::IsNullOrWhiteSpace($locInput)) { "eastus" } else { $locInput }

$schedInput = Read-Host "Intervalo do agendamento em horas (padrao: 1)"
$ScheduleIntervalHours = if ([string]::IsNullOrWhiteSpace($schedInput)) { 1 } else { [int]$schedInput }

$arcInput = Read-Host "Incluir VMs Azure Arc? (S/n - padrao: S)"
$IncludeArc = if ($arcInput -eq 'n' -or $arcInput -eq 'N') { $false } else { $true }

# Nome do grupo = Nome da subscription (AUTOMATICO)
$GroupDisplayName = $SubscriptionName
$mailNickname = ($GroupDisplayName -replace '[^a-zA-Z0-9]', '') + "-mde"

Write-Host ""
Write-Host "--- RESUMO DA CONFIGURACAO ---" -ForegroundColor Green
Write-Host "  Subscription     : $SubscriptionName" -ForegroundColor White
Write-Host "  Resource Group   : $ResourceGroupName" -ForegroundColor White
Write-Host "  Localizacao      : $Location" -ForegroundColor White
Write-Host "  Grupo Entra ID   : $GroupDisplayName (auto)" -ForegroundColor Yellow
Write-Host "  Agendamento      : A cada $ScheduleIntervalHours hora(s)" -ForegroundColor White
Write-Host "  Incluir Arc      : $IncludeArc" -ForegroundColor White
Write-Host ""

$confirm = Read-Host "Confirmar deploy? (S/n)"
if ($confirm -eq 'n' -or $confirm -eq 'N') {
    Write-Host "Deploy cancelado" -ForegroundColor Red
    exit 0
}

# ============================================================================
# PASSO 3: DEPLOYMENT
# ============================================================================
Write-Host ""
Write-Host "--- [3/3] INICIANDO DEPLOYMENT ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "Execution ID: $ExecutionId" -ForegroundColor DarkGray
Write-Host ""

# ============================================================================
# [1/10] RESOURCE GROUP
# ============================================================================
Write-Host "[1/10] Criando Resource Group..." -ForegroundColor Cyan
try {
    Write-Host "  [DEBUG] Verificando existencia do RG..." -ForegroundColor DarkGray
    $rgExists = az group exists --name $ResourceGroupName 2>$null
    
    if ($rgExists -ne "true") {
        Write-Host "  [DEBUG] Criando RG com tags obrigatorias..." -ForegroundColor DarkGray
        az group create `
            --name $ResourceGroupName `
            --location $Location `
            --tags created_by="Seg Info" squad_owner="Seg info" cod_budget="SEG-0012" cost_center="72060104" `
            --only-show-errors 2>$null | Out-Null
        Write-Host "  [INFO] Tags aplicadas: created_by, squad_owner, cod_budget, cost_center" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] Resource Group existe, atualizando tags..." -ForegroundColor Gray
        az group update `
            --name $ResourceGroupName `
            --tags created_by="Seg Info" squad_owner="Seg info" cod_budget="SEG-0012" cost_center="72060104" `
            --only-show-errors 2>$null | Out-Null
        Write-Host "  [INFO] Tags atualizadas" -ForegroundColor Green
    }
    Write-Host "  OK: $ResourceGroupName" -ForegroundColor Green
}
catch {
    Write-Host "  ERRO: Falha ao criar resource group" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [2/10] AUTOMATION ACCOUNT
# ============================================================================
Write-Host "[2/10] Criando Automation Account..." -ForegroundColor Cyan
try {
    $aaName = "aa-mde-sync-$(Get-Random -Minimum 1000 -Maximum 9999)"
    
    # Passo 1: Criar automation account SEM identity
    Write-Host "  [PASSO 1] Criando $aaName..." -ForegroundColor Gray
    Write-Host "  [DEBUG] Resource Group: $ResourceGroupName" -ForegroundColor DarkGray
    Write-Host "  [DEBUG] Location: $Location" -ForegroundColor DarkGray
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $createCmd = "az automation account create --resource-group `"$ResourceGroupName`" --name `"$aaName`" --location `"$Location`" --sku Basic --output json"
    
    Write-Host "  [DEBUG] Executando: $createCmd" -ForegroundColor DarkGray
    Invoke-Expression "$createCmd > `"$tempFile`" 2>&1"
    $exitCode = $LASTEXITCODE
    $output = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    
    Write-Host "  [DEBUG] Exit code: $exitCode" -ForegroundColor DarkGray
    
    if ($exitCode -ne 0) {
        Write-Host "  ERRO: Falha ao criar automation account" -ForegroundColor Red
        if ($output) { 
            Write-Host "  ERRO: $output" -ForegroundColor Yellow 
        }
        exit 1
    }
    
    Write-Host "  OK: Automation Account criado" -ForegroundColor Green
    
    # Passo 2: Atribuir managed identity (comando separado e VERBOSE)
    Write-Host "  [PASSO 2] Atribuindo managed identity..." -ForegroundColor Gray
    
    $identityTempFile = [System.IO.Path]::GetTempFileName()
    $identityCmd = "az automation account update --resource-group `"$ResourceGroupName`" --name `"$aaName`" --assign-identity --output json"
    
    Write-Host "  [DEBUG] Executando: $identityCmd" -ForegroundColor DarkGray
    Invoke-Expression "$identityCmd > `"$identityTempFile`" 2>&1"
    $identityExitCode = $LASTEXITCODE
    $identityOutput = Get-Content $identityTempFile -Raw -ErrorAction SilentlyContinue
    Remove-Item $identityTempFile -Force -ErrorAction SilentlyContinue
    
    Write-Host "  [DEBUG] Identity exit code: $identityExitCode" -ForegroundColor DarkGray
    
    if ($identityExitCode -ne 0) {
        Write-Host "  ERRO: Falha ao atribuir managed identity (exit code: $identityExitCode)" -ForegroundColor Red
        if ($identityOutput) {
            Write-Host "  ERRO: $identityOutput" -ForegroundColor Yellow
        }
        Write-Host "  SOLUCAO: Tente atribuir manualmente via portal:" -ForegroundColor Yellow
        Write-Host "    1. Va para: Automation Accounts > $aaName" -ForegroundColor Cyan
        Write-Host "    2. Identity > System assigned > Status = On" -ForegroundColor Cyan
        exit 1
    }
    
    Write-Host "  OK: Managed identity atribuida" -ForegroundColor Green
    
    # Passo 3: Aguardar e fazer retry para obter principal ID
    Write-Host "  [PASSO 3] Aguardando provisionamento da identity..." -ForegroundColor Gray
    $principalId = $null
    $maxRetries = 12
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries -and [string]::IsNullOrWhiteSpace($principalId)) {
        Start-Sleep -Seconds 5
        $retryCount++
        Write-Host "  [DEBUG] Tentativa $retryCount/$maxRetries..." -ForegroundColor DarkGray
        
        $aaInfo = Get-AzJsonOutput -Command "az automation account show --resource-group $ResourceGroupName --name $aaName --output json"
        
        if ($aaInfo -and $aaInfo.identity -and $aaInfo.identity.principalId) {
            $principalId = $aaInfo.identity.principalId
            Write-Host "  OK: Managed Identity provisionada!" -ForegroundColor Green
            Write-Host "  [INFO] Principal ID: $principalId" -ForegroundColor DarkGray
            break
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        Write-Host "  ERRO: Managed identity nao ficou pronta apos $($maxRetries * 5) segundos" -ForegroundColor Red
        Write-Host "  SOLUCAO: Aguarde e execute:" -ForegroundColor Yellow
        Write-Host "  az automation account show --resource-group $ResourceGroupName --name $aaName --query identity.principalId -o tsv" -ForegroundColor Cyan
        exit 1
    }
    
    Write-Host "  OK: $aaName" -ForegroundColor Green
    Write-Host "  Identity: $principalId" -ForegroundColor DarkGray
}
catch {
    Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [3/10] MODULO Az.Accounts
# ============================================================================
Write-Host "[3/10] Instalando modulo Az.Accounts (tipicamente 5-8 min)..." -ForegroundColor Cyan
Write-Host "  Este e o passo mais demorado - Cloud Shell permanecera ativo" -ForegroundColor Gray
try {
    # Criar modulo com verificacao de erro
    Write-Host "  [DEBUG] Executando: az automation module create..." -ForegroundColor DarkGray
    $moduleCmd = "az automation module create --resource-group `"$ResourceGroupName`" --automation-account-name `"$aaName`" --name Az.Accounts --content-link https://www.powershellgallery.com/api/v2/package/Az.Accounts --output none"
    Invoke-Expression "$moduleCmd 2>&1" | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao iniciar instalacao do modulo" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique permissoes no Automation Account" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  [INFO] Instalacao do modulo iniciada..." -ForegroundColor Green
    Write-Host "  [INFO] Monitorando estado (verificando a cada 30s)..." -ForegroundColor Gray
    
    $timeout = (Get-Date).AddMinutes(12)
    $lastStatus = ""
    $checkCount = 0
    
    while ((Get-Date) -lt $timeout) {
        Start-Sleep -Seconds 30
        $checkCount++
        
        Write-Host "  [DEBUG] Verificacao $checkCount..." -ForegroundColor DarkGray
        $moduleStatus = Get-AzJsonOutput -Command "az automation module show --resource-group $ResourceGroupName --automation-account-name $aaName --name Az.Accounts --output json"
        
        if (-not $moduleStatus) {
            Write-Host "  AVISO: Nao foi possivel verificar status do modulo (tentativa $checkCount)" -ForegroundColor Yellow
            continue
        }
        
        $currentStatus = $moduleStatus.provisioningState
        Write-Host "  [DEBUG] Status atual: $currentStatus" -ForegroundColor DarkGray
        
        if ($currentStatus -eq "Succeeded") {
            $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
            Write-Host "  OK: Modulo instalado com sucesso em $elapsed minutos!" -ForegroundColor Green
            break
        }
        elseif ($currentStatus -eq "Failed") {
            Write-Host "  ERRO: Instalacao do modulo falhou" -ForegroundColor Red
            Write-Host "  SOLUCAO: Verifique no portal: Automation Account > Modules > Az.Accounts" -ForegroundColor Yellow
            exit 1
        }
        elseif ($currentStatus -ne $lastStatus) {
            $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
            Write-Host "  Status: $currentStatus (apos $elapsed min)" -ForegroundColor Yellow
            $lastStatus = $currentStatus
        }
        else {
            # Mostrar progresso sem mudar linha
            Write-Host "." -NoNewline -ForegroundColor DarkGray
        }
    }
    
    # Verificar se houve timeout
    if ($moduleStatus.provisioningState -ne "Succeeded") {
        $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
        Write-Host "`n  AVISO: Modulo ainda provisionando apos $elapsed minutos" -ForegroundColor Yellow
        Write-Host "  Status atual: $($moduleStatus.provisioningState)" -ForegroundColor Yellow
        Write-Host "  Deployment continuara, mas runbook pode falhar ate modulo estar pronto" -ForegroundColor Yellow
        Write-Host "  Monitore no portal: Automation Account > Modules" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [4/10] RUNBOOK
# ============================================================================
Write-Host "[4/10] Criando Runbook..." -ForegroundColor Cyan
try {
    # Criar conteudo do runbook
    Write-Host "  [DEBUG] Gerando conteudo do runbook..." -ForegroundColor DarkGray
    $runbookContent = @'
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$GroupId,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeArc = $true
)

$ErrorActionPreference = "Continue"

Write-Output "[INICIO] Conectando com Managed Identity..."
Connect-AzAccount -Identity | Out-Null
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

Write-Output "[INFO] Obtendo VMs Azure..."
$vms = Get-AzVM -Status

if ($IncludeArc) {
    Write-Output "[INFO] Obtendo VMs Arc..."
    $arcVms = Get-AzConnectedMachine
}
else {
    $arcVms = @()
}

$allVmNames = @()
$allVmNames += $vms | ForEach-Object { $_.Name }
$allVmNames += $arcVms | ForEach-Object { $_.Name }

Write-Output "[INFO] Total de maquinas encontradas: $($allVmNames.Count)"

Write-Output "[INFO] Obtendo token Graph API..."
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

Write-Output "[INFO] Obtendo membros atuais do grupo..."
$membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
$currentMembers = @()

try {
    $response = Invoke-RestMethod -Uri $membersUri -Headers $headers -Method GET
    $currentMembers = $response.value
    Write-Output "[INFO] Membros atuais: $($currentMembers.Count)"
}
catch {
    Write-Output "[AVISO] Falha ao obter membros atuais: $_"
}

Write-Output "[INFO] Obtendo dispositivos Entra ID..."
$devicesUri = "https://graph.microsoft.com/v1.0/devices?`$select=displayName,id"
$allDevices = @()

try {
    $response = Invoke-RestMethod -Uri $devicesUri -Headers $headers -Method GET
    $allDevices = $response.value
    Write-Output "[INFO] Dispositivos encontrados: $($allDevices.Count)"
}
catch {
    Write-Output "[AVISO] Falha ao obter dispositivos: $_"
}

$added = 0
$skipped = 0
$errors = 0

Write-Output "[INFO] Processando maquinas..."
foreach ($vmName in $allVmNames) {
    $device = $allDevices | Where-Object { $_.displayName -eq $vmName }
    
    if ($device) {
        $isMember = $currentMembers | Where-Object { $_.id -eq $device.id }
        
        if (-not $isMember) {
            $addUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
            $body = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$($device.id)"
            } | ConvertTo-Json
            
            try {
                Invoke-RestMethod -Uri $addUri -Method POST -Headers $headers -Body $body | Out-Null
                Write-Output "[OK] Adicionado: $vmName"
                $added++
            }
            catch {
                Write-Output "[ERRO] Falha ao adicionar: $vmName ($_)"
                $errors++
            }
        }
        else {
            $skipped++
        }
    }
    else {
        Write-Output "[AVISO] Dispositivo nao encontrado no Entra ID: $vmName"
    }
}

Write-Output "[RESUMO] Adicionados=$added, Ignorados=$skipped, Erros=$errors, Total=$($allVmNames.Count)"
Write-Output "[FIM] Sincronizacao concluida"
'@
    
    # Salvar em arquivo temporario
    Write-Host "  [DEBUG] Salvando runbook em arquivo temporario..." -ForegroundColor DarkGray
    $runbookPath = "/tmp/Sync-VMs-Runbook-$ExecutionId.ps1"
    $runbookContent | Out-File -FilePath $runbookPath -Encoding UTF8 -Force
    
    if (-not (Test-Path $runbookPath)) {
        Write-Host "  ERRO: Falha ao criar arquivo do runbook" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [INFO] Arquivo criado: $runbookPath" -ForegroundColor DarkGray
    
    Write-Host "  [DEBUG] Criando objeto runbook..." -ForegroundColor DarkGray
    az automation runbook create `
        --resource-group $ResourceGroupName `
        --automation-account-name $aaName `
        --name "Sync-VMs-To-M365Group" `
        --type "PowerShell" `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao criar runbook (exit code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique permissoes no Automation Account" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  [DEBUG] Fazendo upload do conteudo do runbook..." -ForegroundColor DarkGray
    az automation runbook replace-content `
        --resource-group $ResourceGroupName `
        --automation-account-name $aaName `
        --name "Sync-VMs-To-M365Group" `
        --content "@$runbookPath" `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao fazer upload do conteudo (exit code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique tamanho do runbook e permissoes" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  [DEBUG] Publicando runbook..." -ForegroundColor DarkGray
    az automation runbook publish `
        --resource-group $ResourceGroupName `
        --automation-account-name $aaName `
        --name "Sync-VMs-To-M365Group" `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao publicar runbook (exit code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique estado do runbook no portal" -ForegroundColor Yellow
        exit 1
    }
    
    # Limpar arquivo temporario
    Write-Host "  [DEBUG] Limpando arquivo temporario..." -ForegroundColor DarkGray
    Remove-Item $runbookPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "  OK: Runbook criado e publicado" -ForegroundColor Green
}
catch {
    Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [5/10] GRUPO ENTRA ID
# ============================================================================
Write-Host "[5/10] Criando Grupo Entra ID '$GroupDisplayName'..." -ForegroundColor Cyan
try {
    # Obter token de acesso
    Write-Host "  [DEBUG] Obtendo token Graph API..." -ForegroundColor DarkGray
    $tokenInfo = Get-AzJsonOutput -Command "az account get-access-token --resource https://graph.microsoft.com --output json"
    $token = $tokenInfo.accessToken
    Write-Host "  [DEBUG] Token obtido com sucesso" -ForegroundColor DarkGray
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    Write-Host "  [DEBUG] Preparando body do grupo..." -ForegroundColor DarkGray
    $groupBody = @{
        displayName     = $GroupDisplayName
        mailEnabled     = $false
        mailNickname    = $mailNickname
        securityEnabled = $true
        description     = "Dispositivos MDE gerenciados automaticamente para: $SubscriptionName"
    } | ConvertTo-Json
    
    try {
        Write-Host "  [DEBUG] Criando grupo via Graph API..." -ForegroundColor DarkGray
        $response = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/groups" `
            -Method POST `
            -Headers $headers `
            -Body $groupBody
        
        $groupId = $response.id
        Write-Host "  OK: Grupo criado" -ForegroundColor Green
    }
    catch {
        Write-Host "  [INFO] Grupo pode existir, pesquisando..." -ForegroundColor Yellow
        $searchUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$GroupDisplayName'"
        Write-Host "  [DEBUG] Pesquisando: $searchUri" -ForegroundColor DarkGray
        $searchResponse = Invoke-RestMethod -Uri $searchUri -Headers $headers -Method GET
        
        if ($searchResponse.value.Count -gt 0) {
            $groupId = $searchResponse.value[0].id
            Write-Host "  OK: Usando grupo existente" -ForegroundColor Green
        }
        else {
            Write-Host "  ERRO: Falha ao criar ou encontrar grupo" -ForegroundColor Red
            Write-Host "  SOLUCAO: Verifique permissoes Group.ReadWrite.All" -ForegroundColor Yellow
            exit 1
        }
    }
    
    Write-Host "  [INFO] ID: $groupId" -ForegroundColor DarkGray
}
catch {
    Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [6/10] RBAC READER
# ============================================================================
Write-Host "[6/10] Atribuindo role Reader..." -ForegroundColor Cyan
try {
    Write-Host "  [DEBUG] Atribuindo ao principal: $principalId" -ForegroundColor Gray
    
    $roleCmd = "az role assignment create --assignee-object-id `"$principalId`" --assignee-principal-type ServicePrincipal --role Reader --scope /subscriptions/$SubscriptionId --output none"
    Write-Host "  [DEBUG] Executando: az role assignment create..." -ForegroundColor DarkGray
    Invoke-Expression "$roleCmd 2>&1" | Out-Null
    
    # Verificar se atribuicao funcionou (ignorar se ja existe)
    Write-Host "  [DEBUG] Exit code: $LASTEXITCODE" -ForegroundColor DarkGray
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) {
        Write-Host "  OK: Role Reader atribuida" -ForegroundColor Green
    }
    else {
        Write-Host "  AVISO: Atribuicao retornou codigo $LASTEXITCODE (pode ja existir)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  AVISO: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# ============================================================================
# [7/10] PERMISSOES GRAPH API
# ============================================================================
Write-Host "[7/10] Atribuindo permissoes Graph API..." -ForegroundColor Cyan
try {
    Write-Host "  [DEBUG] Obtendo service principal do Microsoft Graph..." -ForegroundColor Gray
    
    # Obter Graph service principal com retry
    $graphSP = $null
    $retryCount = 0
    while ($retryCount -lt 3 -and -not $graphSP) {
        $graphSP = Get-AzJsonOutput -Command "az ad sp list --filter `"displayName eq 'Microsoft Graph'`" --query [0] --output json"
        if (-not $graphSP) {
            $retryCount++
            if ($retryCount -lt 3) {
                Write-Host "  [DEBUG] Retry $retryCount/3..." -ForegroundColor Gray
                Start-Sleep -Seconds 5
            }
        }
    }
    
    if (-not $graphSP) {
        Write-Host "  ERRO: Falha ao obter service principal do Microsoft Graph" -ForegroundColor Red
        Write-Host "  SOLUCAO: Tente manualmente: az ad sp list --filter `"displayName eq 'Microsoft Graph'`"" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  [INFO] Graph SP ID: $($graphSP.id)" -ForegroundColor DarkGray
    
    # Obter app roles necessarias
    Write-Host "  [DEBUG] Atribuindo Group.ReadWrite.All..." -ForegroundColor Gray
    $grwRole = $graphSP.appRoles | Where-Object { $_.value -eq "Group.ReadWrite.All" } | Select-Object -First 1
    
    if (-not $grwRole) {
        Write-Host "  ERRO: Role Group.ReadWrite.All nao encontrada" -ForegroundColor Red
        exit 1
    }
    
    $body1 = @{
        principalId = $principalId
        resourceId  = $graphSP.id
        appRoleId   = $grwRole.id
    } | ConvertTo-Json -Compress
    
    $tempBody1 = [System.IO.Path]::GetTempFileName()
    $body1 | Out-File -FilePath $tempBody1 -Encoding UTF8 -Force
    
    Write-Host "  [DEBUG] Executando az rest POST para Group.ReadWrite.All..." -ForegroundColor DarkGray
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
        --headers "Content-Type=application/json" `
        --body "@$tempBody1" `
        --only-show-errors 2>$null | Out-Null
    
    Remove-Item $tempBody1 -Force -ErrorAction SilentlyContinue
    
    Write-Host "  [DEBUG] Exit code: $LASTEXITCODE" -ForegroundColor DarkGray
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 4) {
        Write-Host "  AVISO: Atribuicao Group.ReadWrite.All retornou codigo $LASTEXITCODE" -ForegroundColor Yellow
    }
    else {
        Write-Host "  OK: Group.ReadWrite.All" -ForegroundColor Green
    }
    
    # Device.Read.All
    Write-Host "  [DEBUG] Atribuindo Device.Read.All..." -ForegroundColor Gray
    $draRole = $graphSP.appRoles | Where-Object { $_.value -eq "Device.Read.All" } | Select-Object -First 1
    
    if (-not $draRole) {
        Write-Host "  ERRO: Role Device.Read.All nao encontrada" -ForegroundColor Red
        exit 1
    }
    
    $body2 = @{
        principalId = $principalId
        resourceId  = $graphSP.id
        appRoleId   = $draRole.id
    } | ConvertTo-Json -Compress
    
    $tempBody2 = [System.IO.Path]::GetTempFileName()
    $body2 | Out-File -FilePath $tempBody2 -Encoding UTF8 -Force
    
    Write-Host "  [DEBUG] Executando az rest POST para Device.Read.All..." -ForegroundColor DarkGray
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" `
        --headers "Content-Type=application/json" `
        --body "@$tempBody2" `
        --only-show-errors 2>$null | Out-Null
    
    Remove-Item $tempBody2 -Force -ErrorAction SilentlyContinue
    
    Write-Host "  [DEBUG] Exit code: $LASTEXITCODE" -ForegroundColor DarkGray
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 4) {
        Write-Host "  AVISO: Atribuicao Device.Read.All retornou codigo $LASTEXITCODE" -ForegroundColor Yellow
    }
    else {
        Write-Host "  OK: Device.Read.All" -ForegroundColor Green
    }
    
    Write-Host "  OK: Permissoes Graph API configuradas" -ForegroundColor Green
}
catch {
    Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Falha na atribuicao de permissoes, mas continuando..." -ForegroundColor Yellow
}
Write-Host ""

# ============================================================================
# [8/10] AGUARDAR PROPAGACAO
# ============================================================================
Write-Host "[8/10] Aguardando propagacao de permissoes (max 5 min)..." -ForegroundColor Cyan
try {
    $timeout = (Get-Date).AddMinutes(5)
    
    while ((Get-Date) -lt $timeout) {
        Start-Sleep -Seconds 20
        
        Write-Host "  [DEBUG] Verificando permissoes atribuidas..." -ForegroundColor DarkGray
        $assignments = Get-AzJsonOutput -Command "az rest --method GET --uri https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments --output json"
        
        if ($assignments.value.Count -ge 2) {
            $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
            Write-Host "  OK: Permissoes propagadas em $elapsed minutos" -ForegroundColor Green
            break
        }
        
        $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
        Write-Host "  [INFO] AGUARDANDO: $elapsed min..." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  AVISO: Falha ao verificar propagacao" -ForegroundColor Yellow
}
Write-Host ""

# ============================================================================
# [9/10] AGENDAMENTO
# ============================================================================
Write-Host "[9/10] Criando agendamento..." -ForegroundColor Cyan
try {
    $scheduleName = "Hourly-MDE-Sync"
    $startTime = (Get-Date).AddHours(1).ToString("yyyy-MM-ddTHH:mm:ss")
    
    Write-Host "  [DEBUG] Criando schedule: $scheduleName" -ForegroundColor DarkGray
    Write-Host "  [DEBUG] Inicio: $startTime" -ForegroundColor DarkGray
    Write-Host "  [DEBUG] Intervalo: $ScheduleIntervalHours hora(s)" -ForegroundColor DarkGray
    
    az automation schedule create `
        --resource-group $ResourceGroupName `
        --automation-account-name $aaName `
        --name $scheduleName `
        --frequency "Hour" `
        --interval $ScheduleIntervalHours `
        --start-time $startTime `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao criar schedule (exit code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique formato da data ou permissoes" -ForegroundColor Yellow
        exit 1
    }
    
    # Vincular schedule ao runbook
    Write-Host "  [DEBUG] Preparando parametros do runbook..." -ForegroundColor DarkGray
    $params = @{
        SubscriptionId = $SubscriptionId
        GroupId        = $groupId
        IncludeArc     = $IncludeArc
    } | ConvertTo-Json -Compress
    
    Write-Host "  [DEBUG] Vinculando schedule ao runbook..." -ForegroundColor DarkGray
    az automation job schedule create `
        --resource-group $ResourceGroupName `
        --automation-account-name $aaName `
        --runbook-name "Sync-VMs-To-M365Group" `
        --schedule-name $scheduleName `
        --parameters $params `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao vincular schedule (exit code: $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "  SOLUCAO: Verifique permissoes ou crie manualmente no portal" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  OK: Agendamento criado" -ForegroundColor Green
    Write-Host "  [INFO] Proxima execucao: $startTime" -ForegroundColor DarkGray
}
catch {
    Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# ============================================================================
# [10/10] AZURE POLICY
# ============================================================================
Write-Host "[10/10] Criando Azure Policy..." -ForegroundColor Cyan
try {
    $policyName = "mde-vm-device-tagging"
    
    Write-Host "  [DEBUG] Preparando regras da policy..." -ForegroundColor DarkGray
    $policyRule = @{
        if   = @{
            allOf = @(
                @{ field = "type"; equals = "Microsoft.Compute/virtualMachines" },
                @{
                    anyOf = @(
                        @{ field = "tags['mde_device_id']"; exists = $false },
                        @{ field = "tags['mde_device_id']"; equals = "" }
                    )
                }
            )
        }
        then = @{
            effect  = "modify"
            details = @{
                roleDefinitionIds = @("/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c")
                operations        = @(
                    @{
                        operation = "addOrReplace"
                        field     = "tags['mde_device_id']"
                        value     = "[field('name')]"
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress
    
    Write-Host "  [DEBUG] Criando policy definition..." -ForegroundColor DarkGray
    az policy definition create `
        --name $policyName `
        --display-name "Tag Azure VMs with MDE Device ID" `
        --description "Marca automaticamente VMs com seu nome como mde_device_id" `
        --rules $policyRule `
        --mode "All" `
        --only-show-errors 2>$null | Out-Null
    
    Write-Host "  [DEBUG] Atribuindo policy..." -ForegroundColor DarkGray
    az policy assignment create `
        --name "mde-auto-tagging" `
        --display-name "MDE VM Auto-Tagging" `
        --policy $policyName `
        --scope "/subscriptions/$SubscriptionId" `
        --location $Location `
        --assign-identity `
        --only-show-errors 2>$null | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  AVISO: Policy pode ja existir (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  OK: Policy criada e atribuida" -ForegroundColor Green
    }
}
catch {
    Write-Host "  AVISO: Policy pode ja existir" -ForegroundColor Yellow
}
Write-Host ""

# ============================================================================
# RESUMO
# ============================================================================
$et = Get-Date
$dur = $et - $StartTime

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT CONCLUIDO COM SUCESSO" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "RECURSOS CRIADOS:" -ForegroundColor Cyan
Write-Host "  Subscription       : $SubscriptionName" -ForegroundColor White
Write-Host "  Resource Group     : $ResourceGroupName" -ForegroundColor White
Write-Host "  Automation Account : $aaName" -ForegroundColor White
Write-Host "  Managed Identity   : $principalId" -ForegroundColor White
Write-Host "  Grupo Entra ID     : $GroupDisplayName" -ForegroundColor Yellow
Write-Host "  ID do Grupo        : $groupId" -ForegroundColor White
Write-Host "  Runbook            : Sync-VMs-To-M365Group" -ForegroundColor White
Write-Host "  Agendamento        : A cada $ScheduleIntervalHours hora(s)" -ForegroundColor White
Write-Host ""
Write-Host "INFO DA EXECUCAO:" -ForegroundColor Magenta
Write-Host "  ID de Execucao     : $ExecutionId" -ForegroundColor DarkGray
Write-Host "  Duracao Total      : $($dur.ToString('hh\:mm\:ss'))" -ForegroundColor DarkGray
Write-Host "  Versao             : $ScriptVersion" -ForegroundColor DarkGray
Write-Host ""
Write-Host "PROXIMOS PASSOS:" -ForegroundColor Yellow
Write-Host "  1. Verifique o runbook no portal Azure" -ForegroundColor White
Write-Host "  2. Execute um teste manual se desejar" -ForegroundColor White
Write-Host "  3. Monitore a primeira execucao agendada" -ForegroundColor White
Write-Host "  4. Verifique membros do grupo: $GroupDisplayName" -ForegroundColor White
Write-Host ""
Write-Host "GROUP NAME = SUBSCRIPTION NAME (AUTOMATIC)" -ForegroundColor Yellow
Write-Host ""
