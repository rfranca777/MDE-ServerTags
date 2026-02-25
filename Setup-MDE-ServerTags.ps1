<#
.SYNOPSIS
    Setup-MDE-ServerTags.ps1 v2.2.0 — Assistente de Configuração Inteligente
    Auto-descobre tenant, subscriptions e contexto da conta atual antes de perguntar qualquer coisa.

.DESCRIPTION
    FLUXO:
      PRE-DESCOBERTA SILENCIOSA — Azure CLI, config.json, ARM API, MDE API
      Apresenta tudo descoberto para confirmacao (ENTER = confirmar, digitar = corrigir)
      Nenhum parametro manual obrigatorio se a conta tiver permissoes suficientes

.NOTES
    Versao: 2.2.0 | Fev 2026 | Microsoft
#>

# ============================================================================
# FUNCOES UI
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "  +===================================================================+" -ForegroundColor Cyan
    Write-Host "  |                                                                   |" -ForegroundColor Cyan
    Write-Host "  |   MDE SERVER TAGS  --  S E T U P   W I Z A R D   v2.2.0         |" -ForegroundColor White
    Write-Host "  |                                                                   |" -ForegroundColor Cyan
    Write-Host "  |   Classificacao Automatica de Servidores por Subscription Azure  |" -ForegroundColor Gray
    Write-Host "  |   Microsoft Defender for Endpoint                                |" -ForegroundColor Gray
    Write-Host "  |                                                                   |" -ForegroundColor Cyan
    Write-Host "  +===================================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Step {
    param([int]$Num, [int]$Total, [string]$Title)
    Write-Host ""
    Write-Host "  -- ETAPA $Num/$Total -- $Title -----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-DiscoveryBanner {
    Write-Host ""
    Write-Host "  +===================================================================+" -ForegroundColor DarkYellow
    Write-Host "  |   >>> PRE-DESCOBERTA EM ANDAMENTO...                             |" -ForegroundColor Yellow
    Write-Host "  |   Analisando a conta atual para pre-preencher todos os campos.   |" -ForegroundColor Gray
    Write-Host "  +===================================================================+" -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Ok    { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Err   { param([string]$m) Write-Host "  [ERR]  $m" -ForegroundColor Red }
function Write-Info  { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan }
function Write-Found { param([string]$m) Write-Host "  [>>>]  $m" -ForegroundColor Magenta }

function Prompt-WithDefault {
    param(
        [string]$Label,
        [string]$Default = "",
        [switch]$IsSecret
    )
    Write-Host ""
    if ($Default -and $Default.Length -gt 0) {
        if ($IsSecret) {
            $display = "****" + $Default.Substring([Math]::Max(0,$Default.Length-4))
        } else {
            $display = $Default
        }
        Write-Host "  $Label" -ForegroundColor White
        Write-Host "  Descoberto: " -NoNewline -ForegroundColor DarkGray
        Write-Host $display -NoNewline -ForegroundColor Cyan
        Write-Host "  [ENTER=confirmar | digite para substituir]: " -NoNewline -ForegroundColor DarkGray
    } else {
        Write-Host "  $Label [nao descoberto -- informe]: " -NoNewline -ForegroundColor Yellow
    }
    $inputVal = (Read-Host).Trim()
    if ($inputVal -eq "") { return $Default }
    return $inputVal
}

function Confirm-YN {
    param([string]$Question, [bool]$DefaultYes = $true)
    $hint = if ($DefaultYes) { "S/n" } else { "s/N" }
    Write-Host ""
    Write-Host "  $Question ($hint): " -NoNewline -ForegroundColor Yellow
    $r = (Read-Host).Trim()
    if ($r -eq "") { return $DefaultYes }
    return ($r -match '^[Ss]')
}

# ============================================================================
# VARIAVEIS GLOBAIS
# ============================================================================
$ErrorActionPreference = "Continue"
$scriptRoot  = $PSScriptRoot
$configPath  = Join-Path $scriptRoot "config.json"
$csvPath     = Join-Path $scriptRoot "subscription_mapping.csv"
$mainScript  = Join-Path $scriptRoot "01-Classificacao-Servidores\Sync-MDE-ServerTags-BySubscription.ps1"
$totalSteps  = 6

$discovered = @{
    tenantId       = ""
    tenantName     = ""
    appId          = ""
    appSecret      = ""
    accountUser    = ""
    subscriptions  = @()
    azCliAvailable = $false
    azCliLoggedIn  = $false
    configHasCreds = $false
}

# ============================================================================
# FASE 0 -- PRE-DESCOBERTA SILENCIOSA
# ============================================================================
Clear-Host
Show-Banner
Show-DiscoveryBanner

# --- 0.1 Carregar config.json existente ---
if (Test-Path $configPath) {
    try {
        $cfg = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($cfg.autenticacao.tenantId -and $cfg.autenticacao.tenantId -ne "") {
            $discovered.tenantId = $cfg.autenticacao.tenantId
            Write-Found "Tenant ID lido do config.json: $($discovered.tenantId)"
        }
        if ($cfg.autenticacao.appId -and $cfg.autenticacao.appId -ne "") {
            $discovered.appId = $cfg.autenticacao.appId
            Write-Found "App ID lido do config.json: $($discovered.appId)"
        }
        if ($cfg.autenticacao.appSecret -and $cfg.autenticacao.appSecret -ne "") {
            $discovered.appSecret      = $cfg.autenticacao.appSecret
            $discovered.configHasCreds = $true
            Write-Found "Secret lido do config.json (mascarado)"
        }
    } catch { Write-Warn "Nao foi possivel ler config.json: $_" }
} else {
    Write-Warn "config.json nao encontrado -- sera criado ao final"
}

# --- 0.2 Azure CLI ---
try {
    $azCheck = & az --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $discovered.azCliAvailable = $true
        Write-Found "Azure CLI disponivel"

        $azAccountJson = & az account show --output json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $azAccount = $azAccountJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($azAccount -and $azAccount.id) {
                $discovered.azCliLoggedIn = $true
                $discovered.accountUser   = $azAccount.user.name

                # Tenant ID do CLI
                if ((-not $discovered.tenantId -or $discovered.tenantId -eq "") -and $azAccount.tenantId) {
                    $discovered.tenantId = $azAccount.tenantId
                    Write-Found "Tenant ID descoberto via Azure CLI: $($discovered.tenantId)"
                } elseif ($discovered.tenantId -and $discovered.tenantId -ne "") {
                    Write-Found "Tenant ID confirmado pelo Azure CLI: $($discovered.tenantId)"
                }

                # Listar TODAS as subscriptions
                Write-Found "Listando subscriptions disponiveis..."
                $azSubsJson = & az account list --all --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $azSubs = $azSubsJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($azSubs -and $azSubs.Count -gt 0) {
                        $discovered.subscriptions = @($azSubs | ForEach-Object {
                            [pscustomobject]@{
                                id        = $_.id
                                name      = $_.name
                                state     = $_.state
                                isDefault = $_.isDefault
                            }
                        })
                        Write-Found "$($discovered.subscriptions.Count) subscription(s) encontrada(s) via Azure CLI"
                    }
                }

                # Nome do tenant via ARM CLI
                try {
                    $tenantJson = & az rest --method GET --url "https://management.azure.com/tenants?api-version=2020-01-01" --output json 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $tenantData = $tenantJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($tenantData.value) {
                            $t = $tenantData.value | Where-Object { $_.tenantId -eq $discovered.tenantId } | Select-Object -First 1
                            if ($t -and $t.displayName) { $discovered.tenantName = $t.displayName }
                        }
                    }
                } catch { }
            }
        } else {
            Write-Warn "Azure CLI instalado mas NAO autenticado ('az login' recomendado)"
        }
    }
} catch {
    Write-Info "Azure CLI nao disponivel neste ambiente"
}

# --- 0.3 Tentativa via ARM API com Service Principal do config ---
if ($discovered.tenantId -and $discovered.appId -and $discovered.appSecret -and $discovered.subscriptions.Count -eq 0) {
    try {
        $armBody = @{
            grant_type    = "client_credentials"
            client_id     = $discovered.appId
            client_secret = $discovered.appSecret
            scope         = "https://management.azure.com/.default"
        }
        $armToken = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$($discovered.tenantId)/oauth2/v2.0/token" `
            -Method POST -Body $armBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        $armHdrs = @{ Authorization = "Bearer $($armToken.access_token)" }
        $armSubs = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
            -Headers $armHdrs -ErrorAction Stop

        if ($armSubs.value -and $armSubs.value.Count -gt 0) {
            $discovered.subscriptions = @($armSubs.value | ForEach-Object {
                [pscustomobject]@{
                    id        = $_.subscriptionId
                    name      = $_.displayName
                    state     = $_.state
                    isDefault = $false
                }
            })
            Write-Found "$($discovered.subscriptions.Count) subscription(s) via ARM API (Service Principal)"
        }
    } catch {
        Write-Info "ARM API via SP nao retornou subscriptions -- usando outros metodos"
    }
}

# --- 0.4 Ler CSV existente para referencia ---
$existingCsvMap = @{}
if (Test-Path $csvPath) {
    try {
        $csvRows = Import-Csv $csvPath -Delimiter ";" -ErrorAction Stop
        foreach ($row in $csvRows) {
            if ($row.subscriptionId -and $row.subscriptionId -notmatch 'aaaaaaaa') {
                $existingCsvMap[$row.subscriptionId] = $row.subscriptionName
            }
        }
        if ($existingCsvMap.Count -gt 0) {
            Write-Found "$($existingCsvMap.Count) subscription(s) ja mapeada(s) no CSV atual"
        }
    } catch { }
}

# --- 0.5 Enriquecer com nomes do CSV existente ---
foreach ($sub in $discovered.subscriptions) {
    if ($existingCsvMap.ContainsKey($sub.id)) {
        $sub | Add-Member -NotePropertyName csvName -NotePropertyValue $existingCsvMap[$sub.id] -Force
    }
}

Write-Host ""
Write-Host "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Pre-descoberta concluida. Confirme ou corrija as informacoes abaixo." -ForegroundColor White
Write-Host "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

if ($discovered.accountUser)  { Write-Info "Conta atual : $($discovered.accountUser)" }
if ($discovered.tenantName)   { Write-Info "Tenant      : $($discovered.tenantName) ($($discovered.tenantId))" }
if ($discovered.subscriptions.Count -gt 0) {
    Write-Info "Subscriptions encontradas: $($discovered.subscriptions.Count)"
}

if (-not (Confirm-YN "Deseja iniciar a configuracao?" $true)) {
    Write-Host "  Cancelado." -ForegroundColor Gray; exit 0
}

# ============================================================================
# ETAPA 1 -- PRE-REQUISITOS
# ============================================================================
Show-Step 1 $totalSteps "PRE-REQUISITOS"

$prereqOk = $true

$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -ge 5) {
    Write-Ok "PowerShell $($psVer.Major).$($psVer.Minor)"
} else {
    Write-Err "PowerShell $($psVer.Major).$($psVer.Minor) -- minimo 5.1 necessario"
    $prereqOk = $false
}

try {
    $null = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" -TimeoutSec 10
    Write-Ok "Conectividade Azure AD (login.microsoftonline.com)"
} catch {
    Write-Err "Sem conectividade com Azure AD"
    $prereqOk = $false
}

try {
    $r = Invoke-WebRequest -Uri "https://api.securitycenter.microsoft.com" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    Write-Ok "API MDE acessivel"
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
        Write-Ok "API MDE acessivel (401 esperado sem token)"
    } else {
        Write-Warn "API MDE pode estar bloqueada -- verifique proxy/firewall se necessario"
    }
}

if (Test-Path $configPath)  { Write-Ok "config.json encontrado" }
else                        { Write-Err "config.json nao encontrado: $configPath"; $prereqOk = $false }

if (Test-Path $mainScript)  { Write-Ok "Script principal encontrado" }
else                        { Write-Err "Script principal nao encontrado: $mainScript"; $prereqOk = $false }

if ($discovered.azCliAvailable) {
    if ($discovered.azCliLoggedIn) {
        Write-Ok "Azure CLI autenticado como: $($discovered.accountUser)"
    } else {
        Write-Warn "Azure CLI disponivel mas NAO autenticado. Execute 'az login' para auto-descoberta."
    }
} else {
    Write-Info "Azure CLI nao disponivel -- auto-descoberta usara metadados MDE"
}

if (-not $prereqOk) {
    Write-Err "Corrija os itens acima e execute novamente."
    exit 1
}

# ============================================================================
# ETAPA 2 -- CREDENCIAIS DO APP REGISTRATION
# ============================================================================
Show-Step 2 $totalSteps "CREDENCIAIS -- APP REGISTRATION"

$tenantIdInput  = Prompt-WithDefault -Label "Tenant ID (Directory ID)" -Default $discovered.tenantId
$appIdInput     = ""
$appSecretInput = ""

if (-not $tenantIdInput) {
    Write-Err "Tenant ID e obrigatorio."
    exit 1
}

# ---------- helper: extrair JSON de saida mista (WARNING: ... { json } ) ----
function Extract-JsonFromAzOutput {
    param([object[]]$RawOutput)
    # Junta todas as linhas em uma string
    $joined = ($RawOutput -join ' ')
    # Tenta converter diretamente (sem aviso)
    try { return ($joined | ConvertFrom-Json -ErrorAction Stop) } catch {}
    # Extrai apenas a porcao JSON -- busca o primeiro { ate o ultimo }
    $start = $joined.IndexOf('{')
    if ($start -ge 0) {
        $jsonPart = $joined.Substring($start)
        try { return ($jsonPart | ConvertFrom-Json -ErrorAction Stop) } catch {}
    }
    return $null
}

# ---------- helper: criar App Registration via Azure CLI --------------------
function New-AppRegistrationCLI {
    param([string]$AppName, [string]$TenantId)

    Write-Host ""
    Write-Host "  +===================================================================+" -ForegroundColor DarkCyan
    Write-Host "  |  CRIANDO APP REGISTRATION AUTOMATICAMENTE VIA AZURE CLI          |" -ForegroundColor Cyan
    Write-Host "  +===================================================================+" -ForegroundColor DarkCyan
    Write-Host "  |  Tenant  : $($TenantId.PadRight(55))|" -ForegroundColor Gray
    Write-Host "  |  Nome    : $($AppName.PadRight(55))|" -ForegroundColor White
    Write-Host "  +===================================================================+" -ForegroundColor DarkCyan
    Write-Host ""

    # ---- PASSO 1: criar App Registration ------------------------------------
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  PASSO 1/5 -- Criar App Registration no Entra ID" -ForegroundColor White
    Write-Host "  CMD: az ad app create --display-name `"$AppName`" --sign-in-audience AzureADMyOrg" -ForegroundColor DarkGray
    Write-Host ""

    $rawApp = az ad app create --display-name $AppName --sign-in-audience AzureADMyOrg 2>&1
    Write-Host "  Output bruto az: $($rawApp -join ' ' | Select-Object -First 1)" -ForegroundColor DarkGray

    $appObj = Extract-JsonFromAzOutput $rawApp
    if (-not $appObj -or -not $appObj.appId) {
        Write-Host "  [DETALHE] Saida completa do az:" -ForegroundColor Yellow
        $rawApp | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
        Write-Err "  Falha ao criar App Registration. Verifique permissoes da conta logada."
        Write-Info "  Conta atual: $(az account show --query user.name -o tsv 2>$null)"
        Write-Info "  Permissao necessaria: Application.ReadWrite.All ou Cloud App Admin"
        return $null
    }
    $nAppId    = $appObj.appId
    $nAppObjId = $appObj.id
    Write-Ok "  App Registration criado com sucesso"
    Write-Host "    >> Display Name : $AppName"     -ForegroundColor Cyan
    Write-Host "    >> App (Client) ID : $nAppId"   -ForegroundColor Cyan
    Write-Host "    >> Object ID       : $nAppObjId" -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds 3   # aguarda replicacao Entra ID

    # ---- PASSO 2: criar Service Principal -----------------------------------
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  PASSO 2/5 -- Criar Service Principal para o App" -ForegroundColor White
    Write-Host "  CMD: az ad sp create --id $nAppId" -ForegroundColor DarkGray
    Write-Host ""

    $nSpObjId = $null
    $rawSp = az ad sp create --id $nAppId 2>&1
    $spObj = Extract-JsonFromAzOutput $rawSp
    if ($spObj -and $spObj.id) {
        $nSpObjId = $spObj.id
        Write-Ok "  Service Principal criado"
        Write-Host "    >> SP Object ID: $nSpObjId" -ForegroundColor DarkGray
    } elseif ($rawSp -match 'already exists') {
        Write-Ok "  Service Principal ja existia -- obtendo SP ID..."
        $nSpObjId = (az ad sp show --id $nAppId --query id -o tsv 2>&1).Trim()
        Write-Host "    >> SP Object ID: $nSpObjId" -ForegroundColor DarkGray
    } else {
        Write-Warn "  SP pode nao ter sido criado -- continuando mesmo assim"
        Write-Host "  [DETALHE] Resposta az: $($rawSp -join ' ')" -ForegroundColor DarkYellow
    }
    Write-Host ""
    Start-Sleep -Seconds 5   # aguarda SP replicar antes de adicionar permissao

    # ---- PASSO 3: adicionar permissao Machine.ReadWrite.All -----------------
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  PASSO 3/5 -- Adicionar permissao Machine.ReadWrite.All (WindowsDefenderATP)" -ForegroundColor White
    Write-Host "  API ID  : fc780465-2017-40d4-a0c5-307022471b92  (WindowsDefenderATP)" -ForegroundColor DarkGray
    Write-Host "  Perm ID : d5786bf7-d9b2-4eca-bec3-6fd7fc269ef6  (requiredResourceAccess scope)" -ForegroundColor DarkGray
    Write-Host "  CMD: az ad app permission add --id $nAppId --api fc780465... --api-permissions d5786bf7...=Role" -ForegroundColor DarkGray
    Write-Host ""

    $rawPerm = az ad app permission add `
        --id $nAppId `
        --api fc780465-2017-40d4-a0c5-307022471b92 `
        --api-permissions "d5786bf7-d9b2-4eca-bec3-6fd7fc269ef6=Role" 2>&1
    if ($LASTEXITCODE -eq 0 -or $rawPerm -match 'already') {
        Write-Ok "  Permissao Machine.ReadWrite.All adicionada (requiredResourceAccess)"
    } else {
        Write-Warn "  Possivel erro ao adicionar permissao -- verifique no portal"
        Write-Host "  [DETALHE] Resposta az: $($rawPerm -join ' ')" -ForegroundColor DarkYellow
    }
    Write-Host ""
    Start-Sleep -Seconds 3

    # ---- PASSO 4: Admin Consent via appRoleAssignment (Graph API) -----------
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  PASSO 4/5 -- Aplicar Admin Consent via Graph API (appRoleAssignment)" -ForegroundColor White
    Write-Host "  Metodo 1: az ad app permission admin-consent" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Tentando metodo 1..." -ForegroundColor Gray

    $consentOk = $false
    $rawConsent = az ad app permission admin-consent --id $nAppId 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "  Admin Consent concedido (metodo 1)"
        $consentOk = $true
    } else {
        Write-Host "  Metodo 1 falhou (exit=$LASTEXITCODE). Tentando metodo 2 -- Graph API appRoleAssignment..." -ForegroundColor Yellow
        Write-Host ""

        # Metodo 2: appRoleAssignment direto via Graph API (mais confiavel)
        # O GUID do appRole pode diferir do scope GUID -- consultamos o SP em tempo real
        Write-Host "  [2a] Obtendo SP do WindowsDefenderATP neste tenant..." -ForegroundColor Gray
        $mdeSpObjId = az ad sp show --id fc780465-2017-40d4-a0c5-307022471b92 --query id -o tsv 2>&1
        Write-Host "       MDE SP Object ID: $mdeSpObjId" -ForegroundColor DarkGray

        Write-Host "  [2b] Obtendo GUID real do appRole Machine.ReadWrite.All..." -ForegroundColor Gray
        $machineRwRoleId = az ad sp show --id fc780465-2017-40d4-a0c5-307022471b92 `
            --query "appRoles[?value=='Machine.ReadWrite.All'].id" -o tsv 2>&1
        Write-Host "       Machine.ReadWrite.All appRole ID: $machineRwRoleId" -ForegroundColor DarkGray

        # Garantir que temos o SP Object ID (pode nao ter sido capturado no Passo 2)
        if (-not $nSpObjId) {
            Write-Host "  [SP ID nao disponivel] Consultando via az ad sp show..." -ForegroundColor Gray
            $nSpObjId = (az ad sp show --id $nAppId --query id -o tsv 2>&1).Trim()
            Write-Host "       SP Object ID (consultado agora): $nSpObjId" -ForegroundColor DarkGray
        }
        Write-Host "  [2c] Criando appRoleAssignment (POST Graph API)..." -ForegroundColor Gray
        Write-Host "       Usando SP Object ID: $nSpObjId" -ForegroundColor DarkGray
        $consentBodyFile = Join-Path $env:TEMP "mde-consent-$($nAppId.Substring(0,8)).json"
        @{
            principalId = $nSpObjId    # SP Object ID (CORRETO -- nao App Object ID)
            resourceId  = $mdeSpObjId.Trim()
            appRoleId   = $machineRwRoleId.Trim()
        } | ConvertTo-Json | Set-Content $consentBodyFile -Encoding UTF8

        $consentResult = az rest --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$nSpObjId/appRoleAssignments" `
            --body "@$consentBodyFile" `
            --headers "Content-Type=application/json" 2>&1

        if ($consentResult -match '"id"') {
            Write-Ok "  Admin Consent concedido via Graph API appRoleAssignment!"
            $consentOk = $true
        } else {
            Write-Warn "  Metodo 2 tambem falhou: $($consentResult -join ' ' | Select-Object -First 200)"
        }
        Remove-Item $consentBodyFile -ErrorAction SilentlyContinue
    }

    if (-not $consentOk) {
        Write-Host ""
        Write-Host "  [!] Admin Consent nao foi aplicado automaticamente por nenhum metodo." -ForegroundColor Yellow
        Write-Host "  Possiveis causas: conta sem privilegio, replicacao pendente, MDE nao ativo." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  ACAO MANUAL:" -ForegroundColor Red
        Write-Host "    https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$nAppId" -ForegroundColor Cyan
        Write-Host "    > Grant admin consent for ... > Yes" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  O setup continuara, mas autenticacao MDE falhara ate o consent ser dado." -ForegroundColor Yellow
        Write-Host ""
        Read-Host "  Pressione ENTER para continuar (ou conceda o consent primeiro)"
    }
    Write-Host ""

    # ---- PASSO 5: criar Client Secret ---------------------------------------
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  PASSO 5/5 -- Criar Client Secret (validade 2 anos)" -ForegroundColor White
    Write-Host "  CMD: az ad app credential reset --id $nAppId --years 2" -ForegroundColor DarkGray
    Write-Host "  NOTA: o az CLI pode emitir aviso de seguranca junto com o JSON -- tratado automaticamente" -ForegroundColor DarkGray
    Write-Host ""

    # IMPORTANTE: az ad app credential reset mistura WARNING: ... com o JSON na mesma saida.
    # A funcao Extract-JsonFromAzOutput extrai apenas o bloco JSON, ignorando o aviso.
    $rawSecret = az ad app credential reset --id $nAppId --years 2 2>&1
    Write-Host "  Saida bruta recebida (primeiros 120 chars): $( ($rawSecret -join ' ').Substring(0, [Math]::Min(120,($rawSecret -join ' ').Length)) )..." -ForegroundColor DarkGray

    $secretObj = Extract-JsonFromAzOutput $rawSecret
    if (-not $secretObj -or -not $secretObj.password) {
        Write-Host ""
        Write-Host "  [DETALHE] Saida completa do az credential reset:" -ForegroundColor Yellow
        $rawSecret | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
        Write-Host ""
        Write-Err "  Nao foi possivel extrair o secret automaticamente."
        Write-Host ""
        Write-Host "  Voce pode criar o secret manualmente:" -ForegroundColor Yellow
        Write-Host "    portal.azure.com > Entra ID > App Registrations > $AppName" -ForegroundColor Cyan
        Write-Host "    > Certificates & secrets > New client secret > 24 months" -ForegroundColor Cyan
        Write-Host "    Copie o VALUE imediatamente (so aparece uma vez)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  App ID ja criado: $nAppId" -ForegroundColor Green
        Write-Host "  Informe o secret manualmente a seguir:" -ForegroundColor Yellow
        Write-Host ""
        $manualSecret = Prompt-WithDefault "  Client Secret (cole aqui)" "" 
        if ($manualSecret) {
            Write-Ok "  Secret informado manualmente"
            return [pscustomobject]@{ AppId = $nAppId ; Secret = $manualSecret }
        }
        return $null
    }

    $nSecret = $secretObj.password
    $nHint   = if ($nSecret.Length -ge 6) { $nSecret.Substring(0,3) + "***" + $nSecret.Substring($nSecret.Length-3) } else { "***" }
    Write-Ok "  Client Secret gerado com sucesso"
    Write-Host "    >> Hint (nao usar -- apenas confirmacao): $nHint" -ForegroundColor DarkGray
    Write-Host "    >> O valor completo sera salvo automaticamente no config.json" -ForegroundColor DarkGray
    Write-Host ""

    # ---- Resumo final -------------------------------------------------------
    Write-Host "  +===================================================================+" -ForegroundColor Green
    Write-Host "  |  APP REGISTRATION CRIADO E CONFIGURADO                          |" -ForegroundColor Green
    Write-Host "  +===================================================================+" -ForegroundColor DarkGray
    $lnP = $AppName.PadRight(55)
    $liP = $nAppId.PadRight(55)
    Write-Host "  |  Nome      : $lnP|" -ForegroundColor Cyan
    Write-Host "  |  App ID    : $liP|" -ForegroundColor Cyan
    Write-Host "  |  Secret    : [salvo no config.json -- nao sera mais exibido]    |" -ForegroundColor Yellow
    Write-Host "  |  Expiracao : $(((Get-Date).AddYears(2)).ToString('dd/MM/yyyy')) (2 anos)$((' ').PadRight(34))|" -ForegroundColor DarkGray
    Write-Host "  |  Permissao : Machine.ReadWrite.All (WindowsDefenderATP)        |" -ForegroundColor Green
    Write-Host "  +===================================================================+" -ForegroundColor Green
    Write-Host ""

    return [pscustomobject]@{ AppId = $nAppId ; Secret = $nSecret }
}

# ---------- decisao: appId ja conhecido? ------------------------------------
if ($discovered.appId) {
    # config.json ou discovery ja tem credenciais -- confirmar / substituir
    Write-Found "App Registration ja configurado -- confirme ou altere:"
    $appIdInput     = Prompt-WithDefault -Label "App (Client) ID do App Registration" -Default $discovered.appId
    $appSecretInput = Prompt-WithDefault -Label "Client Secret do App Registration"   -Default $discovered.appSecret -IsSecret

} elseif ($discovered.azCliLoggedIn) {
    # CLI autenticado mas sem App Registration -- oferecer criacao automatica
    Write-Host ""
    Write-Host "  Nenhum App Registration configurado ainda." -ForegroundColor Yellow
    Write-Host "  Azure CLI esta autenticado -- posso criar tudo automaticamente!" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  [C]  Criar novo App Registration agora (recomendado)           |" -ForegroundColor Cyan
    Write-Host "  |  [I]  Informar credenciais de App Registration ja existente     |" -ForegroundColor White
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Escolha [C/I]: " -NoNewline -ForegroundColor Yellow
    $escolha = (Read-Host).Trim().ToUpper()

    if ($escolha -ne "I") {
        # Sugestoes de nomenclatura logica baseadas no tenant / atividade
        $orgSlug      = ($discovered.tenantName -replace '[^a-zA-Z0-9]','-' -replace '-+','-' -replace '^-|-$','').ToUpper()
        if (-not $orgSlug) { $orgSlug = "EMPRESA" }

        $sugestao1 = "MDE-ServerTags-$orgSlug"
        $sugestao2 = "MDE-ServerTags-Automation"
        $sugestao3 = "MDE-ClassificacaoServidores-SP"
        $sugestao4 = "SVC-MDE-DeviceClassification"

        Write-Host ""
        Write-Host "  Sugestoes de nome (baseadas no tenant: $($discovered.tenantName)):" -ForegroundColor White
        Write-Host "    [1] $sugestao1  (recomendado -- identifica org)" -ForegroundColor Cyan
        Write-Host "    [2] $sugestao2" -ForegroundColor White
        Write-Host "    [3] $sugestao3" -ForegroundColor White
        Write-Host "    [4] $sugestao4" -ForegroundColor White
        Write-Host "    [5] Informar nome personalizado" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Escolha [1-5] ou ENTER para recomendado: " -NoNewline -ForegroundColor Yellow
        $nomeEscolha = (Read-Host).Trim()

        $appName = switch ($nomeEscolha) {
            "2"     { $sugestao2 }
            "3"     { $sugestao3 }
            "4"     { $sugestao4 }
            "5"     {
                Write-Host "  Nome personalizado (sem espacos, use hifens): " -NoNewline -ForegroundColor White
                $custom = (Read-Host).Trim()
                if ($custom) { $custom } else { $sugestao1 }
            }
            default { $sugestao1 }
        }
        if (-not $appName) { $appName = $sugestao1 }

        Write-Host ""
        Write-Host "  App Registration sera criado com o nome: " -NoNewline -ForegroundColor White
        Write-Host $appName -ForegroundColor Cyan
        Write-Host ""
        if (Confirm-YN "  Confirmar criacao?" $true) {
            $result = New-AppRegistrationCLI -AppName $appName -TenantId $tenantIdInput
            if ($result) {
                $appIdInput     = $result.AppId
                $appSecretInput = $result.Secret
                $discovered.appId     = $result.AppId
                $discovered.appSecret = $result.Secret
            } else {
                Write-Err "Criacao automatica falhou. Informe as credenciais manualmente."
                $appIdInput     = Prompt-WithDefault -Label "App (Client) ID do App Registration" -Default ""
                $appSecretInput = Prompt-WithDefault -Label "Client Secret do App Registration"   -Default "" -IsSecret
            }
        } else {
            Write-Info "Criacao cancelada. Informe as credenciais de um App Registration existente:"
            $appIdInput     = Prompt-WithDefault -Label "App (Client) ID do App Registration" -Default ""
            $appSecretInput = Prompt-WithDefault -Label "Client Secret do App Registration"   -Default "" -IsSecret
        }
    } else {
        # Usuário escolheu [I] -- informar existente
        Write-Host ""
        Write-Host "  Informe as credenciais do App Registration existente:" -ForegroundColor White
        Write-Host ""
        $appIdInput     = Prompt-WithDefault -Label "App (Client) ID do App Registration" -Default $discovered.appId
        $appSecretInput = Prompt-WithDefault -Label "Client Secret do App Registration"   -Default $discovered.appSecret -IsSecret
    }

} else {
    # Sem CLI -- instrucoes manuais
    Write-Host ""
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Nenhum App Registration configurado.                           |" -ForegroundColor Yellow
    Write-Host "  |  Para criacao automatica: execute 'az login' e rode novamente.  |" -ForegroundColor Cyan
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  |  Criacao manual (portal.azure.com):                             |" -ForegroundColor White
    Write-Host "  |    Entra ID > App Registrations > New Registration              |" -ForegroundColor Gray
    Write-Host "  |    API Permissions > WindowsDefenderATP > Machine.ReadWrite.All |" -ForegroundColor Gray
    Write-Host "  |    Grant Admin Consent > Certificates & Secrets > New Secret   |" -ForegroundColor Gray
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    $appIdInput     = Prompt-WithDefault -Label "App (Client) ID do App Registration" -Default ""
    $appSecretInput = Prompt-WithDefault -Label "Client Secret do App Registration"   -Default "" -IsSecret
}

if (-not $appIdInput -or -not $appSecretInput) {
    Write-Err "App ID e Secret sao obrigatorios."
    exit 1
}

$cfg = Get-Content $configPath -Raw | ConvertFrom-Json
$cfg.autenticacao.tenantId  = $tenantIdInput
$cfg.autenticacao.appId     = $appIdInput
$cfg.autenticacao.appSecret = $appSecretInput
$cfg | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
Write-Ok "Credenciais salvas no config.json"

# ============================================================================
# ETAPA 3 -- VALIDAR AUTENTICACAO E DESCOBERTA FINAL VIA MDE
# ============================================================================
Show-Step 3 $totalSteps "VALIDACAO DA AUTENTICACAO E DESCOBERTA"

Write-Host "  Obtendo token OAuth2 para a API MDE..." -ForegroundColor Gray

$mdeToken = $null
$tokenOk  = $false

try {
    $body = @{
        client_id     = $appIdInput
        client_secret = $appSecretInput
        grant_type    = "client_credentials"
        scope         = "https://api.securitycenter.microsoft.com/.default"
    }
    $tokenResp = Invoke-RestMethod `
        -Uri "https://login.microsoftonline.com/$tenantIdInput/oauth2/v2.0/token" `
        -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

    $mdeToken = $tokenResp.access_token
    $tokenOk  = $true
    $expMin   = [math]::Round($tokenResp.expires_in / 60)
    Write-Ok "Token MDE obtido (expira em $expMin min)"

    $hdrs    = @{ Authorization = "Bearer $mdeToken" }
    $devResp = Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines?`$top=1" -Headers $hdrs -ErrorAction Stop
    $devCount= if ($devResp.'@odata.count') { $devResp.'@odata.count' } else { "1+" }
    Write-Ok "API MDE acessivel -- $devCount dispositivo(s) no tenant"

    # Enriquecer subscriptions via ARM com as mesmas credenciais
    try {
        $armBody = @{
            client_id     = $appIdInput
            client_secret = $appSecretInput
            grant_type    = "client_credentials"
            scope         = "https://management.azure.com/.default"
        }
        $armTkResp = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$tenantIdInput/oauth2/v2.0/token" `
            -Method POST -Body $armBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $armHdrs = @{ Authorization = "Bearer $($armTkResp.access_token)" }
        $armSubs = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers $armHdrs -ErrorAction Stop

        if ($armSubs.value -and $armSubs.value.Count -gt 0) {
            foreach ($s in $armSubs.value) {
                $existing = $discovered.subscriptions | Where-Object { $_.id -eq $s.subscriptionId }
                if ($existing) {
                    $existing.name = $s.displayName
                } else {
                    $discovered.subscriptions += [pscustomobject]@{
                        id        = $s.subscriptionId
                        name      = $s.displayName
                        state     = $s.state
                        isDefault = $false
                    }
                }
            }
            Write-Ok "Nomes enriquecidos via ARM API -- $($armSubs.value.Count) subscription(s) total"
        }
    } catch {
        Write-Info "ARM API nao retornou subscriptions (SP pode nao ter Reader role)"
    }

    # Extrair subscriptions dos metadados MDE se ainda nao temos nenhuma
    if ($discovered.subscriptions.Count -eq 0) {
        Write-Found "Extraindo subscriptions dos metadados dos dispositivos MDE..."
        $page     = "https://api.securitycenter.microsoft.com/api/machines?`$select=id,vmMetadata"
        $subIds   = @{}
        $pgCount  = 0
        while ($page -and $pgCount -lt 10) {
            $r = Invoke-RestMethod -Uri $page -Headers $hdrs -ErrorAction Stop
            foreach ($dev in $r.value) {
                if ($dev.vmMetadata -and $dev.vmMetadata.subscriptionId) {
                    $sid  = $dev.vmMetadata.subscriptionId
                    $name = if ($dev.vmMetadata.resourceId) {
                        ($dev.vmMetadata.resourceId -split '/')[2]
                    } else { $sid }
                    $subIds[$sid] = $name
                }
            }
            $page = $r.'@odata.nextLink'
            $pgCount++
        }
        if ($subIds.Count -gt 0) {
            $discovered.subscriptions = @($subIds.Keys | ForEach-Object {
                [pscustomobject]@{ id = $_; name = $subIds[$_]; state = "Enabled"; isDefault = $false }
            })
            Write-Found "$($subIds.Count) subscription(s) extraida(s) dos metadados MDE"
        }
    }

} catch {
    Write-Err "Falha na autenticacao: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "  Causas comuns:" -ForegroundColor Yellow
    Write-Host "    - Tenant ID ou App ID incorreto" -ForegroundColor White
    Write-Host "    - Secret expirado ou incorreto" -ForegroundColor White
    Write-Host "    - Machine.ReadWrite.All sem Admin Consent" -ForegroundColor White
    Write-Host ""
    if (-not (Confirm-YN "Continuar mesmo assim? (relatorios nao serao gerados)" $false)) { exit 1 }
}

# ============================================================================
# ETAPA 4 -- SELECAO DE SUBSCRIPTIONS (INCLUIR / EXCLUIR)
# ============================================================================
Show-Step 4 $totalSteps "MAPEAMENTO DE SUBSCRIPTIONS"

$excludedSubIds = @()

if ($discovered.subscriptions.Count -gt 0) {

    Write-Host "  Subscriptions descobertas para este tenant:" -ForegroundColor White
    Write-Host "  (Selecione quais EXCLUIR da classificacao -- ENTER inclui todas)" -ForegroundColor Gray
    Write-Host ""

    $subList = @($discovered.subscriptions | Sort-Object name)
    for ($i = 0; $i -lt $subList.Count; $i++) {
        $sub     = $subList[$i]
        $num     = ($i + 1).ToString().PadLeft(2)
        $subName = if ($existingCsvMap.ContainsKey($sub.id)) { $existingCsvMap[$sub.id] } else {
            $sub.name.ToUpper() -replace '[^A-Z0-9\-]','_' -replace '_+','_' -replace '^_|_$',''
        }
        $stateIcon = if ($sub.state -eq "Enabled") { "[OK]" } else { "[!] $($sub.state)" }
        Write-Host "  [$num] $stateIcon  $($sub.id)" -ForegroundColor Cyan -NoNewline
        Write-Host "  >> $subName" -ForegroundColor White
        Write-Host "       Nome oficial: $($sub.name)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Para EXCLUIR subscriptions, informe os numeros separados por virgula." -ForegroundColor Yellow
    Write-Host "  Ex: 2,5   ou   ENTER para incluir todas: " -NoNewline -ForegroundColor Yellow
    $exclusaoInput = (Read-Host).Trim()

    if ($exclusaoInput -ne "") {
        $indices = $exclusaoInput -split ',' | ForEach-Object {
            $n = $_.Trim()
            if ($n -match '^\d+$') { [int]$n - 1 } else { $null }
        } | Where-Object { $_ -ne $null -and $_ -ge 0 -and $_ -lt $subList.Count }

        foreach ($idx in $indices) {
            $excludedSubIds += $subList[$idx].id
            Write-Warn "Excluida: $($subList[$idx].name) ($($subList[$idx].id))"
        }
    }

    $includedSubs = @($subList | Where-Object { $excludedSubIds -notcontains $_.id })
    Write-Ok "$($includedSubs.Count) subscription(s) incluida(s), $($excludedSubIds.Count) excluida(s)"

    # Personalizar nomes das tags
    Write-Host ""
    if (Confirm-YN "Deseja personalizar o nome das tags para cada subscription?" $false) {
        Write-Host ""
        Write-Host "  ENTER = manter nome sugerido | Digite para personalizar" -ForegroundColor Gray
        Write-Host ""
        foreach ($sub in $includedSubs) {
            $suggestName = if ($existingCsvMap.ContainsKey($sub.id)) { $existingCsvMap[$sub.id] } else {
                $sub.name.ToUpper() -replace '[^A-Z0-9\-]','_' -replace '_+','_' -replace '^_|_$',''
            }
            Write-Host "  $($sub.name)" -ForegroundColor DarkGray
            Write-Host "  Tag sugerida: " -NoNewline -ForegroundColor White
            Write-Host $suggestName -NoNewline -ForegroundColor Cyan
            Write-Host " [ENTER=manter]: " -NoNewline -ForegroundColor DarkGray
            $newName = (Read-Host).Trim()
            if ($newName -ne "") {
                $cleanName = $newName.ToUpper() -replace '[^A-Z0-9\-_]','_' -replace '_+','_' -replace '^_|_$',''
                $existingCsvMap[$sub.id] = $cleanName
            } else {
                $existingCsvMap[$sub.id] = $suggestName
            }
        }
    } else {
        foreach ($sub in $includedSubs) {
            if (-not $existingCsvMap.ContainsKey($sub.id)) {
                $existingCsvMap[$sub.id] = $sub.name.ToUpper() -replace '[^A-Z0-9\-]','_' -replace '_+','_' -replace '^_|_$',''
            }
        }
    }

    # Gravar CSV
    $csvLines = @("subscriptionId;subscriptionName")
    foreach ($sub in $includedSubs) {
        $tagName = $existingCsvMap[$sub.id]
        $csvLines += "$($sub.id);$tagName"
    }
    $csvContent = $csvLines -join "`r`n"
    [System.IO.File]::WriteAllText($csvPath, $csvContent, [System.Text.Encoding]::UTF8)
    Write-Ok "subscription_mapping.csv gravado com $($includedSubs.Count) entrada(s)"

    # Atualizar config.json com exclusoes
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
    $cfg.descoberta.excluirSubscriptions = $excludedSubIds
    $cfg | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8

} elseif ($existingCsvMap.Count -gt 0) {
    Write-Ok "Usando CSV existente com $($existingCsvMap.Count) subscription(s) ja mapeada(s)"
} else {
    Write-Warn "Nenhuma subscription descoberta automaticamente."
    Write-Info "A auto-descoberta via metadados MDE ocorrera na primeira execucao."
    Write-Info "Voce tambem pode editar manualmente: $csvPath"
}

# ============================================================================
# ETAPA 5 -- PARAMETROS DE CLASSIFICACAO
# ============================================================================
Show-Step 5 $totalSteps "PARAMETROS DE CLASSIFICACAO"

$cfg = Get-Content $configPath -Raw | ConvertFrom-Json

Write-Host "  Parametros atuais (ENTER = manter todos):" -ForegroundColor White
Write-Host ""
Write-Host "  +---------------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  |  INATIVO_7D  : a partir de $($cfg.classificacao.diasInativo7d) dias sem comunicacao com MDE        |" -ForegroundColor Cyan
Write-Host "  |  INATIVO_40D : a partir de $($cfg.classificacao.diasInativo40d) dias sem comunicacao com MDE       |" -ForegroundColor Cyan
Write-Host "  |  EFEMERO     : VM com menos de $($cfg.classificacao.horasEfemero) horas de vida                    |" -ForegroundColor Cyan
Write-Host "  |  Horario     : $($cfg.agendamento.horarioExecucao) -- a cada $($cfg.agendamento.intervaloHoras)h                               |" -ForegroundColor Cyan
Write-Host "  |  Modo atual  : $(if($cfg.execucao.reportOnly){'REPORT-ONLY [seguro -- sem alteracoes]     '}else{'EXECUCAO REAL [aplica tags no MDE]       '}) |" -ForegroundColor $(if($cfg.execucao.reportOnly){"Green"}else{"Yellow"})
Write-Host "  +---------------------------------------------------------------------+" -ForegroundColor DarkGray

if (Confirm-YN "Deseja alterar algum parametro?" $false) {
    $v = Prompt-WithDefault "Dias para INATIVO_7D" $cfg.classificacao.diasInativo7d.ToString()
    if ($v -match '^\d+$') { $cfg.classificacao.diasInativo7d = [int]$v }

    $v = Prompt-WithDefault "Dias para INATIVO_40D" $cfg.classificacao.diasInativo40d.ToString()
    if ($v -match '^\d+$') { $cfg.classificacao.diasInativo40d = [int]$v }

    $v = Prompt-WithDefault "Horas para EFEMERO" $cfg.classificacao.horasEfemero.ToString()
    if ($v -match '^\d+$') { $cfg.classificacao.horasEfemero = [int]$v }

    $v = Prompt-WithDefault "Horario execucao diaria (HH:mm)" $cfg.agendamento.horarioExecucao
    if ($v -match '^\d{2}:\d{2}$') { $cfg.agendamento.horarioExecucao = $v }

    $v = Prompt-WithDefault "Intervalo entre execucoes (horas)" $cfg.agendamento.intervaloHoras.ToString()
    if ($v -match '^\d+$') { $cfg.agendamento.intervaloHoras = [int]$v }

    $cfg | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
    Write-Ok "Parametros atualizados"
} else {
    Write-Ok "Parametros mantidos"
}

# ============================================================================
# ETAPA 6 -- TESTE REPORT-ONLY + AGENDAMENTO
# ============================================================================
Show-Step 6 $totalSteps "TESTE REPORT-ONLY + AGENDAMENTO"

$cfg = Get-Content $configPath -Raw | ConvertFrom-Json

if ($tokenOk) {
    Write-Host "  O script sera executado em modo REPORT-ONLY." -ForegroundColor White
    Write-Host "  NENHUMA tag sera aplicada no MDE -- apenas relatorio." -ForegroundColor Gray

    if (Confirm-YN "Executar teste agora?" $true) {
        Write-Host ""
        Write-Host "  -----------------------------------------------------------------------" -ForegroundColor DarkGray

        Push-Location (Join-Path $scriptRoot "01-Classificacao-Servidores")
        try {
            & $mainScript `
                -tenantId                  $tenantIdInput `
                -appId                     $appIdInput `
                -appSecret                 $appSecretInput `
                -subscriptionMappingPath   $csvPath `
                -autoDiscoverSubscriptions $true `
                -saveDiscoveredCsv         $true `
                -excludeSubscriptions      $excludedSubIds `
                -reportOnly                $true

            $reportsDir = Join-Path $scriptRoot "Relatorios"
            $logsDir    = Join-Path $scriptRoot "Logs"
            foreach ($d in @($reportsDir, $logsDir)) {
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            }
            Get-ChildItem ".\ServerTags-Report-*.csv"  -ErrorAction SilentlyContinue | Move-Item -Destination $reportsDir -Force
            Get-ChildItem ".\ServerTags-Log-*.log"     -ErrorAction SilentlyContinue | Move-Item -Destination $logsDir -Force
            Get-ChildItem ".\ServerTags-Summary-*.txt" -ErrorAction SilentlyContinue | Move-Item -Destination $reportsDir -Force

            Write-Host "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
            Write-Ok "Teste concluido! Relatorios em: $reportsDir"

            # Distribuicao do relatorio
            $latestReport = Get-ChildItem $reportsDir -Filter "ServerTags-Report-*.csv" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestReport) {
                Write-Host ""
                Write-Host "  Distribuicao de classificacao:" -ForegroundColor White
                Import-Csv $latestReport.FullName -Delimiter ";" -ErrorAction SilentlyContinue |
                    Group-Object TargetTag | Sort-Object Count -Descending |
                    ForEach-Object {
                        Write-Host "    $($_.Name.PadRight(35)) $($_.Count.ToString().PadLeft(4))" -ForegroundColor Cyan
                    }
            }
        } catch {
            Write-Err "Erro durante teste: $($_.Exception.Message)"
        } finally {
            Pop-Location
        }
    }
} else {
    Write-Warn "Teste pulado -- autenticacao nao validada. Configure as credenciais e execute novamente."
}

# Agendamento
Write-Host ""
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    if (Confirm-YN "Instalar Scheduled Task para execucao diaria automatica?" $true) {
        $installScript = Join-Path $scriptRoot "Install-ScheduledTask.ps1"
        if (Test-Path $installScript) {
            & $installScript
            Write-Ok "Scheduled Task instalada"
        } else {
            Write-Warn "Install-ScheduledTask.ps1 nao encontrado"
        }
    }
} else {
    Write-Info "Execute Install-ScheduledTask.ps1 como Administrador para o agendamento automatico."
}

# ============================================================================
# RESUMO FINAL
# ============================================================================
$cfg      = Get-Content $configPath -Raw | ConvertFrom-Json
$csvCount = if (Test-Path $csvPath) { @(Import-Csv $csvPath -Delimiter ";").Count } else { 0 }

Write-Host ""
Write-Host "  +===================================================================+" -ForegroundColor Green
Write-Host "  |                   SETUP CONCLUIDO                                |" -ForegroundColor Green
Write-Host "  +===================================================================+" -ForegroundColor DarkGray
Write-Host "  |                                                                   |" -ForegroundColor DarkGray
Write-Host "  |  Tenant ID  : $($tenantIdInput.PadRight(37))|" -ForegroundColor Cyan
Write-Host "  |  App ID     : $($appIdInput.PadRight(37))|" -ForegroundColor Cyan
Write-Host "  |  Sub map.   : $($csvCount) subscription(s) incluida(s) / $($excludedSubIds.Count) excluida(s)$((' ').PadRight([Math]::Max(0, 8-$csvCount.ToString().Length-$excludedSubIds.Count.ToString().Length)))|" -ForegroundColor Cyan
Write-Host "  |  Modo       : $(if($cfg.execucao.reportOnly){'REPORT-ONLY (seguro)'.PadRight(37)}else{'EXECUCAO REAL -- aplica tags'.PadRight(37)})|" -ForegroundColor $(if($cfg.execucao.reportOnly){"Green"}else{"Yellow"})
Write-Host "  |                                                                   |" -ForegroundColor DarkGray
Write-Host "  +-------------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  |  PROXIMOS PASSOS:                                                 |" -ForegroundColor Yellow
Write-Host "  |  1. Revise o relatorio em .\Relatorios\                           |" -ForegroundColor White
Write-Host "  |  2. Valide distribuicao de tags com a equipe de infra/SOC         |" -ForegroundColor White
Write-Host "  |  3. Quando aprovado: edite config.json > reportOnly = false       |" -ForegroundColor White
Write-Host "  |  4. Crie Device Groups no portal MDE (security.microsoft.com)     |" -ForegroundColor White
Write-Host "  +===================================================================+" -ForegroundColor Green
Write-Host ""
