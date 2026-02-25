<#
.SYNOPSIS
    TEST-Lab-E2E.ps1 v4.0.0 — Validacao End-to-End | MDE ServerTags
    Developed by Rafael França — Open Source Community Edition
    Data: 24/02/2026

.DESCRIPTION
    Script interativo e inteligente de validacao completa do MDE ServerTags.
    Executa 10 etapas com explicacao detalhada, confirmacoes interativas e
    criacao de Device Groups via Microsoft Graph API.

      Etapa 0 — Verificar/instalar PowerShell 7
      Etapa 1 — Pre-requisitos do ambiente (SO, arquivos, rede, Graph API)
      Etapa 2 — Service Principal & Credenciais (detecta, cria ou seleciona)
      Etapa 3 — Autenticacao OAuth2 (MDE + ARM + Microsoft Graph)
      Etapa 4 — App Registration & Permissoes
      Etapa 5 — Configuracao ativa (config.json)
      Etapa 6 — Classificacao de servidores (Report ou Execute)
      Etapa 7 — Device Groups (cria AAD Security Groups + atribui maquinas)
      Etapa 8 — Verificar extensoes AAD + MDE em VMs ligadas
      Etapa 9 — Geracao de relatorio HTML detalhado

    MODOS DE OPERACAO:
      -Report   Modo seguro. Classifica e gera relatorio sem aplicar nada.
      -Execute  Modo real. Aplica tags, cria Device Groups, atribui maquinas.

    PARADIGMA v4.0:
      - O NOME DA SUBSCRIPTION e usado diretamente como nome do Device Group
      - Maquinas Windows e Linux sao inseridas nos grupos automaticamente
      - Cada acao pede confirmacao; o script NUNCA quebra se voce recusar
      - Propagacao de API e respeitada com timers inteligentes
      - Service Principal: detecta existente ou cria novo com sugestao de nome

.PARAMETER Report
    Modo REPORT-ONLY. Seguro, nenhuma alteracao aplicada.

.PARAMETER Execute
    Modo EXECUCAO REAL. Aplica tags, cria Device Groups e atribui maquinas.

.PARAMETER AppSecret
    Client Secret. Se omitido, usa automaticamente o secret do config.json.

.PARAMETER TenantId
    Azure Tenant ID. Se omitido, le do config.json.

.PARAMETER AppId
    Application (Client) ID. Se omitido, le do config.json.

.PARAMETER SkipPS7Install
    Nao tenta instalar PowerShell 7 automaticamente.

.PARAMETER SkipGroupCreation
    Pula a criacao de Device Groups via Graph (apenas documenta).

.PARAMETER PropagationDelay
    Segundos de espera entre operacoes de API para propagacao. Padrao: 8.

.PARAMETER OutputDir
    Diretorio para salvar o relatorio HTML. Padrao: .\Relatorios

.EXAMPLE
    .\TEST-Lab-E2E.ps1 -Report

.EXAMPLE
    .\TEST-Lab-E2E.ps1 -Execute

.EXAMPLE
    .\TEST-Lab-E2E.ps1 -Execute -PropagationDelay 15

.NOTES
    Versao : 4.0.0 | 24/02/2026
    Author : Rafael França — Community Edition
    GitHub : https://github.com/rfranca777/MDE-ServerTags
    MDE    : Microsoft Defender for Endpoint
    Reqs   : Graph API (Group.ReadWrite.All, Device.Read.All)
#>

[CmdletBinding(DefaultParameterSetName = "Report")]
param (
    [Parameter(ParameterSetName = "Report")]
    [switch]$Report,

    [Parameter(ParameterSetName = "Execute")]
    [switch]$Execute,

    [Parameter(Mandatory = $false)]
    [string]$AppSecret,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPS7Install,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGroupCreation,

    [Parameter(Mandatory = $false)]
    [int]$PropagationDelay = 8,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

# ============================================================================
# CONFIGURACAO INICIAL
# ============================================================================
$ErrorActionPreference = "Continue"
$script:Version     = "4.0.0"
$script:ScriptRoot  = $PSScriptRoot
$script:RunTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$script:StartTime   = Get-Date

$script:IsReportOnly = -not $Execute.IsPresent

# Colecoes de resultados
$script:Results  = [ordered]@{}
$script:Prereqs  = [System.Collections.Generic.List[pscustomobject]]::new()
$script:Errors   = [System.Collections.Generic.List[string]]::new()
$script:Warnings = [System.Collections.Generic.List[string]]::new()
$script:DeviceGroupsCreated = [System.Collections.Generic.List[pscustomobject]]::new()
$script:ActionsLog = [System.Collections.Generic.List[pscustomobject]]::new()

# Estado de autenticacao
$script:ClassificationData   = $null
$script:ClassificationOutput = ""
$script:CsvReportPath        = ""
$script:TokenObtained        = $false
$script:GraphTokenObtained   = $false
$script:MdeToken             = ""
$script:GraphToken           = ""
$script:ArmToken             = ""
$script:MdeAuthError         = ""
$script:ServerCount          = 0
$script:TotalSteps           = 10
$script:SkippedActions       = [System.Collections.Generic.List[string]]::new()
$script:ExtensionResults     = $null
$script:PropDelay            = $PropagationDelay

# ============================================================================
# FUNCOES UI — METASPLOIT-INSPIRED
# ============================================================================
function Show-MetasploitBanner {
    $asciiArt = @"

        ___  ___ ____  _____   ____                          _____
       |  \/  ||  _ \| ____| / ___|  ___ _ ____   _____ _ _|_   _|_ _  __ _ ___
       | |\/| || | | |  _|   \___ \ / _ \ '__\ \ / / _ \ '__|| |/ _`` |/ _`` / __|
       | |  | || |_| | |___   ___) |  __/ |   \ V /  __/ |   | | (_| | (_| \__ \
       |_|  |_||____/|_____| |____/ \___|_|    \_/ \___|_|   |_|\__,_|\__, |___/
                                                                       |___/
"@
    Write-Host $asciiArt -ForegroundColor Red

    $subCount = 0
    $csvPath = Join-Path $script:ScriptRoot "subscription_mapping.csv"
    if (Test-Path $csvPath) {
        try {
            $csvRows = Import-Csv $csvPath -Delimiter ";" -ErrorAction SilentlyContinue
            $subCount = @($csvRows | Where-Object { $_.subscriptionId -and $_.subscriptionId -notmatch '^aaaa' }).Count
        } catch {}
    }

    $modeText = if ($script:IsReportOnly) { "report-only" } else { "execute (tags + groups + assign)" }
    $modeColor = if ($script:IsReportOnly) { "Green" } else { "Yellow" }

    Write-Host "       =[ " -NoNewline -ForegroundColor Blue
    Write-Host "mde-servertags v$($script:Version)" -NoNewline -ForegroundColor White
    Write-Host " — $(Get-Date -Format 'dd/MM/yyyy')" -NoNewline -ForegroundColor DarkGray
    Write-Host "                         ]" -ForegroundColor Blue

    Write-Host "  + -- --=[ " -NoNewline -ForegroundColor Blue
    Write-Host "10 etapas" -NoNewline -ForegroundColor Cyan
    Write-Host " — classificacao automatica por subscription" -NoNewline -ForegroundColor DarkGray
    Write-Host "    ]" -ForegroundColor Blue

    Write-Host "  + -- --=[ " -NoNewline -ForegroundColor Blue
    Write-Host "5 lifecycle tags" -NoNewline -ForegroundColor Cyan
    Write-Host " — $subCount subscription(s) mapeadas" -NoNewline -ForegroundColor DarkGray
    Write-Host "         ]" -ForegroundColor Blue

    Write-Host "  + -- --=[ " -NoNewline -ForegroundColor Blue
    Write-Host "graph api" -NoNewline -ForegroundColor Cyan
    Write-Host " — aad security groups — intune ready" -NoNewline -ForegroundColor DarkGray
    Write-Host "       ]" -ForegroundColor Blue

    Write-Host "  + -- --=[ " -NoNewline -ForegroundColor Blue
    Write-Host "mode: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$modeText" -NoNewline -ForegroundColor $modeColor
    $pad = 52 - $modeText.Length
    if ($pad -lt 0) { $pad = 0 }
    Write-Host "$(' ' * $pad)]" -ForegroundColor Blue

    Write-Host ""
    Write-Host "       Microsoft Defender for Endpoint — Security Automation" -ForegroundColor DarkGray
    Write-Host "       Rafael França | MDE ServerTags — Community Edition" -ForegroundColor DarkGray
    Write-Host "       Open Source — github.com/rfranca777/MDE-ServerTags" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Step {
    param([int]$Num, [string]$Title, [string]$Desc = "")
    Write-Host ""
    Write-Host "  ==================================================================" -ForegroundColor DarkCyan
    Write-Host "  === ETAPA $Num/$($script:TotalSteps) — $Title" -ForegroundColor White
    Write-Host "  ==================================================================" -ForegroundColor DarkCyan
    if ($Desc) {
        Write-Host ""
        Write-Host "  $Desc" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Write-Ok      { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:Warnings.Add($m) }
function Write-Err     { param([string]$m) Write-Host "  [ERR]  $m" -ForegroundColor Red;    $script:Errors.Add($m) }
function Write-Info    { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan }
function Write-Explain { param([string]$m) Write-Host "         $m" -ForegroundColor DarkGray }

function Add-PrereqResult {
    param([string]$Name, [string]$Status, [string]$Detail, [string]$Value = "")
    $script:Prereqs.Add([pscustomobject]@{
        Name = $Name; Status = $Status; Detail = $Detail; Value = $Value
    })
}

function Log-Action {
    param([string]$Action, [string]$Status, [string]$Detail = "")
    $script:ActionsLog.Add([pscustomobject]@{
        Timestamp = Get-Date -Format "HH:mm:ss"; Action = $Action
        Status = $Status; Detail = $Detail
    })
}

function Confirm-Action {
    param(
        [string]$Question,
        [string]$DefaultAnswer = "S",
        [string]$ActionName = ""
    )
    $hint = if ($DefaultAnswer -eq "S") { "(S/n)" } else { "(s/N)" }
    Write-Host ""
    Write-Host "  [?] $Question $hint : " -NoNewline -ForegroundColor Yellow
    $r = Read-Host
    $r = if ($null -eq $r) { "" } else { $r.Trim() }
    if ($r -eq "") { $r = $DefaultAnswer }

    if ($r -match '^[Nn]') {
        if ($ActionName) {
            $script:SkippedActions.Add($ActionName)
            Write-Info "Acao ignorada: $ActionName (continuando...)"
            Log-Action $ActionName "IGNORADO" "Recusado pelo usuario"
        }
        return $false
    }
    if ($ActionName) { Log-Action $ActionName "ACEITO" "Confirmado pelo usuario" }
    return $true
}

function Wait-Propagation {
    param(
        [int]$Seconds = $script:PropDelay,
        [string]$Message = "Aguardando propagacao da API"
    )
    if ($Seconds -le 0) { return }
    Write-Host ""
    for ($i = $Seconds; $i -ge 1; $i--) {
        $bar = ([char]9608).ToString() * ($Seconds - $i + 1)
        $empty = ([char]9617).ToString() * ($i - 1)
        $pct = [math]::Round(($Seconds - $i + 1) / $Seconds * 100)
        Write-Host "`r  [*] $Message... [$bar$empty] ${i}s ($pct%)" -NoNewline -ForegroundColor DarkYellow
        Start-Sleep -Seconds 1
    }
    Write-Host "`r  [OK] $Message... concluido.                                          " -ForegroundColor Green
    Write-Host ""
}

function Show-Separator {
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
}

function Format-GroupName {
    param([string]$SubscriptionName, [string]$Prefix = "MDE")
    $sanitized = $SubscriptionName -replace '[^a-zA-Z0-9\s\-_]', ''
    $sanitized = $sanitized.Trim() -replace '\s+', '-'
    if ($sanitized.Length -gt 100) { $sanitized = $sanitized.Substring(0, 100) }
    return "$Prefix-$sanitized"
}

function Format-MailNickname {
    param([string]$Name)
    $nick = $Name -replace '[^a-zA-Z0-9]', ''
    if ([string]::IsNullOrEmpty($nick)) { $nick = "mdegroup" + (Get-Date -Format "yyyyMMddHHmmss") }
    if ($nick.Length -gt 64) { $nick = $nick.Substring(0, 64) }
    return $nick
}

# ============================================================================
# FUNCOES — RESILIENCIA DE API (TOKEN REFRESH + RETRY 429/5xx)
# ============================================================================
function Refresh-AllTokens {
    <#
    .SYNOPSIS
        Re-obtem todos os tokens OAuth2 (MDE, ARM, Graph) quando expirados.
        Usa as credenciais ja armazenadas em $script:Results["Credentials"].
    #>
    $crd = $script:Results["Credentials"]
    if (-not $crd -or -not $crd.AppId -or -not $crd.AppSecret -or -not $crd.TenantId) {
        Write-Warn "Refresh-AllTokens: credenciais nao disponiveis"
        return $false
    }
    $tokenUri = "https://login.microsoftonline.com/$($crd.TenantId)/oauth2/v2.0/token"
    $refreshed = $false

    # MDE Token
    try {
        $body = @{
            client_id = $crd.AppId; client_secret = $crd.AppSecret
            grant_type = "client_credentials"
            scope = "https://api.securitycenter.microsoft.com/.default"
        }
        $resp = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:MdeToken = $resp.access_token
        $script:TokenObtained = $true
        $refreshed = $true
        Write-Info "Token MDE renovado (TTL: $([math]::Round($resp.expires_in / 60)) min)"
    } catch {
        Write-Warn "Falha ao renovar token MDE: $($_.Exception.Message)"
    }

    # Graph Token
    try {
        $body = @{
            client_id = $crd.AppId; client_secret = $crd.AppSecret
            grant_type = "client_credentials"
            scope = "https://graph.microsoft.com/.default"
        }
        $resp = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:GraphToken = $resp.access_token
        $script:GraphTokenObtained = $true
        $refreshed = $true
        Write-Info "Token Graph renovado (TTL: $([math]::Round($resp.expires_in / 60)) min)"
    } catch {
        Write-Warn "Falha ao renovar token Graph: $($_.Exception.Message)"
    }

    # ARM Token
    try {
        $body = @{
            client_id = $crd.AppId; client_secret = $crd.AppSecret
            grant_type = "client_credentials"
            scope = "https://management.azure.com/.default"
        }
        $resp = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $body `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $script:ArmToken = $resp.access_token
        $refreshed = $true
        Write-Info "Token ARM renovado (TTL: $([math]::Round($resp.expires_in / 60)) min)"
    } catch {
        Write-Warn "Falha ao renovar token ARM: $($_.Exception.Message)"
    }

    return $refreshed
}

function Invoke-ApiWithRetry {
    <#
    .SYNOPSIS
        Wrapper resiliente para chamadas REST API.
        Trata: 429 (throttling), 5xx (server errors), 401/403 (token expirado).
        Retry com exponential backoff. Refresh automatico de tokens.
    .PARAMETER Uri
        URI da API.
    .PARAMETER Method
        Metodo HTTP (GET, POST, PATCH, DELETE). Padrao: GET.
    .PARAMETER Headers
        Hashtable de headers (incluindo Authorization).
    .PARAMETER Body
        Body da requisicao (string JSON).
    .PARAMETER ContentType
        Content-Type. Padrao: application/json.
    .PARAMETER MaxRetries
        Numero maximo de tentativas. Padrao: 3.
    .PARAMETER BaseDelaySec
        Delay base em segundos para backoff. Padrao: 5.
    .PARAMETER ApiName
        Nome amigavel da API para logs.
    #>
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType = "application/json",
        [int]$MaxRetries = 3,
        [int]$BaseDelaySec = 5,
        [string]$ApiName = "API"
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            $params = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ErrorAction = "Stop"
            }
            if ($Body) {
                $params.Body        = $Body
                $params.ContentType = $ContentType
            }

            return (Invoke-RestMethod @params)
        } catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            $errMsg  = $_.Exception.Message
            $errBody = try { $_.ErrorDetails.Message } catch { '' }

            # ── Token expirado (401/403) → refresh + retry ──
            if ($statusCode -in @(401, 403) -and $attempt -le $MaxRetries) {
                Write-Warn "  [$ApiName] HTTP $statusCode — token expirado. Renovando tokens (tentativa $attempt/$MaxRetries)..."
                try { $null = Refresh-AllTokens } catch { }
                # Atualizar header Authorization com novo token
                if ($Headers -and $Headers.ContainsKey('Authorization')) {
                    if ($Uri -match 'graph\.microsoft\.com' -and $script:GraphToken) {
                        $Headers['Authorization'] = "Bearer $($script:GraphToken)"
                    } elseif ($Uri -match 'securitycenter' -and $script:MdeToken) {
                        $Headers['Authorization'] = "Bearer $($script:MdeToken)"
                    } elseif ($Uri -match 'management\.azure\.com' -and $script:ArmToken) {
                        $Headers['Authorization'] = "Bearer $($script:ArmToken)"
                    }
                }
                Start-Sleep -Seconds 2
                continue
            }

            # ── Throttling (429) → retry com Retry-After ou backoff ──
            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $retryAfter = $BaseDelaySec * [Math]::Pow(2, $attempt - 1)
                try {
                    $raValue = $_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1
                    if ($raValue) { $retryAfter = [Math]::Max([int]$raValue, 1) }
                } catch { }
                Write-Warn "  [$ApiName] Throttled (429). Aguardando ${retryAfter}s (tentativa $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            # ── Erro de servidor (5xx) → retry com backoff ──
            if ($statusCode -ge 500 -and $attempt -le $MaxRetries) {
                $delay = $BaseDelaySec * $attempt
                Write-Warn "  [$ApiName] Erro $statusCode. Retry em ${delay}s (tentativa $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $delay
                continue
            }

            # ── Erro nao-retryavel ou ultima tentativa → re-throw ──
            throw
        }
    }
}

# ============================================================================
# ETAPA 0 — VERIFICAR POWERSHELL 7
# ============================================================================
function Test-AndInstall-PowerShell7 {
    Show-Step 0 "VERIFICAR POWERSHELL 7" `
        "O PowerShell 7 oferece melhor compatibilidade com APIs REST e modulos Azure.`n  Se nao estiver instalado, o script tenta instalar automaticamente."

    $psVer = $PSVersionTable.PSVersion
    Write-Info "PowerShell atual: v$($psVer.Major).$($psVer.Minor).$($psVer.Build) ($($PSVersionTable.PSEdition))"

    if ($psVer.Major -ge 7) {
        Write-Ok "PowerShell 7+ detectado. Versao ideal para este script."
        Add-PrereqResult "PowerShell" "OK" "v$($psVer.Major).$($psVer.Minor).$($psVer.Build) ($($PSVersionTable.PSEdition))"
        $script:Results["PowerShell"] = @{ Status = "OK"; Version = "$psVer" }
        return $true
    }

    $ps7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
    if (Test-Path $ps7Path) {
        $ps7Ver = & $ps7Path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        Write-Ok "PowerShell 7 instalado: $ps7Path (v$ps7Ver)"
        Write-Warn "Executando com PS $($psVer.Major).$($psVer.Minor). Recomendado: pwsh.exe"
        Add-PrereqResult "PowerShell" "WARN" "PS7 instalado mas executando em PS$($psVer.Major)" "$psVer"
        $script:Results["PowerShell"] = @{ Status = "WARN"; Version = "$psVer"; PS7 = $ps7Ver }
        return $true
    }

    if ($SkipPS7Install.IsPresent) {
        Write-Warn "PS7 nao instalado. -SkipPS7Install ativo."
        Add-PrereqResult "PowerShell" "WARN" "PS7 nao instalado (skip)" "$psVer"
        $script:Results["PowerShell"] = @{ Status = "WARN"; Version = "$psVer" }
        return $true
    }

    if (-not (Confirm-Action "PowerShell 7 nao encontrado. Deseja instalar agora?" "S" "Instalar PowerShell 7")) {
        Write-Info "Continuando com PS $($psVer.Major)."
        Add-PrereqResult "PowerShell" "WARN" "PS7 nao instalado (recusado)" "$psVer"
        $script:Results["PowerShell"] = @{ Status = "WARN"; Version = "$psVer" }
        return $true
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warn "Instalacao requer privilegios de Administrador."
        Add-PrereqResult "PowerShell" "WARN" "PS7 nao instalado (sem Admin)" "$psVer"
        $script:Results["PowerShell"] = @{ Status = "WARN"; Version = "$psVer" }
        return $true
    }

    try {
        $null = & winget --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Info "Instalando via winget..."
            & winget install Microsoft.PowerShell --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $ps7Path)) {
                $ps7Ver = & $ps7Path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
                Write-Ok "PowerShell 7 instalado (v$ps7Ver)"
                Add-PrereqResult "PowerShell" "OK" "PS7 instalado via winget ($ps7Ver)" "$ps7Ver"
                $script:Results["PowerShell"] = @{ Status = "OK"; Version = $ps7Ver }
                return $true
            }
        }
    } catch {}

    Write-Info "Tentando via download MSI..."
    $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.7/PowerShell-7.4.7-win-x64.msi"
    $msiPath = Join-Path $env:TEMP "PowerShell-7-Install.msi"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing -TimeoutSec 120
        $proc = Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet REGISTER_MANIFEST=1" -Wait -PassThru
        if ($proc.ExitCode -eq 0 -and (Test-Path $ps7Path)) {
            $ps7Ver = & $ps7Path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
            Write-Ok "PowerShell 7 instalado via MSI (v$ps7Ver)"
            Add-PrereqResult "PowerShell" "OK" "PS7 instalado via MSI ($ps7Ver)" "$ps7Ver"
            $script:Results["PowerShell"] = @{ Status = "OK"; Version = $ps7Ver }
            return $true
        }
    } catch {
        Write-Warn "Falha no download/instalacao: $($_.Exception.Message)"
    } finally {
        Remove-Item $msiPath -ErrorAction SilentlyContinue
    }

    Write-Warn "Nao foi possivel instalar PS7. Continuando com PS $($psVer.Major)."
    Add-PrereqResult "PowerShell" "WARN" "PS7 nao instalado" "$psVer"
    $script:Results["PowerShell"] = @{ Status = "WARN"; Version = "$psVer" }
    return $true
}

# ============================================================================
# ETAPA 1 — PRE-REQUISITOS
# ============================================================================
function Test-Prerequisites {
    Show-Step 1 "PRE-REQUISITOS DO AMBIENTE" `
        "Validando SO, arquivos, conectividade de rede e Microsoft Graph API."

    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osCaption = if ($osInfo) { $osInfo.Caption } else { $env:OS }
    Write-Info "SO: $osCaption"
    Add-PrereqResult "Sistema Operacional" "OK" $osCaption

    Write-Info "Hostname: $env:COMPUTERNAME | Usuario: $env:USERDOMAIN\$env:USERNAME"
    Add-PrereqResult "Hostname" "OK" $env:COMPUTERNAME
    Add-PrereqResult "Usuario" "OK" "$env:USERDOMAIN\$env:USERNAME"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Ok "Executando como Administrador"
        Add-PrereqResult "Administrador" "OK" "Sim"
    } else {
        Write-Info "Sem privilegio Admin (ok para validacao)"
        Add-PrereqResult "Administrador" "WARN" "Nao (ok para validacao)"
    }

    Show-Separator
    Write-Info "Verificando arquivos obrigatorios..."

    $configPath = Join-Path $script:ScriptRoot "config.json"
    if (Test-Path $configPath) {
        $configSize = (Get-Item $configPath).Length
        Write-Ok "config.json encontrado ($configSize bytes)"
        Add-PrereqResult "config.json" "OK" "Encontrado ($configSize bytes)"
    } else {
        Write-Err "config.json NAO encontrado em: $configPath"
        Add-PrereqResult "config.json" "ERR" "Nao encontrado"
        return $false
    }

    $mainScript = Join-Path $script:ScriptRoot "01-Classificacao-Servidores\Sync-MDE-ServerTags-BySubscription.ps1"
    if (Test-Path $mainScript) {
        $lineCount = (Get-Content $mainScript | Measure-Object -Line).Lines
        Write-Ok "Script principal encontrado ($lineCount linhas)"
        Add-PrereqResult "Script Principal" "OK" "$lineCount linhas"
    } else {
        Write-Err "Script principal NAO encontrado: $mainScript"
        Add-PrereqResult "Script Principal" "ERR" "Nao encontrado"
        return $false
    }

    $runDaily = Join-Path $script:ScriptRoot "Run-Daily.ps1"
    if (Test-Path $runDaily) {
        Write-Ok "Run-Daily.ps1 encontrado"
        Add-PrereqResult "Run-Daily.ps1" "OK" "Encontrado"
    } else {
        Write-Warn "Run-Daily.ps1 nao encontrado (nao bloqueia validacao)"
        Add-PrereqResult "Run-Daily.ps1" "WARN" "Nao encontrado"
    }

    $csvPath = Join-Path $script:ScriptRoot "subscription_mapping.csv"
    if (Test-Path $csvPath) {
        try {
            $csvRows = Import-Csv $csvPath -Delimiter ";" -ErrorAction Stop
            $validRows = @($csvRows | Where-Object { $_.subscriptionId -and $_.subscriptionId -notmatch '^aaaa' })
            Write-Ok "subscription_mapping.csv: $($validRows.Count) subscription(s)"
            Add-PrereqResult "subscription_mapping.csv" "OK" "$($validRows.Count) subscription(s)"
        } catch {
            Write-Warn "CSV existe mas nao pode ser lido"
            Add-PrereqResult "subscription_mapping.csv" "WARN" "Erro de leitura"
        }
    } else {
        Write-Info "CSV nao encontrado (auto-descoberta ativa)"
        Add-PrereqResult "subscription_mapping.csv" "WARN" "Nao encontrado (auto-descoberta)"
    }

    foreach ($dir in @("Relatorios", "Logs")) {
        $dirPath = Join-Path $script:ScriptRoot $dir
        if (-not (Test-Path $dirPath)) {
            New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
            Write-Info "Pasta criada: $dir\"
        }
    }
    Add-PrereqResult "Pastas de Saida" "OK" "Relatorios\ e Logs\"

    Show-Separator
    Write-Info "Testando conectividade de rede (incluindo Microsoft Graph)..."

    $endpoints = @(
        @{ Name = "Azure AD (login.microsoftonline.com)"; Url = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"; Critical = $true },
        @{ Name = "API MDE (api.securitycenter.microsoft.com)"; Url = "https://api.securitycenter.microsoft.com"; Critical = $true },
        @{ Name = "Microsoft Graph (graph.microsoft.com)"; Url = "https://graph.microsoft.com/v1.0/`$metadata"; Critical = $false },
        @{ Name = "Azure ARM (management.azure.com)"; Url = "https://management.azure.com"; Critical = $false }
    )

    foreach ($ep in $endpoints) {
        try {
            $resp = Invoke-WebRequest -Uri $ep.Url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Ok "$($ep.Name) — HTTP $([int]$resp.StatusCode)"
            Add-PrereqResult $ep.Name "OK" "HTTP $([int]$resp.StatusCode)"
        } catch {
            $httpCode = 0
            if ($_.Exception.Response) { $httpCode = [int]$_.Exception.Response.StatusCode }
            if ($httpCode -in @(401, 403)) {
                Write-Ok "$($ep.Name) — HTTP $httpCode (acessivel)"
                Add-PrereqResult $ep.Name "OK" "HTTP $httpCode (acessivel)"
            } elseif ($ep.Critical) {
                Write-Err "$($ep.Name) — FALHA"
                Add-PrereqResult $ep.Name "ERR" "Falha de conectividade"
                return $false
            } else {
                Write-Warn "$($ep.Name) — nao acessivel (nao bloqueante)"
                Add-PrereqResult $ep.Name "WARN" "Nao acessivel"
            }
        }
    }

    Show-Separator
    Write-Info "Verificando Azure CLI..."

    $azCliVer = $null; $azCliLogged = $false; $azCliUser = ""
    try {
        $azVer = & az version --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($azVer) {
            $azCliVer = $azVer.'azure-cli'
            Write-Ok "Azure CLI v$azCliVer instalada"
            Add-PrereqResult "Azure CLI" "OK" "v$azCliVer"

            $azAcct = & az account show --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($azAcct -and $azAcct.user) {
                $azCliLogged = $true
                $azCliUser = $azAcct.user.name
                Write-Ok "Autenticado como: $azCliUser"
                Add-PrereqResult "Azure CLI Login" "OK" $azCliUser
            } else {
                Write-Warn "Azure CLI nao autenticado (az login recomendado)"
                Add-PrereqResult "Azure CLI Login" "WARN" "Nao autenticado"
            }
        }
    } catch {
        Write-Info "Azure CLI nao disponivel (opcional)"
        Add-PrereqResult "Azure CLI" "WARN" "Nao instalado"
    }
    $script:Results["AzureCLI"] = @{ Version = $azCliVer; LoggedIn = $azCliLogged; User = $azCliUser }

    Write-Host ""
    Write-Ok "Pre-requisitos validados com sucesso."
    return $true
}

# ============================================================================
# ETAPA 2 — SERVICE PRINCIPAL & CREDENCIAIS (INTELIGENTE)
# ============================================================================
function Resolve-Credentials {
    Show-Step 2 "SERVICE PRINCIPAL & CREDENCIAIS" `
        "Detecta Service Principals existentes, cria novos ou usa credenciais`n  ja configuradas. Sugere nomes padroes logicos."

    $configPath = Join-Path $script:ScriptRoot "config.json"
    $cfg = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json

    # ── DETECTAR VALORES PLACEHOLDER no config.json (pacote de entrega sanitizado) ──
    # Placeholders como <SEU_TENANT_ID> sao strings nao-vazias, enganando as checagens.
    # Limpar para que o script entre no fluxo de criacao/selecao de Service Principal.
    $placeholderRx = '^<.*>$|^SEU_|^YOUR_|^CHANGE_ME|^PLACEHOLDER|^TODO'
    if ($cfg.autenticacao.tenantId -match $placeholderRx) {
        Write-Info "config.json: tenantId e placeholder ('$($cfg.autenticacao.tenantId)') — limpando"
        $cfg.autenticacao.tenantId = ""
    }
    if ($cfg.autenticacao.appId -match $placeholderRx) {
        Write-Info "config.json: appId e placeholder ('$($cfg.autenticacao.appId)') — limpando"
        $cfg.autenticacao.appId = ""
    }
    if ($cfg.autenticacao.appSecret -match $placeholderRx) {
        Write-Info "config.json: appSecret e placeholder — limpando"
        $cfg.autenticacao.appSecret = ""
    }

    # Auto-detect TenantId via Azure CLI se nao informado
    if (-not $TenantId -and -not $cfg.autenticacao.tenantId) {
        try {
            $acct = & az account show --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($acct -and $acct.tenantId) { $TenantId = $acct.tenantId; Write-Info "Tenant ID auto-detectado via Azure CLI: $TenantId" }
        } catch {}
    }

    $hasTenantId = [bool]$TenantId -or [bool]$cfg.autenticacao.tenantId
    $hasAppId    = [bool]$AppId -or [bool]$cfg.autenticacao.appId
    $hasSecret   = [bool]$AppSecret -or ($cfg.autenticacao.appSecret -and $cfg.autenticacao.appSecret.Length -gt 5)

    if ($hasTenantId -and $hasAppId -and $hasSecret) {
        Write-Info "Credenciais detectadas automaticamente (parametros ou config.json)"
        Write-Explain "Pulando deteccao de Service Principal"
    } else {
        Write-Info "Verificando Service Principals existentes no tenant..."
        $existingSPs = @()
        try {
            $spListJson = & az ad sp list --all --filter "startswith(displayName, 'MDE')" --query "[].{appId:appId, displayName:displayName, id:id}" -o json 2>$null
            if ($LASTEXITCODE -eq 0 -and $spListJson) {
                $existingSPs = @($spListJson | ConvertFrom-Json -ErrorAction SilentlyContinue)
            }
        } catch {}

        if ($existingSPs.Count -gt 0) {
            Write-Ok "$($existingSPs.Count) Service Principal(s) com prefixo 'MDE':"
            Write-Host ""
            $idx = 0
            foreach ($sp in $existingSPs) {
                $idx++
                Write-Host "    $idx. $($sp.displayName)" -ForegroundColor White
                Write-Host "       AppId: $($sp.appId)" -ForegroundColor DarkGray
            }
            Write-Host "    $($idx + 1). Criar NOVO Service Principal" -ForegroundColor Cyan
            Write-Host "    $($idx + 2). Informar AppId manualmente" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  [?] Qual opcao deseja? [1]: " -NoNewline -ForegroundColor Yellow
            $choice = Read-Host
            $choice = if ($null -eq $choice -or $choice.Trim() -eq "") { "1" } else { $choice.Trim() }

            if ($choice -match '^\d+$') {
                $choiceNum = [int]$choice
                if ($choiceNum -le $existingSPs.Count -and $choiceNum -ge 1) {
                    $selectedSP = $existingSPs[$choiceNum - 1]
                    $AppId = $selectedSP.appId
                    Write-Ok "Usando: $($selectedSP.displayName) ($AppId)"
                    if (-not $TenantId) {
                        try {
                            $acct = & az account show --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($acct) { $TenantId = $acct.tenantId }
                        } catch {}
                    }
                } elseif ($choiceNum -eq $existingSPs.Count + 1) {
                    $newSP = New-ServicePrincipal
                    if ($newSP) {
                        $AppId = $newSP.AppId
                        $AppSecret = $newSP.Secret
                        $TenantId = $newSP.TenantId
                    }
                } elseif ($choiceNum -eq $existingSPs.Count + 2) {
                    Write-Host "  Informe o AppId (Client ID): " -NoNewline -ForegroundColor Yellow
                    $manualAppId = Read-Host
                    $manualAppId = if ($null -eq $manualAppId) { "" } else { $manualAppId.Trim() }
                    if ($manualAppId.Length -gt 10) {
                        $AppId = $manualAppId
                        Write-Ok "AppId manual informado: $AppId"
                    } else {
                        Write-Warn "AppId invalido — sera usado o valor do config.json (se existir)"
                    }
                }
            }
        } else {
            Write-Info "Nenhum Service Principal com prefixo 'MDE' encontrado."
            if (Confirm-Action "Deseja criar um novo Service Principal agora?" "S" "Criar Service Principal") {
                $newSP = New-ServicePrincipal
                if ($newSP) {
                    $AppId = $newSP.AppId
                    $AppSecret = $newSP.Secret
                    $TenantId = $newSP.TenantId
                }
            }
        }
    }

    # Resolver credenciais
    $resolvedTenantId = ""
    if ($TenantId) { $resolvedTenantId = $TenantId; Write-Ok "Tenant ID: via parametro" }
    elseif ($cfg.autenticacao.tenantId) { $resolvedTenantId = $cfg.autenticacao.tenantId; Write-Ok "Tenant ID: config.json" }

    $resolvedAppId = ""
    if ($AppId) { $resolvedAppId = $AppId; Write-Ok "App ID: via parametro/selecao" }
    elseif ($cfg.autenticacao.appId) { $resolvedAppId = $cfg.autenticacao.appId; Write-Ok "App ID: config.json" }

    $resolvedSecret = ""; $secretSource = ""
    Show-Separator
    Write-Info "Verificando Client Secret..."

    if ($AppSecret) {
        $resolvedSecret = $AppSecret
        $secretSource = "parametro -AppSecret"
        $hint = $resolvedSecret.Substring(0, [Math]::Min(6, $resolvedSecret.Length)) + "***"
        Write-Ok "Secret via parametro: $hint"
    }
    elseif ($cfg.autenticacao.appSecret -and $cfg.autenticacao.appSecret.Length -gt 5) {
        $resolvedSecret = $cfg.autenticacao.appSecret
        $secretSource = "config.json (auto-detectado)"
        $hint = $resolvedSecret.Substring(0, [Math]::Min(6, $resolvedSecret.Length)) + "***"
        Write-Ok "Secret no config.json: $hint"
    }
    else {
        Write-Warn "Nenhum secret encontrado"
        Write-Host "  Cole o Client Secret (ou ENTER para cancelar): " -NoNewline -ForegroundColor Yellow
        $inputSecret = Read-Host
        $inputSecret = if ($null -eq $inputSecret) { "" } else { $inputSecret.Trim() }
        if ($inputSecret.Length -gt 10) {
            $resolvedSecret = $inputSecret
            $secretSource = "entrada interativa"
        } else {
            Write-Err "Secret nao informado."
            return $null
        }
    }

    if (-not $resolvedTenantId) { Write-Err "Tenant ID nao disponivel."; return $null }
    if (-not $resolvedAppId)    { Write-Err "App ID nao disponivel.";    return $null }

    $secretHint = $resolvedSecret.Substring(0, [Math]::Min(6, $resolvedSecret.Length)) + "***" + $resolvedSecret.Substring([Math]::Max(0, $resolvedSecret.Length - 4))

    # ── PERSISTIR NO CONFIG.JSON (para que Run-Daily e proximas execucoes funcionem) ──
    $configChanged = $false
    if ($resolvedTenantId -ne $cfg.autenticacao.tenantId) {
        $cfg.autenticacao.tenantId = $resolvedTenantId; $configChanged = $true
    }
    if ($resolvedAppId -ne $cfg.autenticacao.appId) {
        $cfg.autenticacao.appId = $resolvedAppId; $configChanged = $true
    }
    if ($resolvedSecret -ne $cfg.autenticacao.appSecret) {
        $cfg.autenticacao.appSecret = $resolvedSecret; $configChanged = $true
    }
    if ($configChanged) {
        try {
            $cfg | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8 -Force
            Write-Ok "config.json atualizado com novas credenciais (persistido para execucoes futuras)"
            Log-Action "Atualizar config.json" "OK" "TenantId + AppId + Secret salvos"
        } catch {
            Write-Warn "Falha ao salvar config.json: $($_.Exception.Message)"
            Write-Warn "As credenciais funcionam NESTA sessao, mas precisam ser salvas manualmente para Run-Daily.ps1"
        }
    }

    Show-Separator
    Write-Host ""
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  CREDENCIAIS RESOLVIDAS                                      |" -ForegroundColor White
    Write-Host "  |  Tenant ID : $resolvedTenantId  |" -ForegroundColor Cyan
    Write-Host "  |  App ID    : $resolvedAppId  |" -ForegroundColor Cyan
    Write-Host "  |  Secret    : $secretHint  |" -ForegroundColor Yellow
    Write-Host "  |  Origem    : $secretSource  |" -ForegroundColor Gray
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor DarkGray

    $script:Results["Credentials"] = @{
        TenantId = $resolvedTenantId; AppId = $resolvedAppId
        AppSecret = $resolvedSecret   # Real secret (para Refresh-AllTokens)
        SecretHint = $secretHint; SecretSource = $secretSource
    }
    return @{ TenantId = $resolvedTenantId; AppId = $resolvedAppId; AppSecret = $resolvedSecret }
}

# ============================================================================
# HELPER — GRANT ADMIN CONSENT VIA GRAPH API (appRoleAssignedTo)
# Ref: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent?pivots=ms-graph
# Usa POST /servicePrincipals/{resourceId}/appRoleAssignedTo (best practice Microsoft)
# ao inves de 'az ad app permission admin-consent' que falha com duplicatas.
# ============================================================================
function Grant-AdminConsentViaGraph {
    param([string]$AppId)

    $clientSpId = (& az ad sp show --id $AppId --query id -o tsv 2>$null)
    if (-not $clientSpId -or $clientSpId.Trim() -eq "") {
        Write-Warn "Service Principal nao encontrado para AppId: $AppId"
        return $false
    }
    $clientSpId = $clientSpId.Trim()

    # Permissoes a conceder: MDE + Graph
    $grants = @(
        @{
            ResourceAppId = "fc780465-2017-40d4-a0c5-307022471b92"  # WindowsDefenderATP
            Permissions = @(
                @{ Id = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79"; Name = "Machine.ReadWrite.All" }
            )
        },
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            Permissions = @(
                @{ Id = "62a82d76-70ea-41e2-9197-370581804d09"; Name = "Group.ReadWrite.All" },
                @{ Id = "7438b122-aefc-4978-80ed-43db9fcc7715"; Name = "Device.Read.All" },
                @{ Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"; Name = "GroupMember.ReadWrite.All" }
            )
        }
    )

    $allOk = $true
    foreach ($resource in $grants) {
        $resourceSpId = (& az ad sp show --id $resource.ResourceAppId --query id -o tsv 2>$null)
        if (-not $resourceSpId -or $resourceSpId.Trim() -eq "") {
            Write-Warn "Resource SP nao encontrado: $($resource.ResourceAppId)"
            $allOk = $false; continue
        }
        $resourceSpId = $resourceSpId.Trim()
        $resourceName = (& az ad sp show --id $resource.ResourceAppId --query displayName -o tsv 2>$null)
        if ($resourceName) { $resourceName = $resourceName.Trim() } else { $resourceName = $resource.ResourceAppId }

        foreach ($perm in $resource.Permissions) {
            $bodyJson = '{"principalId":"' + $clientSpId + '","resourceId":"' + $resourceSpId + '","appRoleId":"' + $perm.Id + '"}'
            $bodyFile = Join-Path ([System.IO.Path]::GetTempPath()) "consent-$($perm.Id.Substring(0,8)).json"
            [System.IO.File]::WriteAllText($bodyFile, $bodyJson, [System.Text.UTF8Encoding]::new($false))

            try {
                $grantUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceSpId/appRoleAssignedTo"
                $result = & az rest --method POST --url $grantUrl --body "@$bodyFile" --output none 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok "  $resourceName -> $($perm.Name) concedido"
                } else {
                    $resultStr = "$result"
                    if ($resultStr -match "already exists") {
                        Write-Ok "  $resourceName -> $($perm.Name) ja concedido"
                    } elseif ($resultStr -match "not found on application") {
                        Write-Warn "  $resourceName -> $($perm.Name) nao declarado no manifest"
                        $allOk = $false
                    } else {
                        Write-Warn "  $resourceName -> $($perm.Name) falhou: $resultStr"
                        $allOk = $false
                    }
                }
            } catch {
                Write-Warn "  $resourceName -> $($perm.Name) erro: $($_.Exception.Message)"
                $allOk = $false
            } finally {
                Remove-Item $bodyFile -ErrorAction SilentlyContinue
            }
        }
    }
    return $allOk
}

function New-ServicePrincipal {
    $tenantName = ""
    $currentTenantId = ""
    try {
        $acct = & az account show --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($acct) {
            $tenantName = ($acct.tenantDisplayName -replace '[^a-zA-Z0-9]', '')
            $currentTenantId = $acct.tenantId
        }
    } catch {}
    if (-not $tenantName) { $tenantName = "Tenant" }

    $suggestedName = "MDE-ServerTags-$tenantName"
    Write-Host ""
    Write-Host "  [*] Nome sugerido: " -NoNewline -ForegroundColor Cyan
    Write-Host $suggestedName -ForegroundColor White
    Write-Host "  [?] ENTER para aceitar, ou digite outro nome: " -NoNewline -ForegroundColor Yellow
    $customName = Read-Host
    $customName = if ($null -eq $customName -or $customName.Trim() -eq "") { $suggestedName } else { $customName.Trim() }

    Write-Info "Criando App Registration: $customName..."
    try {
        $appJson = & az ad app create --display-name $customName --output json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $appJson) {
            Write-Err "Falha ao criar App Registration"; return $null
        }
        $app = $appJson | ConvertFrom-Json
        $newAppId = $app.appId
        Write-Ok "App Registration criado: $customName ($newAppId)"

        Write-Info "Criando Service Principal..."
        & az ad sp create --id $newAppId --output none 2>$null
        Write-Ok "Service Principal criado"

        # Declarar TODAS as permissoes em um unico JSON (evita duplicatas)
        # Ref: az ad app update --required-resource-accesses
        Write-Info "Declarando permissoes: MDE (Machine.ReadWrite.All) + Graph (Group/Device/GroupMember)..."
        $permsJson = '[{"resourceAppId":"fc780465-2017-40d4-a0c5-307022471b92","resourceAccess":[{"id":"ea8291d3-4b9a-44b5-bc3a-6cea3026dc79","type":"Role"}]},{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"62a82d76-70ea-41e2-9197-370581804d09","type":"Role"},{"id":"7438b122-aefc-4978-80ed-43db9fcc7715","type":"Role"},{"id":"dbaae8cf-10b5-4b86-a4a1-f871c94c6695","type":"Role"}]}]'
        $permsFile = Join-Path ([System.IO.Path]::GetTempPath()) "mde-perms-$($newAppId.Substring(0,8)).json"
        [System.IO.File]::WriteAllText($permsFile, $permsJson, [System.Text.UTF8Encoding]::new($false))
        & az ad app update --id $newAppId --required-resource-accesses "@$permsFile" --output none 2>$null
        Remove-Item $permsFile -ErrorAction SilentlyContinue
        Write-Ok "Permissoes declaradas (MDE + Graph) — sem duplicatas"

        Write-Info "Concedendo Admin Consent..."
        Wait-Propagation -Seconds 8 -Message "Propagacao do App Registration"
        $consentOk = Grant-AdminConsentViaGraph -AppId $newAppId
        if ($consentOk) {
            Write-Ok "Admin Consent concedido automaticamente via Graph API!"
        } else {
            $cUrl = "https://login.microsoftonline.com/$currentTenantId/adminconsent?client_id=$newAppId"
            Write-Warn "Consent automatico incompleto. Abrindo navegador..."
            Write-Host ""
            Write-Host "  +===================================================================+" -ForegroundColor Yellow
            Write-Host "  |  ACAO: Clique 'Accept' no navegador para conceder Admin Consent  |" -ForegroundColor Yellow
            Write-Host "  |                                                                   |" -ForegroundColor Yellow
            Write-Host "  |  Isso aprova MDE (Machine.ReadWrite.All) + Graph de uma vez.      |" -ForegroundColor White
            Write-Host "  |                                                                   |" -ForegroundColor Yellow
            Write-Host "  |  URL: $cUrl" -ForegroundColor Cyan
            Write-Host "  |                                                                   |" -ForegroundColor Yellow
            Write-Host "  |  Se o navegador nao abrir, copie e cole o link acima.             |" -ForegroundColor DarkGray
            Write-Host "  +===================================================================+" -ForegroundColor Yellow
            try { Start-Process $cUrl } catch { Write-Warn "Copie o link acima e abra no navegador." }
            Write-Host ""
            Write-Host "  [?] Pressione ENTER apos conceder consent no navegador: " -ForegroundColor Yellow -NoNewline
            Read-Host
            Wait-Propagation -Seconds 12 -Message "Propagacao Admin Consent"
            Write-Ok "Consent confirmado pelo usuario"
        }

        Write-Info "Gerando Client Secret (validade: 2 anos)..."
        $credJson = & az ad app credential reset --id $newAppId --append --years 2 --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and $credJson) {
            $credObj = $credJson | ConvertFrom-Json
            $newSecret = $credObj.password
            $newTenantId = $credObj.tenant
            Write-Ok "Client Secret gerado com sucesso"
            $sHint = $newSecret.Substring(0, [Math]::Min(6, $newSecret.Length)) + "***"
            Write-Host ""
            Write-Host "  +-- SERVICE PRINCIPAL CRIADO ------------------------------------+" -ForegroundColor Green
            Write-Host "  |  Nome   : $customName" -ForegroundColor White
            Write-Host "  |  AppId  : $newAppId" -ForegroundColor Cyan
            Write-Host "  |  Tenant : $newTenantId" -ForegroundColor Cyan
            Write-Host "  |  Secret : $sHint (SALVE EM LOCAL SEGURO)" -ForegroundColor Yellow
            Write-Host "  |  MDE    : Machine.ReadWrite.All" -ForegroundColor Green
            Write-Host "  |  Graph  : Group.ReadWrite.All + Device.Read.All" -ForegroundColor Green
            Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Green
            Log-Action "Criar Service Principal" "CRIADO" "$customName ($newAppId)"
            return @{ AppId = $newAppId; Secret = $newSecret; TenantId = $newTenantId; Name = $customName }
        } else {
            Write-Err "Falha ao gerar Client Secret"; return $null
        }
    } catch {
        Write-Err "Erro ao criar SP: $($_.Exception.Message)"; return $null
    }
}

# ============================================================================
# ETAPA 3 — AUTENTICACAO OAUTH2 (MDE + ARM + GRAPH)
# ============================================================================
function Test-Authentication {
    param([hashtable]$Creds)
    Show-Step 3 "AUTENTICACAO OAUTH2 (MDE + ARM + GRAPH)" `
        "Obtendo tokens OAuth2 para MDE, Azure ARM e Microsoft Graph.`n  O token Graph e necessario para criar Device Groups e atribuir maquinas."

    $mdeResult   = @{ Status = "ERR"; ExpiresIn = 0 }
    $armResult   = @{ Status = "N/A"; ExpiresIn = 0 }
    $graphResult = @{ Status = "N/A"; ExpiresIn = 0 }
    $consentGranted = $false

    # --- Token MDE ---
    Write-Info "Obtendo token MDE..."
    try {
        $body = @{
            client_id = $Creds.AppId; client_secret = $Creds.AppSecret
            grant_type = "client_credentials"
            scope = "https://api.securitycenter.microsoft.com/.default"
        }
        $tokenResp = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$($Creds.TenantId)/oauth2/v2.0/token" `
            -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        $mdeResult.Status = "OK"; $mdeResult.ExpiresIn = $tokenResp.expires_in
        $script:TokenObtained = $true
        $script:MdeToken = $tokenResp.access_token
        Write-Ok "Token MDE obtido! TTL: $([math]::Round($tokenResp.expires_in / 60)) min"
        Add-PrereqResult "Token OAuth2 MDE" "OK" "Obtido (TTL: $($tokenResp.expires_in)s)"

        Show-Separator
        Write-Info "Testando API MDE..."
        $hdrs = @{ Authorization = "Bearer $($tokenResp.access_token)" }
        $devResp = Invoke-RestMethod `
            -Uri "https://api.securitycenter.microsoft.com/api/machines?`$top=3" `
            -Headers $hdrs -ErrorAction Stop
        $devNames = @()
        if ($devResp.value) { foreach ($d in $devResp.value) { $devNames += "$($d.computerDnsName) ($($d.osPlatform))" } }
        $totalHint = if ($devResp.'@odata.count') { $devResp.'@odata.count' } else { "$($devResp.value.Count)+" }
        Write-Ok "API MDE: $totalHint dispositivo(s)"
        foreach ($dn in $devNames) { Write-Explain "  -> $dn" }
        Add-PrereqResult "API MDE (/machines)" "OK" "$totalHint dispositivos"
        $script:Results["ApiTest"] = @{ Status = "OK"; DeviceCount = $totalHint; Sample = $devNames }
    } catch {
        $errMsg = $_.Exception.Message
        Write-Err "Falha MDE: $errMsg"
        $script:MdeAuthError = $errMsg
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        if ($errMsg -match "401|Unauthorized|unauthorized_client") {
            Write-Host "  ║  DIAGNOSTICO: Admin Consent NAO concedido para MDE API          ║" -ForegroundColor Yellow
            Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║  O App Registration existe e o Secret esta correto, porem as     ║" -ForegroundColor White
            Write-Host "  ║  permissoes API (Machine.ReadWrite.All) nao foram aprovadas       ║" -ForegroundColor White
            Write-Host "  ║  por um Admin do tenant (Admin Consent pendente).                 ║" -ForegroundColor White
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║  FLUXO OAUTH2 (client_credentials):                              ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║    App Reg ──► API Permissions ──► Admin Consent ──► Token        ║" -ForegroundColor Cyan
            Write-Host "  ║      OK             OK              PENDENTE        BLOQ          ║" -ForegroundColor Red
            Write-Host "  ║                      ▲                  ▲                         ║" -ForegroundColor DarkGray
            Write-Host "  ║               Machine.ReadWrite.All     Global Admin               ║" -ForegroundColor DarkGray
            Write-Host "  ║               (configurado OK)          (falta aprovar)            ║" -ForegroundColor DarkGray
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        } elseif ($errMsg -match "invalid_client|AADSTS7000215") {
            Write-Host "  ║  DIAGNOSTICO: Client Secret expirado ou incorreto               ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║  O Secret informado nao e valido para este App Registration.     ║" -ForegroundColor White
            Write-Host "  ║  Verifique no portal: Certificates & secrets > Client secrets.   ║" -ForegroundColor White
            Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        } elseif ($errMsg -match "AADSTS700016") {
            Write-Host "  ║  DIAGNOSTICO: AppId NAO encontrado neste tenant                 ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║  O Application (client) ID informado nao existe no tenant.       ║" -ForegroundColor White
            Write-Host "  ║  Verifique: portal.azure.com > Entra ID > App Registrations.     ║" -ForegroundColor White
            Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        } else {
            Write-Host "  ║  DIAGNOSTICO: Erro generico de autenticacao                     ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                  ║" -ForegroundColor Red
            Write-Host "  ║  Verifique: TenantId, AppId, Secret e conectividade de rede.     ║" -ForegroundColor White
            Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        }
        Write-Host ""
        Add-PrereqResult "Token OAuth2 MDE" "ERR" $errMsg
    }

    # ── AUTO-CONSENT + RETRY (se MDE retornou 401) ──────────────────────────
    if (-not $script:TokenObtained -and $script:MdeAuthError -match "401|Unauthorized|unauthorized_client") {
        Write-Host ""
        Write-Host "  ┌── POR QUE ADMIN CONSENT E NECESSARIO ───────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │                                                                  │" -ForegroundColor Yellow
        Write-Host "  │  No fluxo client_credentials (App-only), as permissoes do tipo   │" -ForegroundColor DarkGray
        Write-Host "  │  'Application' requerem aprovacao explicita de um administrador   │" -ForegroundColor DarkGray
        Write-Host "  │  do tenant (Global Admin ou Application Admin).                  │" -ForegroundColor DarkGray
        Write-Host "  │                                                                  │" -ForegroundColor Yellow
        Write-Host "  │  Sem essa aprovacao, o Azure AD recusa emitir tokens OAuth2      │" -ForegroundColor DarkGray
        Write-Host "  │  que contenham as roles necessarias (Machine.ReadWrite.All).      │" -ForegroundColor DarkGray
        Write-Host "  │                                                                  │" -ForegroundColor Yellow
        Write-Host "  │  O script tentara auto-consent ou abrira o link no navegador.    │" -ForegroundColor White
        Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        $consentGranted = $false
        # Passo 1: Tentar consent automatico via Graph API
        Write-Info "Tentando Admin Consent automatico via Graph API..."
        try {
            $consentOk = Grant-AdminConsentViaGraph -AppId $Creds.AppId
            if ($consentOk) {
                Write-Ok "Admin Consent concedido automaticamente!"
                $consentGranted = $true
                Log-Action "Admin Consent" "CONCEDIDO" "Via Graph API (automatico)"
            }
        } catch { }
        # Passo 2: Se automatico falhou, abrir link de consent no navegador
        if (-not $consentGranted) {
            $cUrl = "https://login.microsoftonline.com/$($Creds.TenantId)/adminconsent?client_id=$($Creds.AppId)"
            $pUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($Creds.AppId)/isMSAApp~/false"
            Write-Host ""
            Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
            Write-Host "  ║  ACAO NECESSARIA: Conceder Admin Consent no navegador             ║" -ForegroundColor Yellow
            Write-Host "  ╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
            Write-Host "  ║                                                                   ║" -ForegroundColor Yellow
            Write-Host "  ║  O consent automatico falhou. Abra o link abaixo no navegador     ║" -ForegroundColor White
            Write-Host "  ║  e clique 'Accept' para aprovar TODAS as permissoes:              ║" -ForegroundColor White
            Write-Host "  ║                                                                   ║" -ForegroundColor Yellow
            Write-Host "  ║  LINK (consent direto — recomendado):                             ║" -ForegroundColor Green
            Write-Host "  ║  $cUrl" -ForegroundColor Cyan
            Write-Host "  ║                                                                   ║" -ForegroundColor Yellow
            Write-Host "  ║  Alternativa (Portal > API Permissions > Grant admin consent):    ║" -ForegroundColor DarkGray
            Write-Host "  ║  $pUrl" -ForegroundColor DarkCyan
            Write-Host "  ║                                                                   ║" -ForegroundColor Yellow
            Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
            Write-Host ""
            try { Start-Process $cUrl } catch { Write-Warn "Navegador nao abriu. Copie o link acima." }
            Write-Host "  [?] " -ForegroundColor Yellow -NoNewline
            Write-Host "Apos clicar 'Accept' no navegador, pressione ENTER: " -ForegroundColor White -NoNewline
            Read-Host
            $consentGranted = $true
            Log-Action "Admin Consent" "MANUAL" "Via URL de consent no navegador"
        }

        if ($consentGranted) {
            Write-Host ""
            Write-Host "  ┌── PROPAGACAO ADMIN CONSENT ─────────────────────────────────────┐" -ForegroundColor Green
            Write-Host "  │                                                                  │" -ForegroundColor Green
            Write-Host "  │  Admin Consent concedido! O Azure AD precisa replicar esta       │" -ForegroundColor White
            Write-Host "  │  alteracao para todos os endpoints de autenticacao.              │" -ForegroundColor White
            Write-Host "  │                                                                  │" -ForegroundColor Green
            Write-Host "  │  Tempo tipico: 30 a 60 segundos.                                │" -ForegroundColor DarkGray
            Write-Host "  │  Em tenants grandes (multi-regiao): ate 5 minutos.              │" -ForegroundColor DarkGray
            Write-Host "  │                                                                  │" -ForegroundColor Green
            Write-Host "  │  Aguardando propagacao antes de retry do token...               │" -ForegroundColor White
            Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor Green
            Wait-Propagation -Seconds 35 -Message "Propagacao Admin Consent (Azure AD replication)"

            Write-Info "RETRY: Obtendo token MDE apos Admin Consent..."
            try {
                $retryBody = @{
                    client_id = $Creds.AppId; client_secret = $Creds.AppSecret
                    grant_type = "client_credentials"
                    scope = "https://api.securitycenter.microsoft.com/.default"
                }
                $retryResp = Invoke-RestMethod `
                    -Uri "https://login.microsoftonline.com/$($Creds.TenantId)/oauth2/v2.0/token" `
                    -Method POST -Body $retryBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

                $mdeResult.Status = "OK"; $mdeResult.ExpiresIn = $retryResp.expires_in
                $script:TokenObtained = $true
                $script:MdeToken = $retryResp.access_token
                Write-Ok "Token MDE obtido no RETRY! TTL: $([math]::Round($retryResp.expires_in / 60)) min"

                # JWT decode para verbose output
                try {
                    $jwtParts = $retryResp.access_token.Split('.')
                    $jwtPad = $jwtParts[1].Replace('-','+').Replace('_','/')
                    while ($jwtPad.Length % 4) { $jwtPad += '=' }
                    $jwtObj = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($jwtPad)) | ConvertFrom-Json
                    $jwtRoles = if ($jwtObj.roles) { ($jwtObj.roles -join ', ') } else { '(nenhuma)' }
                    Write-Explain "JWT Audience : $($jwtObj.aud)"
                    Write-Explain "JWT Roles    : $jwtRoles"
                    Write-Explain "JWT Expires  : $(([DateTimeOffset]::FromUnixTimeSeconds($jwtObj.exp)).LocalDateTime.ToString('dd/MM/yyyy HH:mm'))"
                } catch { }

                # Atualiza prereq com OK (sobrescreve o ERR anterior no relatorio)
                Add-PrereqResult "Token OAuth2 MDE (retry)" "OK" "Obtido apos auto-consent (TTL: $($retryResp.expires_in)s)"
                Log-Action "Token MDE (retry)" "OK" "Obtido apos Admin Consent automatico"

                Show-Separator
                Write-Info "Validando API MDE (GET /api/machines)..."
                try {
                    $hdrs = @{ Authorization = "Bearer $($retryResp.access_token)" }
                    $devResp = Invoke-RestMethod `
                        -Uri "https://api.securitycenter.microsoft.com/api/machines?`$top=3" `
                        -Headers $hdrs -ErrorAction Stop
                    $devNames = @()
                    if ($devResp.value) { foreach ($d in $devResp.value) { $devNames += "$($d.computerDnsName) ($($d.osPlatform))" } }
                    $totalHint = if ($devResp.'@odata.count') { $devResp.'@odata.count' } else { "$($devResp.value.Count)+" }
                    Write-Ok "API MDE operacional: $totalHint dispositivo(s)"
                    foreach ($dn in $devNames) { Write-Explain "  -> $dn" }
                    Add-PrereqResult "API MDE (/machines)" "OK" "$totalHint dispositivos"
                    $script:Results["ApiTest"] = @{ Status = "OK"; DeviceCount = $totalHint; Sample = $devNames }
                } catch {
                    Write-Warn "Token obtido mas API retornou: $($_.Exception.Message)"
                    Write-Explain "Propagacao pode levar mais tempo. Tente novamente em 2-5 min."
                }
            } catch {
                Write-Err "RETRY MDE falhou: $($_.Exception.Message)"
                Write-Host ""
                Write-Host "  ┌── PROPAGACAO INSUFICIENTE ──────────────────────────────────────┐" -ForegroundColor Yellow
                Write-Host "  │  O Admin Consent foi concedido mas a propagacao precisa de      │" -ForegroundColor DarkGray
                Write-Host "  │  mais tempo. Aguarde 2-5 minutos e execute novamente:           │" -ForegroundColor DarkGray
                Write-Host "  │                                                                  │" -ForegroundColor Yellow
                Write-Host "  │    .\TEST-Lab-E2E.ps1 -Report                                   │" -ForegroundColor Cyan
                Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
            }
        }
    }

    # --- Token ARM ---
    Show-Separator
    Write-Info "Obtendo token ARM..."
    try {
        $armBody = @{
            client_id = $Creds.AppId; client_secret = $Creds.AppSecret
            grant_type = "client_credentials"
            scope = "https://management.azure.com/.default"
        }
        $armResp = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$($Creds.TenantId)/oauth2/v2.0/token" `
            -Method POST -Body $armBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $armResult.Status = "OK"; $armResult.ExpiresIn = $armResp.expires_in
        $script:ArmToken = $armResp.access_token
        Write-Ok "Token ARM obtido"
        $armHdrs = @{ Authorization = "Bearer $($armResp.access_token)" }
        try {
            $armSubs = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers $armHdrs -ErrorAction Stop
            if ($armSubs.value -and $armSubs.value.Count -gt 0) {
                Write-Ok "$($armSubs.value.Count) subscription(s) descobertas via ARM"
                Add-PrereqResult "Subscriptions (ARM)" "OK" "$($armSubs.value.Count) subscription(s)"
                $script:Results["ArmSubscriptions"] = @($armSubs.value | ForEach-Object { @{ Id = $_.subscriptionId; Name = $_.displayName } })
            }
        } catch { Write-Info "ARM nao retornou subscriptions" }
        Add-PrereqResult "Token ARM" "OK" "Obtido"
    } catch {
        Write-Info "Token ARM nao disponivel (nao bloqueante)"
        Add-PrereqResult "Token ARM" "WARN" "Nao disponivel"
    }

    # --- Token Microsoft Graph ---
    Show-Separator
    Write-Info "Obtendo token Microsoft Graph..."
    Write-Explain "Necessario para: criar AAD Security Groups e atribuir maquinas"
    try {
        $graphBody = @{
            client_id = $Creds.AppId; client_secret = $Creds.AppSecret
            grant_type = "client_credentials"
            scope = "https://graph.microsoft.com/.default"
        }
        $graphResp = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$($Creds.TenantId)/oauth2/v2.0/token" `
            -Method POST -Body $graphBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $graphResult.Status = "OK"; $graphResult.ExpiresIn = $graphResp.expires_in
        $script:GraphTokenObtained = $true
        $script:GraphToken = $graphResp.access_token
        Write-Ok "Token Graph obtido! TTL: $([math]::Round($graphResp.expires_in / 60)) min"
        Add-PrereqResult "Token Microsoft Graph" "OK" "Obtido (TTL: $($graphResp.expires_in)s)"
        try {
            $null = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$top=1" `
                -Headers @{ Authorization = "Bearer $($graphResp.access_token)" } -ErrorAction Stop
            Write-Ok "Graph API acessivel (Group.Read confirmado)"
            Add-PrereqResult "Graph Permissions" "OK" "Group access OK"
        } catch {
            $gErr = $_.Exception.Message
            if ($gErr -match "403|Authorization_RequestDenied") {
                Write-Warn "Graph Token obtido mas SEM permissao Group.ReadWrite.All"
                Write-Explain "Adicione: Azure Portal > App Registration > API Permissions > Microsoft Graph"
                Add-PrereqResult "Graph Permissions" "WARN" "Group.ReadWrite.All nao concedido"
                $script:GraphTokenObtained = $false
            }
        }
    } catch {
        $graphErrMsg = $_.Exception.Message
        Write-Warn "Token Graph: $graphErrMsg"
        if ($graphErrMsg -match "401|Unauthorized|unauthorized_client" -and $consentGranted -eq $true) {
            Write-Info "RETRY Graph: Admin Consent ja concedido, aguardando propagacao Graph..."
            Wait-Propagation -Seconds 12 -Message "Propagacao Graph API permissions"
            try {
                $graphRetryBody = @{
                    client_id = $Creds.AppId; client_secret = $Creds.AppSecret
                    grant_type = "client_credentials"
                    scope = "https://graph.microsoft.com/.default"
                }
                $graphRetryResp = Invoke-RestMethod `
                    -Uri "https://login.microsoftonline.com/$($Creds.TenantId)/oauth2/v2.0/token" `
                    -Method POST -Body $graphRetryBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                $graphResult.Status = "OK"; $graphResult.ExpiresIn = $graphRetryResp.expires_in
                $script:GraphTokenObtained = $true
                $script:GraphToken = $graphRetryResp.access_token
                Write-Ok "Token Graph obtido no RETRY! TTL: $([math]::Round($graphRetryResp.expires_in / 60)) min"
                Add-PrereqResult "Token Microsoft Graph" "OK" "Obtido apos retry"
                Log-Action "Token Graph (retry)" "OK" "Obtido apos Admin Consent"
                try {
                    $null = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$top=1" `
                        -Headers @{ Authorization = "Bearer $($graphRetryResp.access_token)" } -ErrorAction Stop
                    Write-Ok "Graph API: Group.Read confirmado"
                    Add-PrereqResult "Graph Permissions (retry)" "OK" "Group access OK"
                } catch {
                    if ($_.Exception.Message -match "403|Authorization_RequestDenied") {
                        Write-Warn "Token Graph obtido mas Group.ReadWrite.All nao propagado ainda"
                        Write-Explain "Aguarde 2-5 min e execute novamente."
                        $script:GraphTokenObtained = $false
                    }
                }
            } catch {
                Write-Warn "RETRY Graph falhou. Device Groups serao documentados."
                Add-PrereqResult "Token Microsoft Graph" "WARN" "Falha apos retry"
            }
        } else {
            Write-Explain "Device Groups serao documentados para criacao manual."
            Add-PrereqResult "Token Microsoft Graph" "WARN" "Nao disponivel"
        }
    }

    # ── RESUMO AUTENTICACAO ──
    Show-Separator
    Write-Host ""
    $mdeIcon  = if ($script:TokenObtained)      { [char]0x2713 } else { [char]0x2717 }
    $gphIcon  = if ($script:GraphTokenObtained) { [char]0x2713 } else { '~' }
    $armIcon  = if ($armResult.Status -eq 'OK') { [char]0x2713 } else { '~' }
    Write-Host "  ┌── TOKENS OAUTH2 ────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │  [$mdeIcon] MDE Token    $(if($script:TokenObtained){'OBTIDO — classificacao + tags habilitada'}else{'FALHOU — classificacao bloqueada'})" -ForegroundColor $(if($script:TokenObtained){'Green'}else{'Red'})
    Write-Host "  │  [$gphIcon] Graph Token  $(if($script:GraphTokenObtained){'OBTIDO — Device Groups automaticos'}else{'N/A — grupos serao documentados'})" -ForegroundColor $(if($script:GraphTokenObtained){'Green'}else{'Yellow'})
    Write-Host "  │  [$armIcon] ARM Token    $(if($armResult.Status -eq 'OK'){'OBTIDO — subscription discovery via API'}else{'N/A — usando CSV ou Azure CLI'})" -ForegroundColor $(if($armResult.Status -eq 'OK'){'Green'}else{'Yellow'})
    Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $script:Results["Auth"] = @{ MDE = $mdeResult; ARM = $armResult; Graph = $graphResult }
    return $script:TokenObtained
}

# ============================================================================
# ETAPA 4 — APP REGISTRATION DETAILS
# ============================================================================
function Get-AppRegistrationInfo {
    param([hashtable]$Creds)
    Show-Step 4 "APP REGISTRATION & PERMISSOES" `
        "Consultando Azure AD para validar nome, permissoes, consent e expiracao."

    $appInfo = @{
        DisplayName = "N/A"; ObjectId = "N/A"; SPObjectId = "N/A"
        SecretExpiry = "N/A"; ConsentStatus = "N/A"; Permissions = @()
    }

    try {
        $appJson = & az ad app show --id $Creds.AppId --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and $appJson) {
            $appObj = $appJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($appObj) {
                $appInfo.DisplayName = $appObj.displayName
                $appInfo.ObjectId = $appObj.id
                Write-Ok "App Registration: $($appObj.displayName)"
                Add-PrereqResult "App Registration" "OK" $appObj.displayName

                $spId = & az ad sp show --id $Creds.AppId --query id -o tsv 2>$null
                if ($LASTEXITCODE -eq 0 -and $spId) {
                    $appInfo.SPObjectId = $spId.Trim()
                    Write-Ok "Service Principal: $($appInfo.SPObjectId)"
                    Add-PrereqResult "Service Principal" "OK" $appInfo.SPObjectId

                    try {
                        $rolesJson = & az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($appInfo.SPObjectId)/appRoleAssignments" --output json 2>$null
                        if ($LASTEXITCODE -eq 0 -and $rolesJson) {
                            $roles = ($rolesJson | ConvertFrom-Json -ErrorAction SilentlyContinue).value
                            if ($roles -and $roles.Count -gt 0) {
                                $appInfo.ConsentStatus = "Granted"
                                $appInfo.Permissions = @($roles | ForEach-Object { @{ RoleId = $_.appRoleId; ResourceId = $_.resourceId } })
                                Write-Ok "Admin Consent: CONCEDIDO ($($roles.Count) role(s))"
                                Add-PrereqResult "Admin Consent" "OK" "Concedido ($($roles.Count) role(s))"
                                $hasGraphGroup = $false; $hasGraphDevice = $false; $hasGraphMember = $false
                                $hasMdeWrite = $false
                                foreach ($r in $roles) {
                                    if ($r.appRoleId -eq "62a82d76-70ea-41e2-9197-370581804d09") { $hasGraphGroup = $true }
                                    if ($r.appRoleId -eq "7438b122-aefc-4978-80ed-43db9fcc7715") { $hasGraphDevice = $true }
                                    if ($r.appRoleId -eq "dbaae8cf-10b5-4b86-a4a1-f871c94c6695") { $hasGraphMember = $true }
                                    if ($r.appRoleId -eq "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79") { $hasMdeWrite = $true }
                                }
                                if ($hasMdeWrite) { Write-Ok "MDE: Machine.ReadWrite.All — ATIVO" }
                                else { Write-Warn "MDE: Machine.ReadWrite.All — NAO ENCONTRADO (tags nao serao aplicadas)" }
                                if ($hasGraphGroup) { Write-Ok "Graph: Group.ReadWrite.All — ATIVO" }
                                else { Write-Warn "Graph: Group.ReadWrite.All — NAO ENCONTRADO (grupos nao serao criados)" }
                                if ($hasGraphDevice) { Write-Ok "Graph: Device.Read.All — ATIVO" }
                                else { Write-Warn "Graph: Device.Read.All — NAO ENCONTRADO (mapeamento device limitado)" }
                                if ($hasGraphMember) { Write-Ok "Graph: GroupMember.ReadWrite.All — ATIVO" }
                                else { Write-Warn "Graph: GroupMember.ReadWrite.All — NAO ENCONTRADO (atribuicao de maquinas bloqueada)" }
                            } else {
                                $appInfo.ConsentStatus = "Not Granted"
                                Write-Warn "Admin Consent: NAO encontrado"
                                Add-PrereqResult "Admin Consent" "WARN" "Sem appRoleAssignments"
                            }
                        }
                    } catch {}
                }

                try {
                    $credsJson = & az ad app credential list --id $Creds.AppId --output json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $credsJson) {
                        $credsList = $credsJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($credsList -and $credsList.Count -gt 0) {
                            $latest = $credsList | Sort-Object endDateTime -Descending | Select-Object -First 1
                            $appInfo.SecretExpiry = $latest.endDateTime
                            $expiryDate = [datetime]$latest.endDateTime
                            $daysLeft = [math]::Round(($expiryDate - (Get-Date)).TotalDays)
                            Write-Ok "Secret expira: $($expiryDate.ToString('dd/MM/yyyy')) ($daysLeft dias)"
                            Add-PrereqResult "Secret Expiry" "OK" "$($expiryDate.ToString('dd/MM/yyyy')) ($daysLeft dias)"
                        }
                    }
                } catch {}
            }
        }
    } catch {
        Write-Info "Azure CLI nao disponivel para consultar App Registration"
        Add-PrereqResult "App Registration" "WARN" "Nao verificavel"
    }

    $script:Results["AppRegistration"] = $appInfo
}

# ============================================================================
# ETAPA 5 — CONFIGURACAO
# ============================================================================
function Show-ConfigDetails {
    Show-Step 5 "CONFIGURACAO ATIVA (config.json)" `
        "Exibindo parametros de classificacao, seguranca e agendamento."

    $configPath = Join-Path $script:ScriptRoot "config.json"
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json

    $cd = @{
        ReportOnly    = [bool]$cfg.execucao.reportOnly
        DiasInativo7d = $cfg.classificacao.diasInativo7d
        DiasInativo40d = $cfg.classificacao.diasInativo40d
        HorasEfemero  = $cfg.classificacao.horasEfemero
        TamanhoLote   = $cfg.classificacao.tamanhoLoteBulkApi
        AutoDiscover  = [bool]$cfg.descoberta.autoDiscoverSubscriptions
        SalvarCsv     = [bool]$cfg.descoberta.salvarCsvAposDiscovery
        LogRetention  = $cfg.execucao.logRetentionDays
        MaxRetries    = $cfg.execucao.maxRetries
        Horario       = $cfg.agendamento.horarioExecucao
        Intervalo     = $cfg.agendamento.intervaloHoras
        ExcluirSubs   = @($cfg.descoberta.excluirSubscriptions)
    }

    Write-Host "  +-- PARAMETROS DE CLASSIFICACAO -----------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  INATIVO_7D  : >= $($cd.DiasInativo7d) dias sem heartbeat MDE                        |" -ForegroundColor Cyan
    Write-Host "  |  INATIVO_40D : >= $($cd.DiasInativo40d) dias sem heartbeat MDE                       |" -ForegroundColor Cyan
    Write-Host "  |  EFEMERO     : <= $($cd.HorasEfemero) horas de vida da VM                          |" -ForegroundColor Cyan
    Write-Host "  |  Lote API    : $($cd.TamanhoLote) dispositivos/chamada bulk                       |" -ForegroundColor Gray
    Write-Host "  |  Max Retries : $($cd.MaxRetries)                                                    |" -ForegroundColor Gray
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    if ($script:IsReportOnly) {
        Write-Host "  |  MODO >> REPORT-ONLY (nenhuma tag sera alterada)                |" -ForegroundColor Green
    } else {
        Write-Host "  |  MODO >> EXECUCAO REAL (tags + grupos + assignment)             |" -ForegroundColor Yellow
    }
    Write-Host "  |  AutoDiscover: $(if($cd.AutoDiscover){'Ativo'}else{'Desativado'}) | Agendamento: $($cd.Horario) ($($cd.Intervalo)h)          |" -ForegroundColor Gray
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray

    Write-Ok "Configuracao validada"
    Add-PrereqResult "Configuracao" "OK" "Parametros validos"
    $script:Results["Config"] = $cd
}

# ============================================================================
# ETAPA 6 — CLASSIFICACAO
# ============================================================================
function Run-Classification {
    param([hashtable]$Creds)

    $modeLabel = if ($script:IsReportOnly) { "REPORT-ONLY" } else { "EXECUCAO REAL" }
    Show-Step 6 "CLASSIFICACAO DE SERVIDORES ($modeLabel)" `
        "Executando motor de classificacao Sync-MDE-ServerTags-BySubscription.ps1.`n  $(if($script:IsReportOnly){'Modo SEGURO: nenhuma tag sera alterada.'}else{'ATENCAO: Tags serao APLICADAS!'})"

    if (-not $script:TokenObtained) {
        Write-Err "Classificacao pulada: autenticacao nao validada"
        $script:Results["Classification"] = @{ Status = "SKIPPED" }
        return $false
    }

    if (-not $script:IsReportOnly) {
        if (-not (Confirm-Action "Tags serao APLICADAS nos servidores do MDE. Continuar?" "S" "Aplicar Tags MDE")) {
            Write-Info "Alternando para REPORT-ONLY."
            $script:IsReportOnly = $true
        }
    }

    $mainScript = Join-Path $script:ScriptRoot "01-Classificacao-Servidores\Sync-MDE-ServerTags-BySubscription.ps1"
    $csvPath    = Join-Path $script:ScriptRoot "subscription_mapping.csv"
    $configPath = Join-Path $script:ScriptRoot "config.json"
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json

    $excludeSubs = @()
    if ($cfg.descoberta -and $cfg.descoberta.excluirSubscriptions) {
        $excludeSubs = @($cfg.descoberta.excluirSubscriptions)
    }

    # ── PRE-CHECK: Auto-popular CSV se vazio (apenas header) ──────────────
    # O motor de classificacao le o CSV como "encontrado" mesmo se so tem header,
    # e nao cai no auto-discovery. Resultado: 0 subs mapeadas = todos SKIP.
    # Fix: Popular o CSV com Azure CLI ANTES de chamar o motor.
    if (Test-Path $csvPath) {
        $csvLines = @(Get-Content $csvPath -ErrorAction SilentlyContinue)
        if ($csvLines.Count -le 1) {
            Write-Warn "subscription_mapping.csv vazio (apenas header) — auto-populando..."
            try {
                # Tentativa 1: Azure CLI (mais confiavel para nomes)
                $azSubs = $null
                if (Get-Command az -ErrorAction SilentlyContinue) {
                    $azSubs = az account list --query "[?state=='Enabled']" --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                if ($azSubs -and $azSubs.Count -gt 0) {
                    $newCsvLines = @("subscriptionId;subscriptionName")
                    foreach ($s in $azSubs) {
                        if ($s.id -and $s.name) {
                            $newCsvLines += "$($s.id);$($s.name)"
                            Write-Explain "  + $($s.name) ($($s.id.Substring(0,8))...)"
                        }
                    }
                    $newCsvLines | Set-Content $csvPath -Encoding UTF8
                    Write-Ok "$($azSubs.Count) subscription(s) populadas no CSV via Azure CLI"
                    Log-Action "Pre-Popular CSV" "OK" "$($azSubs.Count) subscriptions via Azure CLI"
                }
                # Tentativa 2: ARM API (se Azure CLI falhou)
                elseif ($script:ArmToken) {
                    try {
                        $armHeaders = @{ Authorization = "Bearer $($script:ArmToken)" }
                        $armResp = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2022-12-01" -Headers $armHeaders -ErrorAction Stop
                        if ($armResp.value) {
                            $newCsvLines = @("subscriptionId;subscriptionName")
                            foreach ($s in $armResp.value) {
                                $newCsvLines += "$($s.subscriptionId);$($s.displayName)"
                                Write-Explain "  + $($s.displayName) ($($s.subscriptionId.Substring(0,8))...)"
                            }
                            $newCsvLines | Set-Content $csvPath -Encoding UTF8
                            Write-Ok "$($armResp.value.Count) subscription(s) populadas no CSV via ARM API"
                            Log-Action "Pre-Popular CSV" "OK" "$($armResp.value.Count) subscriptions via ARM API"
                        }
                    } catch {
                        Write-Warn "ARM API fallback: $($_.Exception.Message)"
                    }
                }
            } catch {
                Write-Warn "Falha ao auto-popular CSV: $($_.Exception.Message)"
            }
        } else {
            Write-Ok "subscription_mapping.csv: $($csvLines.Count - 1) subscription(s) mapeadas"
        }
    }

    Write-Info "Executando classificacao..."
    Write-Explain "Motor     : Sync-MDE-ServerTags-BySubscription.ps1 v2.2.0"
    Write-Explain "API Read  : GET https://api.securitycenter.microsoft.com/api/machines"
    Write-Explain "API Filter: osPlatform contendo 'Server' (exclui workstations e mobile)"
    Write-Explain "API Write : PUT /api/machines/{machineId}/tags (body: {Value, Action:'Add'})"
    Write-Explain "Cadeia    : DUPLICADA > EFEMERO > INATIVO_40D > INATIVO_7D > SUB > SKIP"
    Write-Explain "Idempotent: tags ja corretas geram acao 'OK' sem chamada API"
    if (-not $script:IsReportOnly) {
        Write-Explain "MODO      : EXECUCAO REAL — tags serao alteradas via PUT na API MDE"
    } else {
        Write-Explain "MODO      : REPORT-ONLY — nenhuma chamada PUT sera feita"
    }
    Write-Host ""
    $classifStart = Get-Date
    $scriptDir = Split-Path $mainScript -Parent
    $outputCapture = [System.Text.StringBuilder]::new()

    Push-Location $scriptDir
    try {
        $result = & $mainScript `
            -tenantId                  $Creds.TenantId `
            -appId                     $Creds.AppId `
            -appSecret                 $Creds.AppSecret `
            -subscriptionMappingPath   $csvPath `
            -autoDiscoverSubscriptions $true `
            -saveDiscoveredCsv         $true `
            -excludeSubscriptions      $excludeSubs `
            -reportOnly                $script:IsReportOnly 2>&1

        foreach ($line in $result) { [void]$outputCapture.AppendLine($line) }
        $classifDuration = (Get-Date) - $classifStart
        Write-Ok "Classificacao concluida em $([math]::Round($classifDuration.TotalSeconds, 1))s"
        $script:ClassificationOutput = $outputCapture.ToString()

        $reportsDir = Join-Path $script:ScriptRoot "Relatorios"
        $logsDir    = Join-Path $script:ScriptRoot "Logs"

        $csvReport = Get-ChildItem ".\ServerTags-Report-*.csv" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($csvReport) {
            $destPath = Join-Path $reportsDir $csvReport.Name
            Move-Item $csvReport.FullName -Destination $destPath -Force
            $script:CsvReportPath = $destPath
            Write-Ok "Relatorio CSV: $($csvReport.Name)"
        }
        Get-ChildItem ".\ServerTags-Log-*.log" -ErrorAction SilentlyContinue | Move-Item -Destination $logsDir -Force
        Get-ChildItem ".\ServerTags-Summary-*.txt" -ErrorAction SilentlyContinue | Move-Item -Destination $reportsDir -Force

        if ($script:CsvReportPath -and (Test-Path $script:CsvReportPath)) {
            try {
                $data = Import-Csv $script:CsvReportPath -Delimiter ";" -ErrorAction Stop
                $script:ClassificationData = $data
                $script:ServerCount = $data.Count

                $groups  = $data | Group-Object TargetTag  | Sort-Object Count -Descending
                $actions = $data | Group-Object Action     | Sort-Object Count -Descending

                Show-Separator
                Write-Host "  DISTRIBUICAO POR TAG:" -ForegroundColor White
                foreach ($g in $groups) {
                    $tagName = if ($g.Name) { $g.Name } else { "(SKIP)" }
                    $pct = [math]::Round($g.Count / $data.Count * 100)
                    $bar = ([char]9608).ToString() * [Math]::Min(25, [Math]::Max(1, [int]($pct / 4)))
                    Write-Host "    $($tagName.PadRight(22)) $($g.Count.ToString().PadLeft(3)) ($($pct.ToString().PadLeft(2))%) $bar" -ForegroundColor Cyan
                }
                Write-Host ""
                Write-Host "  DISTRIBUICAO POR ACAO:" -ForegroundColor White
                foreach ($a in $actions) {
                    $color = switch ($a.Name) { "TAG" { "Blue" } "OK" { "Green" } "SKIP" { "Gray" } default { "White" } }
                    Write-Host "    $($a.Name.PadRight(10)) $($a.Count.ToString().PadLeft(3)) servidor(es)" -ForegroundColor $color
                }

                $script:Results["Classification"] = @{
                    Status = "OK"; ServerCount = $data.Count
                    Duration = [math]::Round($classifDuration.TotalSeconds, 1)
                    CsvPath = $script:CsvReportPath; Groups = @{}; Actions = @{}
                }
                foreach ($g in $groups)  { $script:Results["Classification"].Groups[$g.Name]  = $g.Count }
                foreach ($a in $actions) { $script:Results["Classification"].Actions[$a.Name] = $a.Count }
            } catch {
                Write-Warn "Erro ao processar CSV: $($_.Exception.Message)"
            }
        }
        Log-Action "Classificacao" "OK" "$($script:ServerCount) servidores"
        return $true
    } catch {
        Write-Err "Erro durante classificacao: $($_.Exception.Message)"
        $script:Results["Classification"] = @{ Status = "ERR"; Error = $_.Exception.Message }
        return $false
    } finally {
        Pop-Location
    }
}

# ============================================================================
# ETAPA 7 — DEVICE GROUPS VIA MICROSOFT GRAPH + ATRIBUICAO DE MAQUINAS
# ============================================================================
function Manage-DeviceGroups {
    param([hashtable]$Creds)

    Show-Step 7 "DEVICE GROUPS — SUBSCRIPTION = NOME DO GRUPO" `
        "Cria AAD Security Groups usando o NOME DA SUBSCRIPTION como nome do grupo.`n  Insere maquinas Windows e Linux de cada subscription no grupo correspondente.`n  Cada acao pede confirmacao. Voce pode recusar sem quebrar o script."

    Write-Host "  +-- PARADIGMA v4.0 -----------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  Subscription Azure  ->  Nome do Device Group no Intune         |" -ForegroundColor White
    Write-Host "  |  Maquinas W/L        ->  Inseridas automaticamente no grupo     |" -ForegroundColor White
    Write-Host "  |  Cada acao           ->  Confirmacao interativa                 |" -ForegroundColor White
    Write-Host "  |  Propagacao          ->  ${script:PropDelay}s entre operacoes de API                    |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    if (-not $script:TokenObtained) {
        Write-Warn "Device Groups pulado: token MDE nao disponivel"
        $script:Results["DeviceGroups"] = @{ Status = "SKIPPED"; Reason = "No MDE Token" }
        return
    }

    if ($script:IsReportOnly) {
        Write-Info "Modo REPORT-ONLY: grupos serao PLANEJADOS (nao criados)"
    }

    if ($SkipGroupCreation.IsPresent) {
        Write-Info "Flag -SkipGroupCreation ativa: apenas documentando grupos"
    }

    # Limpar resultados anteriores (suporta re-invocacao pos-extensao)
    $script:DeviceGroupsCreated.Clear()

    # 7.1 — Mapeamento SubscriptionId -> SubscriptionName
    Write-Info "Montando mapeamento de subscriptions..."
    $subMapping = @{}

    if ($script:Results["ArmSubscriptions"]) {
        foreach ($sub in $script:Results["ArmSubscriptions"]) {
            if ($sub.Id -and $sub.Name) { $subMapping[$sub.Id] = $sub.Name }
        }
        Write-Ok "$($subMapping.Count) subscription(s) mapeadas via ARM API"
    }

    $csvPath = Join-Path $script:ScriptRoot "subscription_mapping.csv"
    if (Test-Path $csvPath) {
        try {
            $csvRows = Import-Csv $csvPath -Delimiter ";" -ErrorAction Stop
            foreach ($row in $csvRows) {
                if ($row.subscriptionId -and $row.subscriptionId -notmatch '^aaaa' -and $row.subscriptionName) {
                    if (-not $subMapping.ContainsKey($row.subscriptionId)) {
                        $subMapping[$row.subscriptionId] = $row.subscriptionName
                    }
                }
            }
        } catch {}
    }

    if ($subMapping.Count -eq 0) {
        try {
            $azSubs = & az account list --output json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($azSubs) {
                foreach ($s in $azSubs) { $subMapping[$s.id] = $s.name }
                Write-Ok "$($subMapping.Count) subscription(s) via Azure CLI"
            }
        } catch {}
    }

    Write-Info "Total de subscriptions mapeadas: $($subMapping.Count)"

    # 7.2 — Agrupar servidores por subscription E por lifecycle
    # IMPORTANTE: Tags internas NAO incluem string vazia — servidores SKIP
    # (TargetTag vazio mas com SubscriptionId) sao servidores ATIVOS PRODUTIVOS
    # que devem ir para grupos de subscription.
    $internalTags = @("INATIVO_7D", "INATIVO_40D", "EFEMERO", "DUPLICADA_EXCLUIR")
    $subGroups = @{}
    $lifecycleMachines = @{
        "INATIVO_7D" = @(); "INATIVO_40D" = @(); "EFEMERO" = @(); "DUPLICADA_EXCLUIR" = @()
    }
    $unmanagedMachines = @()  # Ativos sem subscription (on-prem sem Arc, AWS, etc.)

    if ($script:ClassificationData) {
        foreach ($server in $script:ClassificationData) {
            $tag = $server.TargetTag
            $subId = $server.SubscriptionId

            # Servidores com tags de lifecycle → grupos de lifecycle
            if ($tag -and $tag -in $internalTags) {
                $lifecycleMachines[$tag] += $server
            }
            # Servidores com tag de subscription (classificacao normal)
            elseif ($tag -and $tag -notin $internalTags) {
                if ($subId -and -not $subGroups.ContainsKey($subId)) {
                    $subName = if ($subMapping.ContainsKey($subId)) { $subMapping[$subId] } else { $tag }
                    $subGroups[$subId] = @{
                        Name = $subName; Tag = $tag
                        Machines = [System.Collections.Generic.List[pscustomobject]]::new()
                    }
                }
                if ($subId -and $subGroups.ContainsKey($subId)) {
                    $subGroups[$subId].Machines.Add($server)
                }
            }
            # Servidores SKIP (TargetTag vazio) COM SubscriptionId → sao PRODUTIVOS!
            # O motor classificou como SKIP porque o CSV estava vazio na hora.
            # Mas eles TEM subscription — devem ir para grupos de subscription.
            elseif ([string]::IsNullOrEmpty($tag) -and -not [string]::IsNullOrEmpty($subId)) {
                if (-not $subGroups.ContainsKey($subId)) {
                    $subName = if ($subMapping.ContainsKey($subId)) { $subMapping[$subId] } else { $subId.Substring(0, 8) }
                    $subGroups[$subId] = @{
                        Name = $subName; Tag = "SUB-ATIVO"
                        Machines = [System.Collections.Generic.List[pscustomobject]]::new()
                    }
                }
                $subGroups[$subId].Machines.Add($server)
            }
            # Servidores sem tag E sem subscription → verdadeiramente nao gerenciados
            else {
                $unmanagedMachines += $server
            }
        }
    }

    # ── VISAO ASSERTIVA DO AMBIENTE ──────────────────────────────────────────
    $totalServers = $script:ClassificationData.Count
    $totalActive = @($script:ClassificationData | Where-Object { $_.HealthStatus -eq 'Active' }).Count
    $totalSubServers = ($subGroups.Values | ForEach-Object { $_.Machines.Count } | Measure-Object -Sum).Sum
    if ($null -eq $totalSubServers) { $totalSubServers = 0 }
    $totalLifecycle = ($lifecycleMachines.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    if ($null -eq $totalLifecycle) { $totalLifecycle = 0 }

    Show-Separator
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║         VISAO ASSERTIVA DO AMBIENTE — MDE INVENTORY             ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║" -ForegroundColor Cyan
    Write-Host "  ║  Total servidores MDE    : $totalServers" -ForegroundColor White
    Write-Host "  ║  Ativos (reporting)      : $totalActive" -ForegroundColor Green
    Write-Host "  ║  Em subscriptions Azure  : $totalSubServers (alvo de policies AV/EDR)" -ForegroundColor Green
    Write-Host "  ║  Em lifecycle (problema)  : $totalLifecycle (inativos/efemeros/duplicatas)" -ForegroundColor Yellow
    Write-Host "  ║  Nao gerenciados          : $($unmanagedMachines.Count) (sem subscription Azure)" -ForegroundColor $(if($unmanagedMachines.Count -gt 0){"Red"}else{"Green"})
    Write-Host "  ║" -ForegroundColor Cyan

    # Mostrar servidores ativos POR SUBSCRIPTION
    Write-Host "  ║  ── SERVIDORES ATIVOS POR SUBSCRIPTION (produtivos) ──" -ForegroundColor White
    foreach ($subId in ($subGroups.Keys | Sort-Object)) {
        $sg = $subGroups[$subId]
        $activeInSub = @($sg.Machines | Where-Object { $_.HealthStatus -eq 'Active' }).Count
        $winC = @($sg.Machines | Where-Object { $_.OsPlatform -match 'Windows' }).Count
        $linC = @($sg.Machines | Where-Object { $_.OsPlatform -match 'Linux|Ubuntu|Red|CentOS|Suse|Amazon' }).Count
        Write-Host "  ║    [$($sg.Name)] $($sg.Machines.Count) srv ($activeInSub ativos) — Win:$winC Lin:$linC" -ForegroundColor Green
        foreach ($m in $sg.Machines) {
            $hIcon = if ($m.HealthStatus -eq 'Active') { '[OK]' } else { '[!!]' }
            $osIcon = if ($m.OsPlatform -match 'Windows') { 'W' } else { 'L' }
            $hColor = if ($m.HealthStatus -eq 'Active') { 'Green' } else { 'Yellow' }
            Write-Host "  ║      $hIcon [$osIcon] $($m.ComputerDnsName)" -ForegroundColor $hColor
        }
    }
    Write-Host "  ║" -ForegroundColor Cyan

    # Lifecycle breakdown
    Write-Host "  ║  ── SERVIDORES EM LIFECYCLE (requerem acao) ──" -ForegroundColor Yellow
    foreach ($lcTag in @("INATIVO_7D","INATIVO_40D","EFEMERO","DUPLICADA_EXCLUIR")) {
        $lcMachines = $lifecycleMachines[$lcTag]
        if ($lcMachines.Count -gt 0) {
            $action = switch ($lcTag) {
                "INATIVO_7D"       { "investigar" }
                "INATIVO_40D"      { "offboard?" }
                "EFEMERO"          { "limpeza periodica" }
                "DUPLICADA_EXCLUIR" { "offboard recomendado" }
            }
            Write-Host "  ║    [$lcTag] $($lcMachines.Count) srv — acao: $action" -ForegroundColor Yellow
        }
    }

    if ($unmanagedMachines.Count -gt 0) {
        Write-Host "  ║" -ForegroundColor Cyan
        Write-Host "  ║  ── NAO GERENCIADOS (sem subscription Azure) ──" -ForegroundColor Red
        foreach ($m in $unmanagedMachines) {
            Write-Host "  ║    [?] $($m.ComputerDnsName) ($($m.OsPlatform))" -ForegroundColor Red
        }
    }

    # Coverage metric
    $coveragePct = if ($totalServers -gt 0) { [math]::Round(($totalSubServers / $totalServers) * 100, 1) } else { 0 }
    Write-Host "  ║" -ForegroundColor Cyan
    Write-Host "  ║  COBERTURA DE POLICIES: $coveragePct% dos servidores em grupos de subscription" -ForegroundColor $(if($coveragePct -ge 50){"Green"}elseif($coveragePct -ge 20){"Yellow"}else{"Red"})
    Write-Host "  ║  (Apenas servidores em grupos de subscription recebem policies AV/EDR)" -ForegroundColor DarkGray
    Write-Host "  ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $script:Results["EnvironmentOverview"] = @{
        Total = $totalServers; Active = $totalActive
        InSubscriptions = $totalSubServers; InLifecycle = $totalLifecycle
        Unmanaged = $unmanagedMachines.Count; Coverage = $coveragePct
        SubscriptionGroups = $subGroups.Count
    }

    # 7.3 — Plano de grupos
    Show-Separator
    Write-Host ""
    Write-Host "  DEVICE GROUPS POR SUBSCRIPTION:" -ForegroundColor White
    Write-Host ""

    $allPlannedGroups = @()
    $idx = 0

    foreach ($subId in ($subGroups.Keys | Sort-Object)) {
        $sg = $subGroups[$subId]
        $idx++
        $groupName = Format-GroupName -SubscriptionName $sg.Name
        $winCount = @($sg.Machines | Where-Object { $_.OsPlatform -match "Windows" }).Count
        $linCount = @($sg.Machines | Where-Object { $_.OsPlatform -match "Linux|Ubuntu|Red|CentOS" }).Count

        Write-Host "    $idx. [SUB] $groupName" -ForegroundColor White
        Write-Host "       Subscription: $($sg.Name) ($subId)" -ForegroundColor DarkGray
        Write-Host "       Maquinas: $($sg.Machines.Count) (Win:$winCount Lin:$linCount) | Automation: Semi" -ForegroundColor Cyan
        Write-Host ""

        $allPlannedGroups += @{
            Name = $groupName; SubId = $subId; SubName = $sg.Name; Tag = $sg.Tag
            Type = "Subscription"; Machines = $sg.Machines; ServerCount = $sg.Machines.Count
            WinCount = $winCount; LinCount = $linCount; Automation = "Semi"
            Description = "Servidores da subscription $($sg.Name)"
            Purpose = "Politicas AV/EDR de producao ($($sg.Machines.Count) servidores)"
        }
    }

    # Lifecycle groups
    $lifecycleGroupDefs = @(
        @{ Tag = "INATIVO_7D";       Name = "MDE-Lifecycle-Inativos-7D";  Automation = "Semi"; Desc = "Inativos 7+ dias"; Purpose = "Investigar inatividade." }
        @{ Tag = "INATIVO_40D";      Name = "MDE-Lifecycle-Inativos-40D"; Automation = "No";   Desc = "Inativos 40+ dias"; Purpose = "Validar antes de offboard." }
        @{ Tag = "EFEMERO";          Name = "MDE-Lifecycle-Efemeros";     Automation = "No";   Desc = "VMs efemeras (CI/CD)"; Purpose = "Offboard ou ignorar." }
        @{ Tag = "DUPLICADA_EXCLUIR"; Name = "MDE-Lifecycle-Duplicatas";  Automation = "No";   Desc = "Duplicados"; Purpose = "Offboard mensal." }
    )

    Write-Host "  DEVICE GROUPS POR LIFECYCLE:" -ForegroundColor White
    Write-Host ""
    foreach ($lgDef in $lifecycleGroupDefs) {
        $machines = $lifecycleMachines[$lgDef.Tag]
        $count = $machines.Count
        $idx++
        $autoColor = switch ($lgDef.Automation) { "Full" { "Green" } "Semi" { "Yellow" } "No" { "Red" } default { "Gray" } }
        Write-Host "    $idx. [LCY] $($lgDef.Name)" -ForegroundColor White
        Write-Host "       $($lgDef.Desc) | Servidores: $count | Automation: $($lgDef.Automation)" -ForegroundColor $autoColor
        Write-Host ""

        $winC = @($machines | Where-Object { $_.OsPlatform -match "Windows" }).Count
        $linC = @($machines | Where-Object { $_.OsPlatform -match "Linux|Ubuntu|Red|CentOS" }).Count

        $allPlannedGroups += @{
            Name = $lgDef.Name; SubId = ""; SubName = ""; Tag = $lgDef.Tag
            Type = "Lifecycle"; Machines = $machines; ServerCount = $count
            WinCount = $winC; LinCount = $linC; Automation = $lgDef.Automation
            Description = $lgDef.Desc; Purpose = $lgDef.Purpose
        }
    }

    Write-Host "  Total: $($allPlannedGroups.Count) grupos ($(@($allPlannedGroups | Where-Object { $_.Type -eq 'Subscription' }).Count) sub + $(@($allPlannedGroups | Where-Object { $_.Type -eq 'Lifecycle' }).Count) lifecycle)" -ForegroundColor White
    Write-Host ""

    # 7.4 — Modo Report-Only ou SkipGroupCreation
    if ($script:IsReportOnly -or $SkipGroupCreation.IsPresent) {
        foreach ($pg in $allPlannedGroups) {
            $script:DeviceGroupsCreated.Add([pscustomobject]@{
                Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
                Status = "PLANEJADO"; Automation = $pg.Automation
                Description = $pg.Description; Purpose = $pg.Purpose
                ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
                SubName = $pg.SubName; GroupId = ""; MembersAdded = 0
            })
        }
        $script:Results["DeviceGroups"] = @{ Status = "REPORT"; Count = $allPlannedGroups.Count }
        Write-Info "$($allPlannedGroups.Count) grupos documentados. Use -Execute para criar."
        return
    }

    # 7.5 — Confirmacao geral
    if (-not (Confirm-Action "Prosseguir com criacao de Device Groups e atribuicao de maquinas?" "S" "Criar Device Groups")) {
        foreach ($pg in $allPlannedGroups) {
            $script:DeviceGroupsCreated.Add([pscustomobject]@{
                Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
                Status = "IGNORADO_USUARIO"; Automation = $pg.Automation
                Description = $pg.Description; Purpose = $pg.Purpose
                ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
                SubName = $pg.SubName; GroupId = ""; MembersAdded = 0
            })
        }
        $script:Results["DeviceGroups"] = @{ Status = "SKIPPED_USER"; Count = $allPlannedGroups.Count }
        return
    }

    # 7.6 — Verificar Graph Token
    if (-not $script:GraphTokenObtained -or -not $script:GraphToken) {
        Write-Warn "Token Graph NAO disponivel. Documentando para criacao manual."
        Write-Host ""
        Write-Host "  +-- COMO HABILITAR CRIACAO AUTOMATICA ----------------------------+" -ForegroundColor Yellow
        Write-Host "  |  1. Azure Portal > App Registrations > API Permissions          |" -ForegroundColor White
        Write-Host "  |  2. Microsoft Graph > Application Permissions:                  |" -ForegroundColor White
        Write-Host "  |     - Group.ReadWrite.All                                       |" -ForegroundColor Cyan
        Write-Host "  |     - Device.Read.All                                           |" -ForegroundColor Cyan
        Write-Host "  |     - GroupMember.ReadWrite.All                                 |" -ForegroundColor Cyan
        Write-Host "  |  3. Grant Admin Consent                                         |" -ForegroundColor White
        Write-Host "  |  4. Execute novamente com -Execute                              |" -ForegroundColor White
        Write-Host "  +----------------------------------------------------------------+" -ForegroundColor Yellow

        foreach ($pg in $allPlannedGroups) {
            $script:DeviceGroupsCreated.Add([pscustomobject]@{
                Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
                Status = "AGUARDANDO_GRAPH"; Automation = $pg.Automation
                Description = $pg.Description; Purpose = $pg.Purpose
                ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
                SubName = $pg.SubName; GroupId = ""; MembersAdded = 0
            })
        }
        $script:Results["DeviceGroups"] = @{ Status = "MANUAL"; Count = $allPlannedGroups.Count }
        return
    }

    # 7.7 — Buscar dispositivos MDE (aadDeviceId)
    Write-Info "Obtendo dispositivos MDE (aadDeviceId)..."
    Write-Explain "API: GET /api/machines?`$top=10000 (paginacao via @odata.nextLink)"
    Write-Explain "Campo chave: aadDeviceId (GUID do dispositivo registrado no Azure AD)"
    Write-Explain "Fluxo: hostname MDE -> aadDeviceId -> AAD Object ID -> membro do grupo"
    Write-Explain "Fallback: hostname MDE -> displayName AAD (case-insensitive + short name)"
    $mdeDeviceLookup = @{}
    try {
        $mdeHeaders = @{ Authorization = "Bearer $($script:MdeToken)" }
        $allMachines = @()
        $nextUrl = "https://api.securitycenter.microsoft.com/api/machines?`$top=10000"
        while ($nextUrl) {
            $resp = Invoke-ApiWithRetry -Uri $nextUrl -Headers $mdeHeaders `
                -ApiName "MDE-ListMachines" -MaxRetries 3 -BaseDelaySec 5
            if ($resp.value) { $allMachines += $resp.value }
            $nextUrl = $resp.'@odata.nextLink'
        }
        foreach ($m in $allMachines) {
            if ($m.computerDnsName -and $m.aadDeviceId) {
                $mdeDeviceLookup[$m.computerDnsName.ToLower()] = $m.aadDeviceId
            }
        }
        Write-Ok "$($allMachines.Count) dispositivos MDE. $($mdeDeviceLookup.Count) com aadDeviceId."
    } catch {
        Write-Warn "Falha ao obter dispositivos MDE: $($_.Exception.Message)"
    }

    # 7.8 — Mapear aadDeviceId -> AAD Object ID
    Write-Info "Mapeando dispositivos AAD via Graph..."
    Write-Explain "API: GET /v1.0/devices?`$select=id,deviceId,displayName&`$top=999"
    Write-Explain "Correlacao: deviceId (Graph) == aadDeviceId (MDE) -> id = AAD Object ID"
    Write-Explain "O AAD Object ID e usado em POST /groups/{id}/members/`$ref"
    $aadObjectLookup = @{}
    $graphHeaders = @{
        Authorization = "Bearer $($script:GraphToken)"
        "Content-Type" = "application/json"
    }
    try {
        $allDevices = @()
        $nextUrl = "https://graph.microsoft.com/v1.0/devices?`$select=id,deviceId,displayName&`$top=999"
        while ($nextUrl) {
            $resp = Invoke-ApiWithRetry -Uri $nextUrl -Headers $graphHeaders `
                -ApiName "Graph-ListDevices" -MaxRetries 3 -BaseDelaySec 5
            if ($resp.value) { $allDevices += $resp.value }
            $nextUrl = $resp.'@odata.nextLink'
        }
        $aadDisplayNameLookup = @{}  # fallback: hostname -> AAD Object ID
        foreach ($d in $allDevices) {
            if ($d.deviceId) { $aadObjectLookup[$d.deviceId] = $d.id }
            if ($d.displayName -and $d.id) {
                $aadDisplayNameLookup[$d.displayName.ToLower()] = $d.id
            }
        }
        Write-Ok "$($allDevices.Count) dispositivos AAD. $($aadObjectLookup.Count) por deviceId, $($aadDisplayNameLookup.Count) por hostname."
    } catch {
        Write-Warn "Falha ao listar dispositivos AAD: $($_.Exception.Message)"
        Write-Explain "Verifique permissao Device.Read.All"
    }
    if ($aadDisplayNameLookup.Count -eq 0) { $aadDisplayNameLookup = @{} }

    # 7.9 — Obter ID do usuario logado (sera adicionado como Owner dos grupos)
    $signedInUserId = $null
    try {
        Write-Info "Obtendo usuario logado (sera adicionado como Owner dos grupos)..."
        $meResp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" `
            -Headers $graphHeaders -ErrorAction Stop
        $signedInUserId = $meResp.id
        $signedInUpn   = $meResp.userPrincipalName
        Write-Ok "Usuario logado: $signedInUpn (ObjId: $($signedInUserId.Substring(0,8))...)"
    } catch {
        # Fallback: App Registration (client_credentials) nao tem /me — usar az CLI
        try {
            $signedInUserId = (& az ad signed-in-user show --query id -o tsv 2>$null)
            $signedInUpn    = (& az ad signed-in-user show --query userPrincipalName -o tsv 2>$null)
            if ($signedInUserId -and $signedInUserId.Trim().Length -gt 10) {
                $signedInUserId = $signedInUserId.Trim()
                Write-Ok "Usuario logado (via CLI): $signedInUpn (ObjId: $($signedInUserId.Substring(0,8))...)"
            } else {
                $signedInUserId = $null
                Write-Warn "Nao foi possivel obter usuario logado (Owner nao sera configurado)"
            }
        } catch {
            $signedInUserId = $null
            Write-Warn "Nao foi possivel obter usuario logado: $($_.Exception.Message)"
        }
    }

    # 7.10 — Criar grupos e atribuir maquinas
    $createdCount = 0; $assignedTotal = 0; $failedCount = 0; $groupIdx = 0

    foreach ($pg in $allPlannedGroups) {
        $groupIdx++
        $typeLabel = if ($pg.Type -eq "Subscription") { "SUB" } else { "LCY" }

        Show-Separator
        Write-Host ""
        Write-Host "  [$groupIdx/$($allPlannedGroups.Count)] [$typeLabel] $($pg.Name)" -ForegroundColor Cyan
        if ($pg.SubName) { Write-Host "       Subscription: $($pg.SubName)" -ForegroundColor DarkGray }
        Write-Host "       Maquinas: $($pg.ServerCount) (Win:$($pg.WinCount) Lin:$($pg.LinCount)) | Automation: $($pg.Automation)" -ForegroundColor White

        if (-not (Confirm-Action "Criar grupo '$($pg.Name)' e atribuir $($pg.ServerCount) maquina(s)?" "S" "Criar $($pg.Name)")) {
            $script:DeviceGroupsCreated.Add([pscustomobject]@{
                Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
                Status = "IGNORADO_USUARIO"; Automation = $pg.Automation
                Description = $pg.Description; Purpose = $pg.Purpose
                ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
                SubName = $pg.SubName; GroupId = ""; MembersAdded = 0
            })
            continue
        }

        # Verificar se grupo ja existe
        $existingGroupId = $null
        try {
            $filterName = $pg.Name -replace "'", "''"
            $checkUrl = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$filterName'&`$select=id,displayName"
            $checkResp = Invoke-ApiWithRetry -Uri $checkUrl -Headers $graphHeaders `
                -ApiName "Graph-CheckGroup" -MaxRetries 2 -BaseDelaySec 3
            if ($checkResp.value -and $checkResp.value.Count -gt 0) {
                $existingGroupId = $checkResp.value[0].id
                Write-Ok "Grupo ja existe: $($pg.Name) (ID: $($existingGroupId.Substring(0,8))...)"
                Log-Action "Verificar Grupo" "JA_EXISTE" "$($pg.Name)"
            }
        } catch {}

        # Criar se nao existe
        $groupId = $existingGroupId
        if (-not $groupId) {
            Write-Info "Criando AAD Security Group: $($pg.Name)..."
            try {
                $groupBody = @{
                    displayName     = $pg.Name
                    description     = "$($pg.Description) — MDE ServerTags v$($script:Version)"
                    mailEnabled     = $false
                    mailNickname    = Format-MailNickname $pg.Name
                    securityEnabled = $true
                    groupTypes      = @()
                } | ConvertTo-Json -Depth 3

                $createResp = Invoke-ApiWithRetry `
                    -Uri "https://graph.microsoft.com/v1.0/groups" `
                    -Method POST -Headers $graphHeaders -Body $groupBody `
                    -ApiName "Graph-CreateGroup" -MaxRetries 3 -BaseDelaySec 5

                $groupId = $createResp.id
                $createdCount++
                Write-Ok "Grupo CRIADO: $($pg.Name) (ID: $($groupId.Substring(0,8))...)"
                Log-Action "Criar Grupo" "CRIADO" "$($pg.Name)"

                Wait-Propagation -Seconds $script:PropDelay -Message "Propagacao do grupo $($pg.Name)"
            } catch {
                Write-Err "Falha ao criar grupo: $($_.Exception.Message)"
                $failedCount++
                Log-Action "Criar Grupo" "FALHA" "$($pg.Name): $($_.Exception.Message)"
                $script:DeviceGroupsCreated.Add([pscustomobject]@{
                    Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
                    Status = "FALHA_CRIACAO"; Automation = $pg.Automation
                    Description = $pg.Description; Purpose = $pg.Purpose
                    ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
                    SubName = $pg.SubName; GroupId = ""; MembersAdded = 0
                })
                continue
            }
        }

        # Adicionar Owner (usuario logado) ao grupo
        if ($groupId -and $signedInUserId) {
            try {
                $ownerBody = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$signedInUserId"
                } | ConvertTo-Json
                Invoke-ApiWithRetry `
                    -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/owners/`$ref" `
                    -Method POST -Headers $graphHeaders -Body $ownerBody `
                    -ApiName "Graph-AddOwner" -MaxRetries 2 -BaseDelaySec 3
                Write-Ok "Owner adicionado: $signedInUpn"
                Log-Action "Adicionar Owner" "OK" "$($pg.Name) -> $signedInUpn"
            } catch {
                $ownerErr = $_.Exception.Message
                $ownerErrBody = try { $_.ErrorDetails.Message } catch { '' }
                if ($ownerErr -match 'already exist' -or $ownerErrBody -match 'already exist') {
                    Write-Explain "  Owner ja configurado: $signedInUpn"
                } else {
                    Write-Warn "Falha ao adicionar Owner: $ownerErr"
                    Log-Action "Adicionar Owner" "WARN" "$($pg.Name): $ownerErr"
                }
            }
        }

        # Atribuir maquinas
        $membersAdded = 0; $membersSkipped = 0; $membersFailed = 0
        $addedAadIds = @{}  # Rastreia AAD Object IDs ja adicionados neste grupo

        if ($pg.Machines -and $pg.Machines.Count -gt 0 -and $groupId) {
            Write-Info "Atribuindo $($pg.Machines.Count) maquina(s)..."
            foreach ($machine in $pg.Machines) {
                $hostname = $machine.ComputerDnsName
                if (-not $hostname) { $membersSkipped++; continue }

                # Caminho 1: aadDeviceId (MDE API) -> deviceId (Graph) -> AAD Object ID
                $aadObjId = $null
                $matchMethod = ""
                $aadDevId = $mdeDeviceLookup[$hostname.ToLower()]
                if ($aadDevId) {
                    $aadObjId = $aadObjectLookup[$aadDevId]
                    if ($aadObjId) { $matchMethod = "aadDeviceId" }
                }

                # Caminho 2 (fallback): hostname -> displayName (Graph) -> AAD Object ID
                if (-not $aadObjId -and $aadDisplayNameLookup.Count -gt 0) {
                    $hostLower = $hostname.ToLower()
                    $shortName = $hostname.Split('.')[0].ToLower()
                    # Tentar FQDN primeiro, depois short hostname
                    $aadObjId = $aadDisplayNameLookup[$hostLower]
                    if (-not $aadObjId -and $shortName -ne $hostLower) {
                        $aadObjId = $aadDisplayNameLookup[$shortName]
                    }
                    if ($aadObjId) { $matchMethod = "hostname" }
                }

                if (-not $aadObjId) {
                    Write-Explain "  [SKIP] $hostname — sem aadDeviceId e sem match AAD"
                    $membersSkipped++; continue
                }

                # Dedup: se este AAD Object ID ja foi adicionado neste grupo, pular
                if ($addedAadIds.ContainsKey($aadObjId)) {
                    $membersAdded++
                    Write-Explain "  [=] $hostname — ja adicionado (mesmo device: $($addedAadIds[$aadObjId]))"
                    continue
                }

                try {
                    $memberBody = @{
                        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$aadObjId"
                    } | ConvertTo-Json

                    Invoke-ApiWithRetry `
                        -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members/`$ref" `
                        -Method POST -Headers $graphHeaders -Body $memberBody `
                        -ApiName "Graph-AddMember" -MaxRetries 3 -BaseDelaySec 3
                    $membersAdded++
                    $addedAadIds[$aadObjId] = $hostname
                    $osIcon = if ($machine.OsPlatform -match "Windows") { "W" } else { "L" }
                    $matchLabel = if ($matchMethod -eq "hostname") { " (hostname match)" } else { "" }
                    Write-Explain "  [+] [$osIcon] $hostname$matchLabel"
                } catch {
                    $memberErr = $_.Exception.Message
                    $errBody  = try { $_.ErrorDetails.Message } catch { '' }
                    if ($memberErr -match 'already exist' -or $errBody -match 'already exist') {
                        $membersAdded++
                        $addedAadIds[$aadObjId] = $hostname
                        Write-Explain "  [=] $hostname — ja membro"
                    } else {
                        $membersFailed++
                        Write-Explain "  [x] $hostname — falha: $memberErr"
                    }
                }
            }

            Write-Ok "Resultado: +$membersAdded ok, ~$membersSkipped sem match AAD, x$membersFailed falhas"
            $assignedTotal += $membersAdded

            if ($membersAdded -gt 0) {
                Wait-Propagation -Seconds ([Math]::Min($script:PropDelay, 5)) -Message "Propagacao de membros"
            }
        }

        $statusFinal = if ($existingGroupId) { "JA_EXISTE" } else { "CRIADO" }

        $script:DeviceGroupsCreated.Add([pscustomobject]@{
            Name = $pg.Name; Tag = $pg.Tag; Type = $pg.Type
            Status = $statusFinal; Automation = $pg.Automation
            Description = $pg.Description; Purpose = $pg.Purpose
            ServerCount = $pg.ServerCount; WinCount = $pg.WinCount; LinCount = $pg.LinCount
            SubName = $pg.SubName; GroupId = $groupId; MembersAdded = $membersAdded
        })
    }

    # Resumo
    Show-Separator
    Write-Host ""
    Write-Host "  +-- RESUMO DEVICE GROUPS ----------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  Total planejados  : $($allPlannedGroups.Count)" -ForegroundColor White
    Write-Host "  |  Criados           : $createdCount" -ForegroundColor Green
    Write-Host "  |  Ja existiam       : $(@($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'JA_EXISTE' }).Count)" -ForegroundColor Cyan
    Write-Host "  |  Ignorados (user)  : $(@($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'IGNORADO_USUARIO' }).Count)" -ForegroundColor Yellow
    Write-Host "  |  Falhas            : $failedCount" -ForegroundColor Red
    Write-Host "  |  Maquinas inseridas: $assignedTotal" -ForegroundColor Green
    Write-Host "  +----------------------------------------------------------------+" -ForegroundColor DarkCyan

    $script:Results["DeviceGroups"] = @{
        Status = "OK"; Count = $allPlannedGroups.Count
        Created = $createdCount; Assigned = $assignedTotal; Failed = $failedCount
    }
}

# ============================================================================
# ETAPA 8 — VERIFICAR EXTENSOES AAD + MDE EM VMs LIGADAS
# ============================================================================
function Test-VmExtensions {
    <#
    .SYNOPSIS
        Verifica extensoes AAD Login e MDE (Defender for Servers) em VMs ligadas.
        Para VMs sem extensoes, oferece instalacao automatica (modo -Execute).
        NAO liga nem desliga VMs — apenas verifica as que ja estao Running.
    #>
    param([hashtable]$Creds)
    Show-Step 8 "VERIFICAR EXTENSOES AAD + MDE EM VMs" `
        "Verificando extensoes de AAD Login e Microsoft Defender em VMs ligadas.`n  Para VMs sem extensoes, oferece opcao de instalacao automatica.`n  NOTA: Apenas VMs ja ligadas sao verificadas. Nenhuma VM sera ligada/desligada."

    if ($script:IsReportOnly) {
        Write-Info "Modo REPORT — verificacao apenas (sem instalacao)"
    }

    # --- Obter subscriptions do CSV ---
    $csvPath = Join-Path $script:ScriptRoot "subscription_mapping.csv"
    $subscriptions = @()
    if (Test-Path $csvPath) {
        try {
            $csvRows = Import-Csv $csvPath -Delimiter ";" -ErrorAction SilentlyContinue
            $subscriptions = @($csvRows | Where-Object { $_.subscriptionId -and $_.subscriptionId -notmatch '^aaaa' })
        } catch { }
    }

    if ($subscriptions.Count -eq 0) {
        Write-Warn "Nenhuma subscription encontrada no CSV — extensoes nao verificadas"
        $script:Results["Extensions"] = @{ Status = "SKIP"; Reason = "Sem subscriptions" }
        return
    }

    # --- Verificar Azure CLI ---
    $azLoggedIn = $false
    try {
        $null = & az account show --output none 2>$null
        $azLoggedIn = ($LASTEXITCODE -eq 0)
    } catch { }

    if (-not $azLoggedIn) {
        Write-Warn "Azure CLI nao autenticada — extensoes nao podem ser verificadas"
        Write-Explain "Execute 'az login' antes de rodar este script para habilitar verificacao de extensoes"
        $script:Results["Extensions"] = @{ Status = "SKIP"; Reason = "Azure CLI nao autenticada" }
        return
    }

    $totalVmsChecked   = 0
    $totalVmsOk        = 0
    $totalVmsMissing   = 0
    $extensionsToInstall = [System.Collections.Generic.List[hashtable]]::new()
    $extensionResults    = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($sub in $subscriptions) {
        $subId   = $sub.subscriptionId
        $subName = if ($sub.subscriptionName) { $sub.subscriptionName } else { $subId }

        Show-Separator
        Write-Info "Subscription: $subName"
        Write-Explain "  ID: $subId"

        # --- Listar VMs ligadas (Running) ---
        $runningVms = $null
        try {
            $vmJson = & az vm list -d --subscription $subId `
                --query "[?powerState=='VM running'].{name:name, rg:resourceGroup, osType:storageProfile.osDisk.osType, vmId:vmId}" `
                -o json 2>$null
            if ($LASTEXITCODE -eq 0 -and $vmJson) {
                $runningVms = $vmJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Warn "  Falha ao listar VMs: $($_.Exception.Message)"
            continue
        }

        if (-not $runningVms -or $runningVms.Count -eq 0) {
            Write-Explain "  Nenhuma VM ligada nesta subscription"
            continue
        }

        Write-Info "  $($runningVms.Count) VM(s) ligada(s) encontrada(s)"

        foreach ($vm in $runningVms) {
            $totalVmsChecked++
            $vmName  = $vm.name
            $vmRg    = $vm.rg
            $vmOs    = $vm.osType  # Linux ou Windows

            # --- Listar extensoes da VM ---
            $extensions = $null
            try {
                $extJson = & az vm extension list --vm-name $vmName -g $vmRg --subscription $subId -o json 2>$null
                if ($LASTEXITCODE -eq 0 -and $extJson) {
                    $extensions = $extJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Explain "  [SKIP] $vmName — falha ao listar extensoes"
                continue
            }

            $extNames = @()
            if ($extensions) {
                $extNames = @($extensions | ForEach-Object { $_.name })
            }

            # --- Verificar extensao AAD Login ---
            $hasAadExt  = $false
            $aadExtName = if ($vmOs -eq 'Linux') { 'AADSSHLoginForLinux' } else { 'AADLoginForWindows' }
            $aadPublisher = 'Microsoft.Azure.ActiveDirectory'
            if ($extNames -contains $aadExtName) { $hasAadExt = $true }

            # --- Verificar extensao MDE (Defender for Servers) ---
            $hasMdeExt  = $false
            $mdeExtName = if ($vmOs -eq 'Linux') { 'MDE.Linux' } else { 'MDE.Windows' }
            $mdePublisher = 'Microsoft.Azure.AzureDefenderForServers'
            if ($extNames -contains $mdeExtName) { $hasMdeExt = $true }

            # --- Resultado por VM ---
            $aadIcon = if ($hasAadExt) { [char]0x2713 } else { [char]0x2717 }
            $mdeIcon = if ($hasMdeExt) { [char]0x2713 } else { [char]0x2717 }

            if ($hasAadExt -and $hasMdeExt) {
                $totalVmsOk++
                Write-Explain "  [$aadIcon] [$mdeIcon] $vmName — AAD: OK | MDE: OK"
            } else {
                $totalVmsMissing++
                $missingList = @()
                if (-not $hasAadExt) { $missingList += "AAD($aadExtName)" }
                if (-not $hasMdeExt) { $missingList += "MDE($mdeExtName)" }
                Write-Warn "  $vmName — FALTANDO: $($missingList -join ', ')"

                # Adicionar a lista de instalacao
                if (-not $hasAadExt) {
                    $extensionsToInstall.Add(@{
                        VmName    = $vmName; RG = $vmRg; SubId = $subId; SubName = $subName
                        ExtName   = $aadExtName; ExtType = "AAD Login"
                        Publisher = $aadPublisher; OsType = $vmOs
                    })
                }
                if (-not $hasMdeExt) {
                    $extensionsToInstall.Add(@{
                        VmName    = $vmName; RG = $vmRg; SubId = $subId; SubName = $subName
                        ExtName   = $mdeExtName; ExtType = "MDE (Defender)"
                        Publisher = $mdePublisher; OsType = $vmOs
                    })
                }
            }

            $extensionResults.Add([pscustomobject]@{
                VM = $vmName; RG = $vmRg; Sub = $subName; OS = $vmOs
                AAD = $hasAadExt; MDE = $hasMdeExt
                AADExt = $aadExtName; MDEExt = $mdeExtName
            })
        }
    }

    # --- RESUMO ---
    Show-Separator
    Write-Host ""
    Write-Host "  +-- RESUMO EXTENSOES VM -----------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  Subscriptions verificadas : $($subscriptions.Count)" -ForegroundColor White
    Write-Host "  |  VMs ligadas verificadas   : $totalVmsChecked" -ForegroundColor White
    Write-Host "  |  VMs com extensoes OK      : $totalVmsOk" -ForegroundColor Green
    Write-Host "  |  VMs faltando extensao     : $totalVmsMissing" -ForegroundColor $(if($totalVmsMissing -gt 0){'Yellow'}else{'Green'})
    Write-Host "  |  Extensoes a instalar      : $($extensionsToInstall.Count)" -ForegroundColor $(if($extensionsToInstall.Count -gt 0){'Yellow'}else{'Green'})
    Write-Host "  +----------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # --- OFERECER INSTALACAO (apenas modo Execute) ---
    if ($extensionsToInstall.Count -gt 0 -and -not $script:IsReportOnly) {
        Write-Host "  Extensoes faltantes em VMs ligadas:" -ForegroundColor Yellow
        foreach ($ext in $extensionsToInstall) {
            Write-Host "    → $($ext.VmName) [$($ext.SubName)] : $($ext.ExtName) ($($ext.ExtType))" -ForegroundColor White
        }
        Write-Host ""

        if (Confirm-Action "Deseja instalar as extensoes faltantes nas VMs ligadas?" "S" "Instalar extensoes AAD+MDE") {
            $installed = 0; $failed = 0
            foreach ($ext in $extensionsToInstall) {
                Write-Info "Instalando $($ext.ExtName) em $($ext.VmName)..."
                try {
                    $null = & az vm extension set `
                        --vm-name $ext.VmName `
                        -g $ext.RG `
                        --subscription $ext.SubId `
                        --name $ext.ExtName `
                        --publisher $ext.Publisher `
                        --no-wait 2>$null

                    if ($LASTEXITCODE -eq 0) {
                        $installed++
                        Write-Ok "  $($ext.VmName): $($ext.ExtName) — instalacao iniciada"
                        Log-Action "Instalar extensao" "OK" "$($ext.ExtName) em $($ext.VmName)"
                    } else {
                        throw "az vm extension set retornou exit code $LASTEXITCODE"
                    }
                } catch {
                    $failed++
                    Write-Err "  $($ext.VmName): $($ext.ExtName) — falha: $($_.Exception.Message)"
                    Log-Action "Instalar extensao" "FALHA" "$($ext.ExtName) em $($ext.VmName): $($_.Exception.Message)"
                }
            }
            Write-Host ""
            Write-Ok "Instalacao: $installed iniciada(s), $failed falha(s)"
            if ($installed -gt 0) {
                Write-Info "Extensoes sao instaladas em background (--no-wait)"
                Write-Info "Verifique status: az vm extension list --vm-name <VM> -g <RG> --subscription <SUB>"
                Write-Info "Registro no AAD pode levar 5-30 min apos instalacao da extensao AAD"
            }

            # --- RE-ATRIBUICAO DE MEMBROS POS-EXTENSAO ---
            # Cadeia critica: VM -> Extensao AAD Login -> Objeto AAD -> Grupo -> Politica MDE
            # Sem a extensao, a VM nao tem aadDeviceId e NAO pode entrar no Device Group.
            # Apos instalar extensoes AAD Login, oferecer espera + re-atribuicao de membros.
            $aadExtCount = @($extensionsToInstall | Where-Object { $_.ExtType -eq 'AAD Login' }).Count
            if ($aadExtCount -gt 0 -and $installed -gt 0) {
                Write-Host ""
                Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "  ║  CADEIA CRITICA: VM → EXTENSAO AAD → OBJETO AAD → GRUPO → POLITICA ║" -ForegroundColor Cyan
                Write-Host "  ╠══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "  ║                                                                      ║" -ForegroundColor White
                Write-Host "  ║  $aadExtCount extensao(oes) AAD Login instalada(s) em VMs ligadas.               ║" -ForegroundColor White
                Write-Host "  ║  Apos propagacao (5-30 min), cada VM tera um OBJETO no Azure AD      ║" -ForegroundColor White
                Write-Host "  ║  que HABILITA insercao no Device Group para receber policies MDE.    ║" -ForegroundColor White
                Write-Host "  ║                                                                      ║" -ForegroundColor White
                Write-Host "  ║  SEM a extensao AAD Login, a VM NAO entra no grupo e                 ║" -ForegroundColor Yellow
                Write-Host "  ║  NAO recebera politicas AV/EDR via Intune.                           ║" -ForegroundColor Yellow
                Write-Host "  ║                                                                      ║" -ForegroundColor White
                Write-Host "  ║  [S] Aguardar propagacao e re-atribuir membros aos Device Groups     ║" -ForegroundColor Green
                Write-Host "  ║  [N] Continuar — membros atualizados na proxima execucao diaria      ║" -ForegroundColor DarkGray
                Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                Write-Host ""

                if (Confirm-Action "Aguardar propagacao AAD e re-atribuir membros aos Device Groups?" "S" "Re-atribuir membros pos-extensao") {
                    $defaultWait = 5
                    Write-Host ""
                    $waitInput = Read-Host "  [?] Minutos de espera para propagacao AAD (padrao: $defaultWait, recomendado ambientes grandes: 10)"
                    $waitMinutes = if ([string]::IsNullOrWhiteSpace($waitInput)) { $defaultWait } else {
                        try { [Math]::Max(1, [Math]::Min(30, [int]$waitInput)) } catch { $defaultWait }
                    }

                    Write-Info "Aguardando $waitMinutes minuto(s) para propagacao das extensoes AAD Login..."
                    Write-Explain "  (As VMs estao registrando-se no Azure AD em background)"
                    for ($i = $waitMinutes; $i -gt 0; $i--) {
                        Write-Host "`r  [Aguardando: $i min restante(s)]  " -NoNewline -ForegroundColor DarkGray
                        Start-Sleep -Seconds 60
                    }
                    Write-Host "`r  [OK] Propagacao concluida — re-atribuindo membros...        " -ForegroundColor Green
                    Write-Host ""

                    Write-Info "Re-executando Etapa 7 — atribuicao de membros aos Device Groups"
                    Write-Explain "  (Grupos ja existem — apenas NOVOS membros de VMs recem-registradas no AAD)"
                    Log-Action "Re-atribuir membros" "INICIO" "Pos-instalacao de $aadExtCount extensao(oes) AAD Login"
                    Manage-DeviceGroups -Creds $Creds
                    Log-Action "Re-atribuir membros" "OK" "Device Groups atualizados com novos membros AAD"
                }
            }
        }
    } elseif ($extensionsToInstall.Count -gt 0 -and $script:IsReportOnly) {
        Write-Info "Modo REPORT — extensoes faltantes documentadas para instalacao futura"
        Write-Info "Execute com -Execute para instalar extensoes faltantes automaticamente"
    } elseif ($totalVmsChecked -gt 0) {
        Write-Ok "Todas as VMs ligadas possuem extensoes AAD + MDE instaladas"
    }

    $script:ExtensionResults = $extensionResults
    $script:Results["Extensions"] = @{
        Status             = "OK"
        VmsChecked         = $totalVmsChecked
        VmsOk              = $totalVmsOk
        VmsMissing         = $totalVmsMissing
        ExtensionsToInstall = $extensionsToInstall.Count
    }
}

# ============================================================================
# ETAPA 9 — RELATORIO HTML COMPLETO
# ============================================================================
function Generate-HtmlReport {
    Show-Step 9 "GERAR RELATORIO HTML DETALHADO" `
        "Gerando relatorio completo com classificacao, Device Groups e recomendacoes."

    $outputPath = if ($OutputDir) { $OutputDir } else { Join-Path $script:ScriptRoot "Relatorios" }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }
    $modeLabel = if ($script:IsReportOnly) { "Report" } else { "Execute" }
    $htmlPath = Join-Path $outputPath "Relatorio-E2E-$modeLabel-$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html"

    $totalDuration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
    $cr  = $script:Results["Classification"]
    $crd = $script:Results["Credentials"]
    $ar  = $script:Results["AppRegistration"]

    # Prereq rows
    $prereqRows = ""
    foreach ($p in $script:Prereqs) {
        $icon = switch ($p.Status) { "OK" {"&#x2705;"} "WARN" {"&#x26A0;&#xFE0F;"} "ERR" {"&#x274C;"} default {"&#x2139;&#xFE0F;"} }
        $bc   = switch ($p.Status) { "OK" {"badge-ok"} "WARN" {"badge-warn"} "ERR" {"badge-err"} default {"badge-info"} }
        $prereqRows += "<div class='ck'><div class='ck-i'>$icon</div><div><div class='ck-l'>$($p.Name)</div><div class='ck-d'>$($p.Detail)</div></div><div class='$bc'>$($p.Status)</div></div>`n"
    }

    # Distribution bars
    $distBars = ""
    if ($cr -and $cr.Groups) {
        $total = $script:ServerCount
        if ($total -gt 0) {
            foreach ($kv in ($cr.Groups.GetEnumerator() | Sort-Object Value -Descending)) {
                $nm = if ($kv.Key) { $kv.Key } else { "SKIP" }
                $cnt = $kv.Value; $pct = [math]::Round($cnt / $total * 100); $w = [Math]::Max(3, $pct)
                $bc = switch ($nm) { "INATIVO_40D"{"#f85149"} "INATIVO_7D"{"#d29922"} "EFEMERO"{"#e3964a"} "DUPLICADA_EXCLUIR"{"#bc8cff"} "SKIP"{"#484f58"} default {"#58a6ff"} }
                $distBars += "<div style='display:flex;align-items:center;gap:16px;margin-bottom:10px'><div style='width:200px;font-size:12px;color:#8b949e;font-family:monospace'>$nm</div><div style='flex:1;background:#21262d;border-radius:4px;height:20px;overflow:hidden'><div style='width:${w}%;height:100%;background:${bc};border-radius:4px;min-width:24px;display:flex;align-items:center;padding-left:8px'><span style='font-size:11px;font-weight:700;color:#fff'>$cnt</span></div></div><div style='font-size:12px;color:${bc};font-weight:700;width:45px;text-align:right'>$pct%</div></div>`n"
            }
        }
    }

    # Server tables
    $serverTables = ""
    if ($script:ClassificationData) {
        $tgs = $script:ClassificationData | Group-Object TargetTag | Sort-Object @{Expression={
            switch ($_.Name) { "INATIVO_40D"{1} "INATIVO_7D"{2} "EFEMERO"{3} "DUPLICADA_EXCLUIR"{4} ""{6} default{5} }
        }}
        foreach ($tg in $tgs) {
            $tn = if ($tg.Name) { $tg.Name } else { "SKIP" }
            $tc = switch ($tg.Name) { "INATIVO_40D"{"tag-in40"} "INATIVO_7D"{"tag-in7"} "EFEMERO"{"tag-ef"} "DUPLICADA_EXCLUIR"{"tag-dup"} ""{"tag-sk"} default{"tag-ok"} }
            $rows = ""; $ix = 0
            foreach ($s in ($tg.Group | Sort-Object ComputerDnsName)) {
                $ix++
                $oi = if ($s.OsPlatform -match "Windows") {"W"} elseif ($s.OsPlatform -match "Linux|Ubuntu|Red") {"L"} else {"?"}
                $hc = switch ($s.HealthStatus) { "Active"{"#3fb950"} "Inactive"{"#f85149"} default{"#8b949e"} }
                $ab = switch ($s.Action) { "TAG"{"<span class='t t-tg'>TAG</span>"} "OK"{"<span class='t t-ok'>OK</span>"} default{"<span class='t t-sk'>$($s.Action)</span>"} }
                $sn = if ($s.ComputerDnsName.Length -gt 40) { $s.ComputerDnsName.Substring(0,37)+"..." } else { $s.ComputerDnsName }
                $dt = if ($s.DaysInactive -and $s.DaysInactive -ne "0") {"$($s.DaysInactive)d"} else {"Ativo"}
                $si = if ($s.SubscriptionId) { $s.SubscriptionId.Substring(0,[Math]::Min(8,$s.SubscriptionId.Length))+"..." } else {"--"}
                $rows += "<tr><td class='m' style='text-align:center'>$ix</td><td class='m'>[$oi] $sn</td><td>$($s.OsPlatform)</td><td style='color:$hc'>$($s.HealthStatus)</td><td>$dt</td><td class='m' style='font-size:10px'>$si</td><td style='text-align:center'>$ab</td><td style='font-size:11px;color:#8b949e'>$($s.Reason)</td></tr>`n"
            }
            $serverTables += "<div style='margin-bottom:32px'><div style='display:flex;align-items:center;gap:12px;margin-bottom:12px'><span class='t $tc' style='font-size:13px;padding:4px 14px'>$tn</span><span style='font-size:14px;font-weight:700;color:#e6edf3'>$($tg.Count) servidor(es)</span></div><div class='tw'><table><thead><tr><th>#</th><th>Hostname</th><th>OS</th><th>Health</th><th>Inativo</th><th>Sub</th><th>Acao</th><th>Motivo</th></tr></thead><tbody>$rows</tbody></table></div></div>`n"
        }
    }

    # Device Groups table
    $dgTable = ""
    if ($script:DeviceGroupsCreated.Count -gt 0) {
        $dgRows = ""
        foreach ($g in $script:DeviceGroupsCreated) {
            $sc = switch ($g.Status) { "CRIADO"{"#3fb950"} "JA_EXISTE"{"#58a6ff"} "PLANEJADO"{"#d29922"} "IGNORADO_USUARIO"{"#8b949e"} "FALHA_CRIACAO"{"#f85149"} default{"#d29922"} }
            $tp = if ($g.Type -eq "Subscription") {"SUB"} else {"LCY"}
            $tcc = switch ($g.Tag) { "INATIVO_7D"{"tag-in7"} "INATIVO_40D"{"tag-in40"} "EFEMERO"{"tag-ef"} "DUPLICADA_EXCLUIR"{"tag-dup"} default{"tag-ok"} }
            $subInfo = if ($g.SubName) { $g.SubName } else { "—" }
            $membInfo = if ($g.MembersAdded -gt 0) { "$($g.MembersAdded)" } else { "—" }
            $dgRows += "<tr><td class='m'>$($g.Name)</td><td>$subInfo</td><td><span class='t $tcc'>$($g.Tag)</span></td><td>$tp</td><td>$($g.ServerCount)</td><td>$($g.Automation)</td><td style='color:$sc'>$($g.Status)</td><td>$membInfo</td></tr>`n"
        }
        $dgTable = "<div class='tw'><table><thead><tr><th>Nome do Grupo</th><th>Subscription</th><th>Tag</th><th>Tipo</th><th>Servers</th><th>Automation</th><th>Status</th><th>Membros</th></tr></thead><tbody>$dgRows</tbody></table></div>"
    }

    # Actions log
    $actionsHtml = ""
    if ($script:ActionsLog.Count -gt 0) {
        $actRows = ""
        foreach ($a in $script:ActionsLog) {
            $aColor = switch ($a.Status) { "CRIADO"{"#3fb950"} "ACEITO"{"#3fb950"} "OK"{"#3fb950"} "IGNORADO"{"#8b949e"} "JA_EXISTE"{"#58a6ff"} "FALHA"{"#f85149"} default{"#d29922"} }
            $actRows += "<tr><td class='m'>$($a.Timestamp)</td><td>$($a.Action)</td><td style='color:$aColor'>$($a.Status)</td><td style='font-size:11px;color:#8b949e'>$($a.Detail)</td></tr>`n"
        }
        $actionsHtml = @"
  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F4DD;</span> Log de Acoes ($($script:ActionsLog.Count))</div>
    <div class='tw'><table><thead><tr><th>Hora</th><th>Acao</th><th>Status</th><th>Detalhe</th></tr></thead><tbody>$actRows</tbody></table></div>
  </div>
"@
    }

    # KPIs
    $kpiHtml = ""
    if ($cr -and $cr.Status -eq "OK") {
        $i40 = if ($cr.Groups.ContainsKey("INATIVO_40D"))       { $cr.Groups["INATIVO_40D"] }       else { 0 }
        $i7  = if ($cr.Groups.ContainsKey("INATIVO_7D"))        { $cr.Groups["INATIVO_7D"] }        else { 0 }
        $efc = if ($cr.Groups.ContainsKey("EFEMERO"))           { $cr.Groups["EFEMERO"] }           else { 0 }
        $dpc = if ($cr.Groups.ContainsKey("DUPLICADA_EXCLUIR")) { $cr.Groups["DUPLICADA_EXCLUIR"] } else { 0 }
        $dgC = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq "CRIADO" }).Count
        $dgA = ($script:DeviceGroupsCreated | Measure-Object -Property MembersAdded -Sum).Sum
        if ($null -eq $dgA) { $dgA = 0 }
        $kpiHtml = @"
  <div class="sg">
    <div class="sc blue"><div class="sn">$($script:ServerCount)</div><div class="sl">Total Servidores</div></div>
    <div class="sc red"><div class="sn">$i40</div><div class="sl">INATIVO 40D</div></div>
    <div class="sc yellow"><div class="sn">$i7</div><div class="sl">INATIVO 7D</div></div>
    <div class="sc orange"><div class="sn">$efc</div><div class="sl">EFEMERO</div></div>
    <div class="sc purple"><div class="sn">$dpc</div><div class="sl">DUPLICATA</div></div>
    <div class="sc green"><div class="sn">$dgC</div><div class="sl">Grupos Criados</div></div>
    <div class="sc cyan"><div class="sn">$dgA</div><div class="sl">Membros Atribuidos</div></div>
  </div>
"@
    }

    # HTML completo
    $html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MDE ServerTags v$($script:Version) | E2E $modeLabel | $(Get-Date -Format 'dd/MM/yyyy')</title>
<style>
:root{--bg:#0d1117;--b2:#161b22;--b3:#21262d;--bd:#30363d;--tx:#e6edf3;--t2:#8b949e;--gn:#3fb950;--gb:#0d2a10;--bl:#58a6ff;--bb:#051d40;--yw:#d29922;--yb:#2a1f00;--rd:#f85149;--rb:#2a0000;--og:#e3964a;--pp:#bc8cff;--cy:#39c5cf}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.6}
.hd{background:linear-gradient(135deg,#0d2a40 0%,#051d40 50%,#0d1117 100%);border-bottom:1px solid var(--bl);padding:40px 48px 32px}
.hd h1{font-size:26px;font-weight:700;color:#fff}.hd h1 em{color:var(--bl);font-style:normal}
.hd-s{color:var(--t2);font-size:14px;margin-top:4px}
.hd-m{display:flex;gap:24px;flex-wrap:wrap;margin-top:20px;padding-top:20px;border-top:1px solid var(--bd)}
.mi{display:flex;flex-direction:column}.ml{font-size:11px;color:var(--t2);text-transform:uppercase;letter-spacing:1px}.mv{font-size:13px;color:var(--tx);font-family:'Cascadia Code',monospace;margin-top:2px}
.ct{max-width:1400px;margin:0 auto;padding:32px 48px}
.sec{margin-bottom:40px}
.st{font-size:18px;font-weight:600;border-bottom:2px solid var(--bd);padding-bottom:12px;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.st span{font-size:20px}
.al{border-radius:8px;padding:16px 20px;border-left:4px solid;margin-bottom:16px;display:flex;align-items:flex-start;gap:14px}
.al-i{font-size:20px;flex-shrink:0}.al-t{font-weight:600;font-size:15px;margin-bottom:4px}.al-b{font-size:13px;color:var(--t2)}
.al-s{background:var(--gb);border-color:var(--gn)}.al-s .al-t{color:var(--gn)}
.al-w{background:var(--yb);border-color:var(--yw)}.al-w .al-t{color:var(--yw)}
.al-e{background:var(--rb);border-color:var(--rd)}.al-e .al-t{color:var(--rd)}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:16px;margin-bottom:24px}
.sc{background:var(--b2);border:1px solid var(--bd);border-radius:10px;padding:20px;position:relative;overflow:hidden}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.sc.green::before{background:var(--gn)}.sc.blue::before{background:var(--bl)}.sc.yellow::before{background:var(--yw)}.sc.red::before{background:var(--rd)}.sc.orange::before{background:var(--og)}.sc.purple::before{background:var(--pp)}.sc.cyan::before{background:var(--cy)}.sc.gray::before{background:#484f58}
.sn{font-size:36px;font-weight:700;line-height:1;margin-bottom:6px}
.sc.green .sn{color:var(--gn)}.sc.blue .sn{color:var(--bl)}.sc.yellow .sn{color:var(--yw)}.sc.red .sn{color:var(--rd)}.sc.orange .sn{color:var(--og)}.sc.purple .sn{color:var(--pp)}.sc.cyan .sn{color:var(--cy)}.sc.gray .sn{color:#484f58}
.sl{font-size:13px;color:var(--t2)}
.ck{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:12px 16px;display:flex;align-items:center;gap:14px;margin-bottom:8px}
.ck-i{font-size:18px;flex-shrink:0}.ck-l{font-size:13px;font-weight:500}.ck-d{font-size:12px;color:var(--t2);margin-top:2px;font-family:monospace}
.badge-ok{margin-left:auto;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;background:var(--gb);color:var(--gn);border:1px solid var(--gn)}
.badge-warn{margin-left:auto;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;background:var(--yb);color:var(--yw);border:1px solid var(--yw)}
.badge-err{margin-left:auto;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;background:var(--rb);color:var(--rd);border:1px solid var(--rd)}
.badge-info{margin-left:auto;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;background:var(--bb);color:var(--bl);border:1px solid var(--bl)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;background:var(--b2);border-radius:10px;overflow:hidden}
thead th{background:var(--b3);color:var(--t2);font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:10px 14px;text-align:left;border-bottom:2px solid var(--bd)}
tbody td{padding:8px 14px;border-bottom:1px solid var(--bd);font-size:12px}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:rgba(88,166,255,0.04)}
.m{font-family:'Cascadia Code',monospace;font-size:12px}
.t{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;border:1px solid}
.tag-in40{background:#2a0000;color:#f85149;border-color:#f85149}
.tag-in7{background:#2a1f00;color:#d29922;border-color:#d29922}
.tag-ef{background:#2a1600;color:#e3964a;border-color:#e3964a}
.tag-dup{background:#1a0a2e;color:#bc8cff;border-color:#bc8cff}
.tag-sk{background:#21262d;color:#8b949e;border-color:#8b949e}
.tag-ok{background:#0d2a10;color:#3fb950;border-color:#3fb950}
.t-tg{background:#051d40;color:#58a6ff;border-color:#58a6ff}
.t-ok{background:#0d2a10;color:#3fb950;border-color:#3fb950}
.t-sk{background:#21262d;color:#8b949e;border-color:#8b949e}
.ig{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.ic{background:var(--b2);border:1px solid var(--bd);border-radius:10px;padding:20px}
.ict{font-size:12px;color:var(--t2);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px}
.ir{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--bd);gap:16px}
.ir:last-child{border-bottom:none}
.ik{font-size:12px;color:var(--t2);flex-shrink:0}
.iv{font-size:12px;text-align:right;font-family:monospace;word-break:break-all}
hr.dv{border:none;border-top:1px solid var(--bd);margin:32px 0}
.rl{list-style:none}
.rl li{background:var(--b2);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;margin-bottom:10px;display:flex;align-items:flex-start;gap:14px}
.rp{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;flex-shrink:0;margin-top:1px}
.ph{background:#2a0000;color:var(--rd)}.pm{background:var(--yb);color:var(--yw)}.pl{background:var(--bb);color:var(--bl)}
.rt{font-size:13px;font-weight:600}.rd{font-size:12px;color:var(--t2);margin-top:4px}
.cb{background:var(--b3);border:1px solid var(--bd);border-radius:8px;padding:16px 20px;font-family:monospace;font-size:12px;color:#79c0ff;overflow-x:auto;white-space:pre;margin:12px 0}
.ft{background:var(--b2);border-top:1px solid var(--bd);padding:24px 48px;margin-top:40px;display:flex;justify-content:space-between;align-items:center}
.fl,.fr{font-size:12px;color:var(--t2)}
@media print{body{background:#fff;color:#000}table,td,th{border:1px solid #ccc !important}}
</style></head><body>

<div class="hd">
  <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px">
    <div style="width:56px;height:56px;background:var(--bl);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:28px">&#x1F6E1;</div>
    <div><h1>MDE ServerTags <em>v$($script:Version)</em> &#x2014; E2E ($modeLabel)</h1>
    <div class="hd-s">Microsoft Defender for Endpoint &#x00B7; Classificacao + Device Groups &#x00B7; Community Edition</div></div>
  </div>
  <div class="hd-m">
    <div class="mi"><span class="ml">Data</span><span class="mv">$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</span></div>
    <div class="mi"><span class="ml">Hostname</span><span class="mv">$env:COMPUTERNAME</span></div>
    <div class="mi"><span class="ml">Tenant</span><span class="mv">$($crd.TenantId)</span></div>
    <div class="mi"><span class="ml">Modo</span><span class="mv" style="color:$(if($script:IsReportOnly){'var(--gn)'}else{'var(--yw)'})">$modeLabel</span></div>
    <div class="mi"><span class="ml">Duracao</span><span class="mv">${totalDuration}s</span></div>
    <div class="mi"><span class="ml">Graph</span><span class="mv" style="color:$(if($script:GraphTokenObtained){'var(--gn)'}else{'var(--yw)'})">$(if($script:GraphTokenObtained){'ATIVO'}else{'N/A'})</span></div>
    <div class="mi"><span class="ml">Dev</span><span class="mv">Rafael França</span></div>
  </div>
</div>

<div class="ct">

  <div class="sec">
    <div class="al $(if($script:Errors.Count -eq 0){'al-s'}else{'al-e'})">
      <div class="al-i">$(if($script:Errors.Count -eq 0){'&#x2705;'}else{'&#x274C;'})</div>
      <div><div class="al-t">$(if($script:Errors.Count -eq 0){"E2E Completa — v$($script:Version) OPERACIONAL ($modeLabel)"}else{"$($script:Errors.Count) erro(s)"})</div>
      <div class="al-b">${totalDuration}s &#x00B7; $($script:Prereqs.Count) checks &#x00B7; $($script:ServerCount) servidores &#x00B7; $($script:DeviceGroupsCreated.Count) grupos</div></div>
    </div>
  </div>

  $kpiHtml

  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F50D;</span> Pre-Requisitos ($($script:Prereqs.Count))</div>$prereqRows</div>

  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F511;</span> Credenciais</div>
    <div class="ig">
      <div class="ic"><div class="ict">App Registration</div>
        <div class="ir"><span class="ik">Display Name</span><span class="iv">$($ar.DisplayName)</span></div>
        <div class="ir"><span class="ik">App ID</span><span class="iv">$($crd.AppId)</span></div>
        <div class="ir"><span class="ik">Tenant ID</span><span class="iv">$($crd.TenantId)</span></div>
      </div>
      <div class="ic"><div class="ict">Tokens</div>
        <div class="ir"><span class="ik">MDE</span><span class="iv" style="color:$(if($script:TokenObtained){'var(--gn)'}else{'var(--rd)'})">$(if($script:TokenObtained){"OK"}else{"FALHA"})</span></div>
        <div class="ir"><span class="ik">Graph</span><span class="iv" style="color:$(if($script:GraphTokenObtained){'var(--gn)'}else{'var(--yw)'})">$(if($script:GraphTokenObtained){"OK"}else{"N/A"})</span></div>
        <div class="ir"><span class="ik">Secret Expiry</span><span class="iv" style="color:var(--yw)">$($ar.SecretExpiry)</span></div>
      </div>
    </div>
  </div>

$(if ($cr -and $cr.Status -eq "OK") {
@"
  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F4CA;</span> Distribuicao ($($script:ServerCount) servidores)</div>
    <div style="background:var(--b2);border:1px solid var(--bd);border-radius:10px;padding:24px;margin-bottom:20px">$distBars</div>
  </div>
  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F4CB;</span> Servidores por Categoria</div>$serverTables</div>
"@
})

$(if ($script:DeviceGroupsCreated.Count -gt 0) {
@"
  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F3AF;</span> Device Groups ($($script:DeviceGroupsCreated.Count)) — Subscription = Nome do Grupo</div>
    <div style="background:var(--b2);border:1px solid var(--bd);border-radius:10px;padding:18px;margin-bottom:16px;font-size:12px;color:var(--t2)">
      <strong style="color:var(--tx)">Paradigma v4.0:</strong> Nome da subscription = nome do Device Group. Maquinas inseridas via Graph API.
    </div>
    $dgTable
  </div>
"@
})

$actionsHtml

  <hr class="dv">
  <div class="sec"><div class="st"><span>&#x1F4D6;</span> Como Usar</div>
    <div class="cb"># Modo relatorio (seguro)
.\TEST-Lab-E2E.ps1 -Report

# Modo execucao (tags + grupos Graph + atribuicao)
.\TEST-Lab-E2E.ps1 -Execute

# Propagacao com delay maior
.\TEST-Lab-E2E.ps1 -Execute -PropagationDelay 15

# Pular criacao de grupos
.\TEST-Lab-E2E.ps1 -Execute -SkipGroupCreation</div>
  </div>

</div>

<div class="ft">
  <div class="fl"><strong style="color:var(--tx)">MDE ServerTags v$($script:Version)</strong><br>$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') &#x00B7; $modeLabel</div>
  <div class="fr" style="text-align:right"><strong style="color:var(--tx)">Rafael Franca</strong><br>Open Source — Community Edition</div>
</div>
</body></html>
"@

    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)
    $htmlSize = (Get-Item $htmlPath).Length
    Write-Ok "Relatorio HTML: $htmlPath ($([math]::Round($htmlSize / 1024, 1)) KB)"
    try { Start-Process $htmlPath; Write-Ok "Aberto no navegador" } catch { Write-Info "Abra manualmente: $htmlPath" }
    $script:Results["HtmlReport"] = @{ Path = $htmlPath; Size = $htmlSize }
    return $htmlPath
}

# ============================================================================
# RESUMO TECNICO COMPLETO — PRE-RELATORIO (COM CONFIRMACAO)
# Exibe resumo detalhado de tudo que foi executado/detectado e pede
# confirmacao antes de gerar o relatorio HTML final.
# ============================================================================
function Show-TechnicalSummary {
    $elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
    $modeLabel = if ($script:IsReportOnly) { "REPORT-ONLY" } else { "EXECUTE" }
    $crd = $script:Results["Credentials"]
    $ar  = $script:Results["AppRegistration"]
    $cr  = $script:Results["Classification"]
    $cfgData = $script:Results["Config"]
    $authData = $script:Results["Auth"]

    Write-Host ""
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║         RESUMO TECNICO COMPLETO — ANTES DO RELATORIO HTML           ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host ""

    # ── 1. SESSAO ────────────────────────────────────────────────────────────
    Write-Host "  ║ [1] SESSAO DE EXECUCAO" -ForegroundColor White
    Write-Host "  ║     Modo           : $modeLabel" -ForegroundColor $(if($script:IsReportOnly){"Green"}else{"Yellow"})
    Write-Host "  ║     Tempo decorrido: ${elapsed}s" -ForegroundColor Gray
    Write-Host "  ║     Host           : $env:COMPUTERNAME ($env:USERDOMAIN\$env:USERNAME)" -ForegroundColor Gray
    Write-Host "  ║     PowerShell     : v$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Gray
    Write-Host "  ║     Script         : TEST-Lab-E2E.ps1 v$($script:Version)" -ForegroundColor Gray
    Write-Host "  ║     PropDelay      : ${script:PropDelay}s entre operacoes de API" -ForegroundColor Gray
    Write-Host "  ║" -ForegroundColor DarkGray

    # ── 2. OAUTH2 ────────────────────────────────────────────────────────────
    Write-Host "  ║ [2] AUTENTICACAO OAUTH2 (grant_type=client_credentials)" -ForegroundColor White
    if ($crd) {
        Write-Host "  ║     Tenant  : $($crd.TenantId)" -ForegroundColor Cyan
        Write-Host "  ║     App ID  : $($crd.AppId)" -ForegroundColor Cyan
        Write-Host "  ║     Secret  : $($crd.SecretHint) (fonte: $($crd.SecretSource))" -ForegroundColor Yellow
    }
    Write-Host "  ║     Endpoint: POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" -ForegroundColor DarkGray
    Write-Host "  ║" -ForegroundColor DarkGray
    $mdeSt = if ($script:TokenObtained)      { "OK — roles incluidas no JWT (Machine.ReadWrite.All)" } else { "FALHA — classificacao bloqueada" }
    $gphSt = if ($script:GraphTokenObtained) { "OK — Group+Device+GroupMember ReadWrite"              } else { "N/A — grupos serao documentados" }
    $armSt2 = if ($authData -and $authData.ARM.Status -eq 'OK') { "OK — subscription discovery" } else { "N/A — fallback Azure CLI ou CSV" }
    Write-Host "  ║     Token MDE   : $mdeSt" -ForegroundColor $(if($script:TokenObtained){"Green"}else{"Red"})
    Write-Host "  ║       scope     : https://api.securitycenter.microsoft.com/.default" -ForegroundColor DarkGray
    Write-Host "  ║       role      : Machine.ReadWrite.All (ler dispositivos + aplicar tags)" -ForegroundColor DarkGray
    Write-Host "  ║       GUID role : ea8291d3-4b9a-44b5-bc3a-6cea3026dc79" -ForegroundColor DarkGray
    Write-Host "  ║     Token Graph : $gphSt" -ForegroundColor $(if($script:GraphTokenObtained){"Green"}else{"Yellow"})
    Write-Host "  ║       scope     : https://graph.microsoft.com/.default" -ForegroundColor DarkGray
    Write-Host "  ║       roles     : Group.ReadWrite.All (62a82d76) + Device.Read.All (7438b122)" -ForegroundColor DarkGray
    Write-Host "  ║                   GroupMember.ReadWrite.All (dbaae8cf)" -ForegroundColor DarkGray
    Write-Host "  ║     Token ARM   : $armSt2" -ForegroundColor $(if($authData -and $authData.ARM.Status -eq 'OK'){"Green"}else{"Yellow"})
    Write-Host "  ║       scope     : https://management.azure.com/.default" -ForegroundColor DarkGray
    Write-Host "  ║" -ForegroundColor DarkGray

    # ── 3. APP REGISTRATION ──────────────────────────────────────────────────
    if ($ar) {
        Write-Host "  ║ [3] APP REGISTRATION & ADMIN CONSENT" -ForegroundColor White
        Write-Host "  ║     Display Name  : $($ar.DisplayName)" -ForegroundColor Gray
        Write-Host "  ║     SP Object ID  : $($ar.SPObjectId)" -ForegroundColor Gray
        Write-Host "  ║     Admin Consent : $($ar.ConsentStatus) ($($ar.Permissions.Count) appRoleAssignment(s))" -ForegroundColor $(if($ar.ConsentStatus -eq "Granted"){"Green"}else{"Yellow"})
        Write-Host "  ║     Secret Expiry : $($ar.SecretExpiry)" -ForegroundColor Gray
        Write-Host "  ║     Consent API   : POST /servicePrincipals/{resourceId}/appRoleAssignedTo" -ForegroundColor DarkGray
        Write-Host "  ║     Consent URL   : https://login.microsoftonline.com/{tenant}/adminconsent" -ForegroundColor DarkGray
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 4. CLASSIFICACAO ─────────────────────────────────────────────────────
    if ($cr -and $cr.Status -eq "OK") {
        Write-Host "  ║ [4] CLASSIFICACAO DE SERVIDORES" -ForegroundColor White
        Write-Host "  ║     Engine   : Sync-MDE-ServerTags-BySubscription.ps1 v2.2.0" -ForegroundColor Gray
        Write-Host "  ║     Total    : $($cr.ServerCount) servidores classificados em $($cr.Duration)s" -ForegroundColor Cyan
        Write-Host "  ║     API Read : GET /api/machines (filtra osPlatform contendo 'Server')" -ForegroundColor DarkGray
        Write-Host "  ║     API Write: PUT /api/machines/{id}/tags {Value, Action:'Add'}" -ForegroundColor DarkGray
        Write-Host "  ║     CSV      : $($cr.CsvPath)" -ForegroundColor DarkGray
        Write-Host "  ║" -ForegroundColor DarkGray
        if ($cfgData) {
            Write-Host "  ║     Cadeia de prioridade (primeira regra que bate define a tag):" -ForegroundColor White
            Write-Host "  ║       P1 DUPLICADA_EXCLUIR — hostname com 2+ machineIds; registro antigo marcado" -ForegroundColor DarkGray
            Write-Host "  ║          Algoritmo: agrupa por hostname, ordena por lastSeen desc, marca N-1" -ForegroundColor DarkGray
            Write-Host "  ║          Excecao: VMSS (instancias _0, _1) nao sao tratadas como duplicatas" -ForegroundColor DarkGray
            Write-Host "  ║       P2 EFEMERO           — lifespan <= $($cfgData.HorasEfemero)h + healthStatus=Inactive + sem sub" -ForegroundColor DarkGray
            Write-Host "  ║          Criterio: (lastSeen - firstSeen) <= $($cfgData.HorasEfemero) horas AND Inactive" -ForegroundColor DarkGray
            Write-Host "  ║       P3 INATIVO_40D       — lastSeen >= $($cfgData.DiasInativo40d) dias (candidato a offboard)" -ForegroundColor DarkGray
            Write-Host "  ║          Campo: lastSeen do JSON /api/machines" -ForegroundColor DarkGray
            Write-Host "  ║       P4 INATIVO_7D        — lastSeen entre $($cfgData.DiasInativo7d) e $($cfgData.DiasInativo40d) dias (investigar)" -ForegroundColor DarkGray
            Write-Host "  ║          Escalada automatica: INATIVO_7D -> INATIVO_40D apos $($cfgData.DiasInativo40d) dias" -ForegroundColor DarkGray
            Write-Host "  ║       P5 {SUBSCRIPTION}    — ativo, subscriptionId mapeado no CSV ou discovery" -ForegroundColor DarkGray
            Write-Host "  ║          Tag = nome da subscription (via subscription_mapping.csv ou Azure CLI)" -ForegroundColor DarkGray
            Write-Host "  ║       FB SKIP              — ativo mas sem subscription mapeada (ignorado)" -ForegroundColor DarkGray
            Write-Host "  ║" -ForegroundColor DarkGray
        }
        if ($cr.Groups) {
            Write-Host "  ║     Distribuicao por tag:" -ForegroundColor White
            $total = $cr.ServerCount
            foreach ($kv in ($cr.Groups.GetEnumerator() | Sort-Object Value -Descending)) {
                $nm = if ($kv.Key) { $kv.Key } else { "SKIP" }
                $cnt = $kv.Value
                $pct = if ($total -gt 0) { [math]::Round($cnt / $total * 100, 1) } else { 0 }
                $bar = ([char]9608).ToString() * [Math]::Min(20, [Math]::Max(1, [int]($pct / 5)))
                Write-Host "  ║       $($nm.PadRight(22)) $($cnt.ToString().PadLeft(3))  $("$pct%".PadLeft(6))  $bar" -ForegroundColor Cyan
            }
            Write-Host "  ║" -ForegroundColor DarkGray
        }
        if ($cr.Actions) {
            Write-Host "  ║     Acoes executadas na API MDE:" -ForegroundColor White
            foreach ($kv in ($cr.Actions.GetEnumerator() | Sort-Object Value -Descending)) {
                $expl = switch ($kv.Key) {
                    "TAG"   { "— PUT /api/machines/{id}/tags (tag aplicada/atualizada)" }
                    "OK"    { "— nenhuma chamada API (tag ja correta, idempotente)" }
                    "SKIP"  { "— ignorado (sem subscription no CSV/discovery)" }
                    "CLEAN" { "— DELETE tag legada removida do servidor" }
                    default { "" }
                }
                Write-Host "  ║       $($kv.Key.PadRight(8))  $($kv.Value.ToString().PadLeft(3))  $expl" -ForegroundColor Gray
            }
            Write-Host "  ║" -ForegroundColor DarkGray
        }
    } elseif ($cr) {
        Write-Host "  ║ [4] CLASSIFICACAO: $($cr.Status)" -ForegroundColor Yellow
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 5. DEVICE GROUPS ─────────────────────────────────────────────────────
    if ($script:DeviceGroupsCreated.Count -gt 0) {
        $nCriados  = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'CRIADO' }).Count
        $nExiste   = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'JA_EXISTE' }).Count
        $nPlan     = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'PLANEJADO' }).Count
        $nIgn      = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'IGNORADO_USUARIO' }).Count
        $nFail     = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq 'FALHA_CRIACAO' }).Count
        $nMembros  = ($script:DeviceGroupsCreated | Measure-Object -Property MembersAdded -Sum).Sum
        if ($null -eq $nMembros) { $nMembros = 0 }
        $nSub = @($script:DeviceGroupsCreated | Where-Object { $_.Type -eq 'Subscription' }).Count
        $nLcy = @($script:DeviceGroupsCreated | Where-Object { $_.Type -eq 'Lifecycle' }).Count

        Write-Host "  ║ [5] DEVICE GROUPS VIA GRAPH API ($($script:DeviceGroupsCreated.Count) grupos)" -ForegroundColor White
        Write-Host "  ║     Paradigma  : subscription name = group name (prefixo MDE-)" -ForegroundColor DarkGray
        Write-Host "  ║     API Criar  : POST /v1.0/groups (securityEnabled=true, mailEnabled=false)" -ForegroundColor DarkGray
        Write-Host "  ║     API Membro : POST /v1.0/groups/{id}/members/`$ref" -ForegroundColor DarkGray
        Write-Host "  ║     API Check  : GET /v1.0/groups?`$filter=displayName eq '{name}'" -ForegroundColor DarkGray
        Write-Host "  ║     Subscription: $nSub grupo(s) | Lifecycle: $nLcy grupo(s)" -ForegroundColor Gray
        Write-Host "  ║     Criados: $nCriados | Existentes: $nExiste | Planejados: $nPlan | Ignorados: $nIgn | Falhas: $nFail" -ForegroundColor Gray
        Write-Host "  ║     Membros atribuidos: $nMembros maquina(s) via Graph API" -ForegroundColor Gray
        Write-Host "  ║" -ForegroundColor DarkGray

        foreach ($g in $script:DeviceGroupsCreated) {
            $sc = switch ($g.Status) {
                "CRIADO"          {"Green"}
                "JA_EXISTE"       {"Cyan"}
                "PLANEJADO"       {"Yellow"}
                "IGNORADO_USUARIO"{"DarkGray"}
                "FALHA_CRIACAO"   {"Red"}
                "AGUARDANDO_GRAPH"{"Yellow"}
                default           {"Gray"}
            }
            $tp = if ($g.Type -eq "Subscription") { "SUB" } else { "LCY" }
            $mi = if ($g.MembersAdded -gt 0) { "+$($g.MembersAdded)" } else { "  0" }
            Write-Host "  ║       [$tp] $($g.Name.PadRight(34)) $($g.Status.PadRight(17)) Auto:$($g.Automation.PadRight(5)) Mbr:$mi" -ForegroundColor $sc
        }
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 5.1 VISAO DO AMBIENTE ────────────────────────────────────────────────
    $envOv = $script:Results["EnvironmentOverview"]
    if ($envOv) {
        Write-Host "  ║ [5.1] VISAO ASSERTIVA DO AMBIENTE" -ForegroundColor White
        Write-Host "  ║     Total servidores      : $($envOv.Total)" -ForegroundColor Gray
        Write-Host "  ║     Ativos (reporting)    : $($envOv.Active)" -ForegroundColor Green
        Write-Host "  ║     Em subscriptions      : $($envOv.InSubscriptions) (alvo de AV/EDR policies)" -ForegroundColor Green
        Write-Host "  ║     Em lifecycle           : $($envOv.InLifecycle) (inativos/efemeros/duplicatas)" -ForegroundColor Yellow
        Write-Host "  ║     Nao gerenciados        : $($envOv.Unmanaged) (sem subscription Azure)" -ForegroundColor $(if($envOv.Unmanaged -gt 0){"Red"}else{"Green"})
        Write-Host "  ║     Cobertura policies     : $($envOv.Coverage)% dos servidores em sub groups" -ForegroundColor $(if($envOv.Coverage -ge 50){"Green"}elseif($envOv.Coverage -ge 20){"Yellow"}else{"Red"})
        Write-Host "  ║     Subscription groups    : $($envOv.SubscriptionGroups) (para deploy de AV/EDR)" -ForegroundColor Cyan
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 5.2 EXTENSOES VM (AAD + MDE) ─────────────────────────────────────────
    $extData = $script:Results["Extensions"]
    if ($extData -and $extData.Status -eq "OK") {
        Write-Host "  ║ [5.2] EXTENSOES AAD + MDE EM VMs LIGADAS" -ForegroundColor White
        Write-Host "  ║     VMs verificadas   : $($extData.VmsChecked)" -ForegroundColor Gray
        Write-Host "  ║     Extensoes OK       : $($extData.VmsOk) VM(s) com AAD + MDE" -ForegroundColor Green
        Write-Host "  ║     Faltando extensao  : $($extData.VmsMissing) VM(s)" -ForegroundColor $(if($extData.VmsMissing -gt 0){"Yellow"}else{"Green"})
        Write-Host "  ║     A instalar         : $($extData.ExtensionsToInstall) extensao(oes)" -ForegroundColor $(if($extData.ExtensionsToInstall -gt 0){"Yellow"}else{"Green"})
        Write-Host "  ║     Tipos verificados  :" -ForegroundColor DarkGray
        Write-Host "  ║       AAD Login: AADSSHLoginForLinux (Linux) / AADLoginForWindows (Windows)" -ForegroundColor DarkGray
        Write-Host "  ║       MDE     : MDE.Linux / MDE.Windows (Microsoft.Azure.AzureDefenderForServers)" -ForegroundColor DarkGray
        Write-Host "  ║" -ForegroundColor DarkGray

        if ($script:ExtensionResults -and $script:ExtensionResults.Count -gt 0) {
            foreach ($er in $script:ExtensionResults) {
                $aadSt = if ($er.AAD) { [char]0x2713 } else { [char]0x2717 }
                $mdeSt = if ($er.MDE) { [char]0x2713 } else { [char]0x2717 }
                $erColor = if ($er.AAD -and $er.MDE) { "Green" } else { "Yellow" }
                Write-Host "  ║       [$aadSt AAD] [$mdeSt MDE] $($er.VM.PadRight(28)) [$($er.OS)] $($er.Sub)" -ForegroundColor $erColor
            }
            Write-Host "  ║" -ForegroundColor DarkGray
        }
    } elseif ($extData -and $extData.Status -eq "SKIP") {
        Write-Host "  ║ [5.2] EXTENSOES: Nao verificadas ($($extData.Reason))" -ForegroundColor Yellow
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 6. LOG DE ACOES ──────────────────────────────────────────────────────
    if ($script:ActionsLog.Count -gt 0) {
        Write-Host "  ║ [6] LOG DE ACOES ($($script:ActionsLog.Count) registros)" -ForegroundColor White
        foreach ($a in $script:ActionsLog) {
            $ac = switch ($a.Status) {
                "CRIADO"    {"Green"}
                "ACEITO"    {"Green"}
                "OK"        {"Green"}
                "IGNORADO"  {"DarkGray"}
                "JA_EXISTE" {"Cyan"}
                "FALHA"     {"Red"}
                "MANUAL"    {"Yellow"}
                "CONCEDIDO" {"Green"}
                default     {"Yellow"}
            }
            Write-Host "  ║       $($a.Timestamp)  $($a.Action.PadRight(26))  $($a.Status.PadRight(12))  $($a.Detail)" -ForegroundColor $ac
        }
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 7. AVISOS E ERROS ────────────────────────────────────────────────────
    if ($script:Warnings.Count -gt 0 -or $script:Errors.Count -gt 0) {
        Write-Host "  ║ [7] AVISOS ($($script:Warnings.Count)) E ERROS ($($script:Errors.Count))" -ForegroundColor White
        foreach ($e in $script:Errors)   { Write-Host "  ║       [ERRO]  $e" -ForegroundColor Red }
        foreach ($w in $script:Warnings) { Write-Host "  ║       [AVISO] $w" -ForegroundColor Yellow }
        Write-Host "  ║" -ForegroundColor DarkGray
    }

    # ── 8. RECOMENDACOES TECNICAS ────────────────────────────────────────────
    Write-Host "  ║ [8] RECOMENDACOES TECNICAS" -ForegroundColor White
    if ($script:IsReportOnly -and $script:ServerCount -gt 0) {
        Write-Host "  ║       > Classificacao validada. Proximo: .\TEST-Lab-E2E.ps1 -Execute" -ForegroundColor Cyan
    }
    $i40x = 0; $dupx = 0
    if ($cr -and $cr.Groups) {
        if ($cr.Groups.ContainsKey("INATIVO_40D")) { $i40x = $cr.Groups["INATIVO_40D"] }
        if ($cr.Groups.ContainsKey("DUPLICADA_EXCLUIR")) { $dupx = $cr.Groups["DUPLICADA_EXCLUIR"] }
    }
    if ($i40x -gt 0) { Write-Host "  ║       > $i40x servidor(es) INATIVO_40D: cruzar inventario Azure, considerar offboard" -ForegroundColor Yellow }
    if ($dupx -gt 0) { Write-Host "  ║       > $dupx servidor(es) DUPLICATA: offboard recomendado (registros fantasma no MDE)" -ForegroundColor Yellow }
    if (-not $script:GraphTokenObtained) {
        Write-Host "  ║       > Graph Token indisponivel: conceder Admin Consent e re-executar" -ForegroundColor Yellow
        Write-Host "  ║         Permissoes necessarias: Group.ReadWrite.All + Device.Read.All" -ForegroundColor DarkGray
    }
    if ($ar -and $ar.SecretExpiry -and $ar.SecretExpiry -ne "N/A") {
        try {
            $daysRemaining = [math]::Round(([datetime]$ar.SecretExpiry - (Get-Date)).TotalDays)
            if ($daysRemaining -lt 90) {
                $urgency = if ($daysRemaining -lt 30) { "URGENTE: renovar imediatamente!" } else { "planejar renovacao" }
                Write-Host "  ║       > Secret expira em $daysRemaining dias — $urgency" -ForegroundColor $(if($daysRemaining -lt 30){"Red"}else{"Yellow"})
            }
        } catch {}
    }
    Write-Host "  ║       > Agendamento diario: Install-ScheduledTask.ps1 (padrao 06:00)" -ForegroundColor DarkGray
    Write-Host "  ║       > Configurar politicas AV/EDR diferenciadas por Device Group no Intune" -ForegroundColor DarkGray
    Write-Host "  ║       > Producao: scan diario + cloud-protection alta + tamper protection ON" -ForegroundColor DarkGray
    Write-Host "  ║       > Inativos/Efemeros: no automated response (candidatos a offboard)" -ForegroundColor DarkGray
    $extD = $script:Results["Extensions"]
    if ($extD -and $extD.VmsMissing -gt 0) {
        Write-Host "  ║       > $($extD.VmsMissing) VM(s) sem extensoes completas: re-executar com -Execute para instalar" -ForegroundColor Yellow
        Write-Host "  ║         Extensoes necessarias: AAD Login (registro AAD) + MDE (Defender for Servers)" -ForegroundColor DarkGray
    }
    Write-Host "  ║" -ForegroundColor DarkGray
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    return (Confirm-Action "Confirma geracao do relatorio HTML com todos os dados acima?" "S" "Gerar Relatorio HTML")
}

# ============================================================================
# EXECUCAO PRINCIPAL
# ============================================================================
Clear-Host
Show-MetasploitBanner

Write-Host "  [*] Informacoes da sessao:" -ForegroundColor White
Write-Host "      Data     : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Gray
Write-Host "      Host     : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "      Usuario  : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
Write-Host "      Script   : $($MyInvocation.MyCommand.Path)" -ForegroundColor Gray
Write-Host "      Modo     : $(if($script:IsReportOnly){'REPORT-ONLY (seguro)'}else{'EXECUTE (tags + groups + assign)'})" -ForegroundColor $(if($script:IsReportOnly){"Green"}else{"Yellow"})
Write-Host "      Propagacao: ${PropagationDelay}s entre operacoes" -ForegroundColor Gray
Write-Host ""

if (-not $script:IsReportOnly) {
    Write-Host "  ################################################################" -ForegroundColor Yellow
    Write-Host "  ##  MODO -Execute SELECIONADO                                 ##" -ForegroundColor Yellow
    Write-Host "  ##                                                            ##" -ForegroundColor Yellow
    Write-Host "  ##  Tags serao APLICADAS nos servidores do MDE                ##" -ForegroundColor Yellow
    Write-Host "  ##  Device Groups serao CRIADOS via Graph API                 ##" -ForegroundColor Yellow
    Write-Host "  ##  Maquinas serao ATRIBUIDAS aos grupos por subscription     ##" -ForegroundColor Yellow
    Write-Host "  ##                                                            ##" -ForegroundColor Yellow
    Write-Host "  ##  Cada acao pede confirmacao. Voce pode recusar qualquer    ##" -ForegroundColor Yellow
    Write-Host "  ##  etapa sem quebrar o script.                               ##" -ForegroundColor Yellow
    Write-Host "  ################################################################" -ForegroundColor Yellow
    if (-not (Confirm-Action "Deseja continuar em modo Execute?" "S" "Modo Execute")) {
        Write-Info "Alternando para REPORT-ONLY"
        $script:IsReportOnly = $true
    }
}

# --- ETAPA 0 ---
$null = Test-AndInstall-PowerShell7

# --- ETAPA 1 ---
$prereqOk = Test-Prerequisites
if (-not $prereqOk) {
    Write-Err "Pre-requisitos criticos nao atendidos."
    exit 1
}

# --- ETAPA 2 ---
$creds = Resolve-Credentials
if (-not $creds) {
    Write-Err "Credenciais nao disponiveis."
    Write-Host "  OPCOES:" -ForegroundColor Yellow
    Write-Host "  1. Execute Setup-MDE-ServerTags.ps1" -ForegroundColor White
    Write-Host "  2. Informe: .\TEST-Lab-E2E.ps1 -Report -AppSecret 'SECRET'" -ForegroundColor White
    exit 1
}

# --- ETAPA 3 ---
$authOk = Test-Authentication -Creds $creds
if (-not $authOk) {
    Write-Warn "Token MDE nao obtido. Classificacao e Device Groups terao funcionalidade limitada."
}

# --- ETAPA 4 ---
Get-AppRegistrationInfo -Creds $creds

# --- ETAPA 5 ---
Show-ConfigDetails

# --- ETAPA 6 ---
$null = Run-Classification -Creds $creds

# --- ETAPA 7 ---
Manage-DeviceGroups -Creds $creds

# --- ETAPA 8 ---
Test-VmExtensions -Creds $creds

# --- RESUMO TECNICO + CONFIRMACAO ---
$confirmReport = Show-TechnicalSummary
if ($confirmReport) {
    # --- ETAPA 9 ---
    $htmlPath = Generate-HtmlReport
} else {
    Write-Info "Geracao de relatorio HTML cancelada pelo usuario."
    Log-Action "Relatorio HTML" "IGNORADO" "Cancelado pelo usuario na confirmacao"
    $htmlPath = "(cancelado pelo usuario)"
}

# ============================================================================
# RESUMO FINAL
# ============================================================================
$totalDuration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
$modeLabel = if ($script:IsReportOnly) { "REPORT-ONLY" } else { "EXECUTE" }
$borderColor = if ($script:Errors.Count -eq 0) { "Green" } else { "Yellow" }
$dgCreated = @($script:DeviceGroupsCreated | Where-Object { $_.Status -eq "CRIADO" }).Count
$dgAssigned = ($script:DeviceGroupsCreated | Measure-Object -Property MembersAdded -Sum).Sum
if ($null -eq $dgAssigned) { $dgAssigned = 0 }

Write-Host ""
Write-Host ""
Write-Host "  +===================================================================+" -ForegroundColor $borderColor
Write-Host "  |                                                                   |" -ForegroundColor $borderColor
if ($script:Errors.Count -eq 0) {
    Write-Host "  |   VALIDACAO E2E CONCLUIDA COM SUCESSO                           |" -ForegroundColor Green
} else {
    Write-Host "  |   VALIDACAO E2E COM $($script:Errors.Count) ERRO(S)                                    |" -ForegroundColor Yellow
}
Write-Host "  |                                                                   |" -ForegroundColor $borderColor
Write-Host "  |  Modo           : $($modeLabel.PadRight(46))|" -ForegroundColor White
Write-Host "  |  Duracao        : $("${totalDuration}s".PadRight(46))|" -ForegroundColor White
Write-Host "  |  Servidores     : $("$($script:ServerCount) classificados".PadRight(46))|" -ForegroundColor Cyan
$dgSubCount = @($script:DeviceGroupsCreated | Where-Object { $_.Type -eq "Subscription" }).Count
Write-Host "  |  Sub Groups     : $("$dgSubCount subscription | $($dgCreated - $dgSubCount) lifecycle".PadRight(46))|" -ForegroundColor Cyan
Write-Host "  |  Device Groups  : $("$($script:DeviceGroupsCreated.Count) planejados | $dgCreated criados".PadRight(46))|" -ForegroundColor Cyan
Write-Host "  |  Maquinas       : $("$dgAssigned atribuidas a grupos".PadRight(46))|" -ForegroundColor Cyan
Write-Host "  |  Graph API      : $($(if($script:GraphTokenObtained){"ATIVO"}else{"N/A"}).PadRight(46))|" -ForegroundColor $(if($script:GraphTokenObtained){"Green"}else{"Yellow"})
$extFinal = $script:Results["Extensions"]
$extLine = if ($extFinal -and $extFinal.Status -eq "OK") { "$($extFinal.VmsOk)/$($extFinal.VmsChecked) VMs OK | $($extFinal.VmsMissing) faltando" } else { "N/A" }
Write-Host "  |  Extensoes VM   : $($extLine.PadRight(46))|" -ForegroundColor $(if($extFinal -and $extFinal.VmsMissing -gt 0){"Yellow"}else{"Green"})
Write-Host "  |  Erros          : $("$($script:Errors.Count)".PadRight(46))|" -ForegroundColor $(if($script:Errors.Count -eq 0){"Green"}else{"Red"})
Write-Host "  |  Avisos         : $("$($script:Warnings.Count)".PadRight(46))|" -ForegroundColor $(if($script:Warnings.Count -eq 0){"Green"}else{"Yellow"})
if ($script:SkippedActions.Count -gt 0) {
    Write-Host "  |  Ignoradas      : $("$($script:SkippedActions.Count) acoes".PadRight(46))|" -ForegroundColor DarkGray
}
$rpDisplay = if ($htmlPath.Length -gt 44) { "..." + $htmlPath.Substring($htmlPath.Length - 41) } else { $htmlPath }
Write-Host "  |  Relatorio      : $($rpDisplay.PadRight(46))|" -ForegroundColor Gray
Write-Host "  |                                                                   |" -ForegroundColor $borderColor
Write-Host "  |  Rafael França — MDE ServerTags Community Edition               |" -ForegroundColor DarkGray
Write-Host "  +===================================================================+" -ForegroundColor $borderColor
Write-Host ""

if ($script:Errors.Count -gt 0) {
    Write-Host "  Erros:" -ForegroundColor Red
    foreach ($e in $script:Errors) { Write-Host "    x $e" -ForegroundColor Red }
    Write-Host ""
}

if ($script:SkippedActions.Count -gt 0) {
    Write-Host "  Acoes ignoradas:" -ForegroundColor DarkGray
    foreach ($s in $script:SkippedActions) { Write-Host "    - $s" -ForegroundColor DarkGray }
    Write-Host ""
}

if ($script:IsReportOnly -and $script:ServerCount -gt 0) {
    Write-Host "  PROXIMO PASSO: .\TEST-Lab-E2E.ps1 -Execute" -ForegroundColor Cyan
    Write-Host "  (tags + Device Groups via Graph + atribuicao de maquinas)" -ForegroundColor DarkGray
    Write-Host ""
}

exit $(if ($script:Errors.Count -eq 0) { 0 } else { 1 })
