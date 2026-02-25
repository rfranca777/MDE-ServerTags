<#
.SYNOPSIS
    Sync-MDE-ServerTags-BySubscription.ps1 v2.2.0
    UMA tag por servidor. Simples, lógico, limpo. Auto-descoberta de subscriptions.

.DESCRIPTION
    OBJETIVO: Cada servidor no MDE recebe EXATAMENTE UMA tag gerenciada por este script.
    Essa tag permite criar Device Groups dinâmicos para aplicação de políticas.

    ESCOPO: Apenas servidores — Windows Server + Linux (Azure VMs ou Azure Arc).
    Workstations (Windows 10/11), mobile e IoT são ignorados.

    ════════════════════════════════════════════════════════════
    LÓGICA DE DECISÃO (por prioridade, a primeira que bater ganha):
    ════════════════════════════════════════════════════════════

    Prioridade 1 — DUPLICADA_EXCLUIR
      Mesmo hostname com múltiplos machineId → o mais antigo ganha esta tag.
      É lixo do MDE (re-onboarding, reimagem de SO). Candidato a offboard/delete.

    Prioridade 2 — EFEMERO
      Máquina que nasceu e morreu no mesmo dia ou no dia seguinte.
      firstSeen e lastSeen com diferença ≤ 48h E status Inactive/NoSensorData.
      Típico de VMSS scale-in, CI/CD runners, containers.
      ** v2.1: Se o VM ainda existir na Azure (resourceId com subscription mapeada),
         NÃO recebe EFEMERO — recebe a tag da subscription. **

    Prioridade 3 — INATIVO_40D
      Sem comunicação há mais de 40 dias. Provavelmente decommissionado.
      Candidato a offboard. Investigar antes de excluir.

    Prioridade 4 — INATIVO_7D
      Sem comunicação entre 7 e 40 dias. Pode ser manutenção, férias, etc.
      Monitorar — se persistir, escala para INATIVO_40D no próximo run.

    Prioridade 5 — {SUBSCRIPTION_NAME}
      Servidor ativo (reportou nos últimos 7 dias) COM subscription mapeada.
      Esta é a tag principal. Permite segmentar Device Groups por subscription.

    Fallback — Sem tag gerenciada
      Servidor ativo sem subscription (on-prem sem Arc). Script não toca.

    ════════════════════════════════════════════════════════════
    DEVICE GROUPS SUGERIDOS (criados manualmente no portal):
    ════════════════════════════════════════════════════════════

    | Device Group              | Tag                    | Automation Level       |
    |---------------------------|------------------------|------------------------|
    | Servers-{Subscription}    | {SUBSCRIPTION_NAME}    | Full / Semi-automated  |
    | Servers-Inativos-7d       | INATIVO_7D             | Semi-automated         |
    | Servers-Inativos-40d      | INATIVO_40D            | No automated response  |
    | Servers-Efemeros          | EFEMERO                | No automated response  |
    | Servers-Duplicadas        | DUPLICADA_EXCLUIR      | No automated response  |

    ════════════════════════════════════════════════════════════
    GARANTIA: UMA ÚNICA TAG GERENCIADA POR DISPOSITIVO
    ════════════════════════════════════════════════════════════
    Quando o script aplica uma tag, REMOVE todas as outras tags gerenciadas.
    Tags NÃO gerenciadas (criadas manualmente, por GPO, ou outros scripts)
    são preservadas — o script NUNCA remove tags que ele não conhece.

.PARAMETER tenantId
    Azure Tenant ID.
.PARAMETER appId
    Client ID do App Registration com Machine.ReadWrite.All.
.PARAMETER appSecret
    Client Secret do App Registration.
.PARAMETER subscriptionMappingPath
    CSV com mapeamento subscriptionId;subscriptionName. OPCIONAL quando autoDiscoverSubscriptions=$true.
    Default: .\subscription_mapping.csv
.PARAMETER autoDiscoverSubscriptions
    $true = descobre subscriptions automaticamente sem CSV. Ordem: (1) CSV se existir, (2) ARM API,
    (3) Azure CLI, (4) metadados dos devices MDE. $false = exige CSV. Default: $true.
.PARAMETER saveDiscoveredCsv
    $true = salva subscription_mapping.csv após descoberta automática (auditoria/revisão).
    Default: $true.
.PARAMETER excludeSubscriptions
    Lista de subscriptionIds a ignorar. Ex: @('sub-id-teste','sub-id-lab'). Default: @().
.PARAMETER reportOnly
    $true = apenas relatório. $false = aplica tags. Default: $true (seguro).

.EXAMPLE
    # Auto-descoberta completa — não precisa de CSV (padrão recomendado)
    .\Sync-MDE-ServerTags-BySubscription.ps1 -tenantId "..." -appId "..." -appSecret "..."

.EXAMPLE
    # Aplicar tags com auto-descoberta
    .\Sync-MDE-ServerTags-BySubscription.ps1 -tenantId "..." -appId "..." -appSecret "..." -reportOnly $false

.EXAMPLE
    # Forçar CSV manual (desabilitar auto-descoberta)
    .\Sync-MDE-ServerTags-BySubscription.ps1 -tenantId "..." -appId "..." -appSecret "..." `
        -autoDiscoverSubscriptions $false -subscriptionMappingPath "C:\mapeamento.csv"

.NOTES
    Versão:  2.2.0
    Data:    2026-02-19
    Requer:  App Registration com Machine.ReadWrite.All (obrigatório)
             Reader nas subscriptions Azure: opcional — melhora nomes das tags via ARM API
             Azure CLI (az login): opcional — descoberta alternativa de subscriptions
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$tenantId,

    [Parameter(Mandatory = $true)]
    [string]$appId,

    [Parameter(Mandatory = $true)]
    [string]$appSecret,

    [Parameter(Mandatory = $false)]
    [string]$subscriptionMappingPath = ".\subscription_mapping.csv",

    [Parameter(Mandatory = $false)]
    [bool]$autoDiscoverSubscriptions = $true,

    [Parameter(Mandatory = $false)]
    [bool]$saveDiscoveredCsv = $true,

    [Parameter(Mandatory = $false)]
    [string[]]$excludeSubscriptions = @(),

    [Parameter(Mandatory = $false)]
    [bool]$reportOnly = $true
)

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================
$ErrorActionPreference = "Continue"
$script:Version = "2.2.0"
$script:RunDate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$script:ReportPath = ".\ServerTags-Report-$($script:RunDate).csv"
$script:LogPath = ".\ServerTags-Log-$($script:RunDate).log"

# Tags gerenciadas por este script (TODAS que o script pode aplicar/remover)
$script:MANAGED_TAGS = [System.Collections.Generic.List[string]]::new()
$script:MANAGED_TAGS.Add("DUPLICADA_EXCLUIR")
$script:MANAGED_TAGS.Add("EFEMERO")
$script:MANAGED_TAGS.Add("INATIVO_40D")
$script:MANAGED_TAGS.Add("INATIVO_7D")
# + tags de subscription são adicionadas dinamicamente em Get-SubscriptionMap

# Tags da versão anterior que devemos limpar (migração v1→v2)
$script:LEGACY_TAGS = @(
    "DUPLICATED",
    "EPHEMERAL_INACTIVE",
    "NO_SUBSCRIPTION",
    "IMPAIRED_COMMUNICATION",
    "REVIEW_NEEDED"
)

# Contadores de API
$script:ApiCalls = 0
$script:ApiErrors = 0

# Tokens (MDE + ARM para descoberta de subscriptions)
$script:Token = $null
$script:TokenExpiry = [datetime]::MinValue
$script:ArmToken = $null
$script:ArmTokenExpiry = [datetime]::MinValue
$script:ArmTokenFailed = $false      # true após falha de ARM Token (evita re-tentativas)
$script:SubscriptionSource = "N/A"   # rastreia origem do mapeamento para logs/relatório

# ============================================================================
# LOG
# ============================================================================
function Write-Log {
    param ([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Msg"
    Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "INFO"  { Write-Host $line -ForegroundColor Cyan }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "OK"    { Write-Host $line -ForegroundColor Green }
        "DEBUG" { Write-Host $line -ForegroundColor Gray }
        default { Write-Host $line }
    }
}

# ============================================================================
# AUTH — OAuth2 client_credentials
# ============================================================================
function Get-Token {
    if ($script:Token -and (Get-Date) -lt $script:TokenExpiry) { return $script:Token }

    $body = @{
        client_id     = $appId
        client_secret = $appSecret
        grant_type    = "client_credentials"
        scope         = "https://api.securitycenter.microsoft.com/.default"
    }
    try {
        $r = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
            -Body $body -ContentType "application/x-www-form-urlencoded"
        $script:Token = $r.access_token
        $script:TokenExpiry = (Get-Date).AddSeconds($r.expires_in - 120)
        Write-Log "Token obtido. Expira em $([math]::Round($r.expires_in / 60)) min" -Level OK
        return $script:Token
    }
    catch {
        Write-Log "FALHA auth: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# ============================================================================
# AUTH — Token ARM (Azure Resource Manager) — usado na descoberta de subscriptions
# Mesmo App Registration, escopo diferente: management.azure.com
# Requer: App Reg com Reader role nas subscriptions (opcional — falha graciosamente)
# ============================================================================
function Get-ArmToken {
    if ($script:ArmTokenFailed) { return $null }
    if ($script:ArmToken -and (Get-Date) -lt $script:ArmTokenExpiry) { return $script:ArmToken }

    $body = @{
        client_id     = $appId
        client_secret = $appSecret
        grant_type    = "client_credentials"
        scope         = "https://management.azure.com/.default"
    }
    try {
        $r = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
            -Body $body -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        $script:ArmToken = $r.access_token
        $script:ArmTokenExpiry = (Get-Date).AddSeconds($r.expires_in - 120)
        Write-Log "ARM Token obtido (validade: $([math]::Round($r.expires_in/60)) min)" -Level OK
        return $script:ArmToken
    }
    catch {
        $script:ArmTokenFailed = $true
        Write-Log "ARM Token: n\u00e3o dispon\u00edvel (App Reg sem Reader nas subs?): $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ============================================================================
# API — chamada genérica com paginação + retry (401 refresh, 429 backoff)
# ============================================================================
function Call-MdeApi {
    param (
        [string]$Uri,
        [string]$Method = "Get",
        [string]$Body = $null
    )

    $all = @()
    $url = $Uri
    $retries = 0
    $maxRetries = 3

    do {
        $headers = @{
            Authorization  = "Bearer $(Get-Token)"
            "Content-Type" = "application/json"
        }
        try {
            $params = @{
                Uri         = $url
                Headers     = $headers
                Method      = $Method
                ErrorAction = "Stop"
            }
            if ($Body) { $params.Body = $Body }

            Write-Log "API $Method $url" -Level DEBUG
            $resp = Invoke-RestMethod @params
            $script:ApiCalls++
            $retries = 0

            if ($resp.value) { $all += $resp.value }
            else { $all += $resp }

            $url = $resp.'@odata.nextLink'
        }
        catch {
            $script:ApiErrors++
            $code = 0
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $code = [int]$_.Exception.Response.StatusCode
            }

            if ($code -eq 401 -and $retries -lt $maxRetries) {
                Write-Log "401 — renovando token (tentativa $($retries+1))..." -Level WARN
                $script:Token = $null
                $retries++
                continue
            }
            elseif ($code -eq 429 -and $retries -lt $maxRetries) {
                $wait = 180
                Write-Log "429 — rate limit. Aguardando ${wait}s (tentativa $($retries+1))..." -Level WARN
                Start-Sleep $wait
                $retries++
                continue
            }
            else {
                Write-Log "API Error ($code): $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    } while ($url)

    return $all
}

# ============================================================================
# SANITIZAR nome de subscription → tag MDE válida
# ============================================================================
function ConvertTo-TagName {
    param ([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "UNKNOWN" }
    # Maiúsculo, remove caracteres inválidos, spaces→underscore
    $tag = $Name.ToUpper() -replace '[^A-Z0-9\-_\s]', '' -replace '\s+', '_' -replace '[-_]{2,}', '_'
    $tag = $tag.Trim('_', '-')
    if ($tag.Length -gt 200) { $tag = $tag.Substring(0, 200) }
    if ([string]::IsNullOrWhiteSpace($tag)) { return "UNKNOWN" }
    return $tag
}

# ============================================================================
# DESCOBERTA N\u00cdVEL 2 — Azure Resource Manager API
# Requer: App Registration com Reader role nas subscriptions Azure.
# Se n\u00e3o tiver Reader, retorna $null graciosamente (sem lan\u00e7ar exce\u00e7\u00e3o).
# ============================================================================
function Get-SubscriptionsFromArm {
    $token = Get-ArmToken
    if (-not $token) { return $null }

    try {
        $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
        $resp = Invoke-RestMethod `
            -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
            -Headers $headers -Method Get -ErrorAction Stop

        $subs = @($resp.value | Where-Object { $_.state -eq 'Enabled' })
        if ($subs.Count -eq 0) {
            Write-Log "ARM: Nenhuma subscription habilitada encontrada" -Level WARN
            return $null
        }
        Write-Log "ARM: $($subs.Count) subscription(s) habilitada(s) encontrada(s)" -Level OK
        return $subs | ForEach-Object {
            [PSCustomObject]@{ subscriptionId = $_.subscriptionId; subscriptionName = $_.displayName }
        }
    }
    catch {
        $code = 0
        if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
        $hint = if ($code -eq 403) { " \u2014 App Registration precisa de Reader role nas subscriptions" } else { "" }
        Write-Log "ARM: Erro HTTP $code$hint \u2014 $($_.Exception.Message)" -Level WARN
        $script:ArmTokenFailed = $true   # n\u00e3o tentar ARM novamente nesta execu\u00e7\u00e3o
        return $null
    }
}

# ============================================================================
# DESCOBERTA N\u00cdVEL 3 — Azure CLI
# Requer: az CLI instalado e 'az login' executado no servidor.
# Retorna $null graciosamente se CLI n\u00e3o estiver dispon\u00edvel ou autenticado.
# ============================================================================
function Get-SubscriptionsFromAzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Log "AzCLI: az n\u00e3o encontrado no PATH" -Level WARN
        return $null
    }
    try {
        # 2>$null descarta stderr; $LASTEXITCODE indica sucesso/falha
        $json = & az account list `
            --query "[?state=='Enabled'].{subscriptionId:id,subscriptionName:name}" `
            --output json 2>$null

        if ($LASTEXITCODE -ne 0) {
            Write-Log "AzCLI: exit $LASTEXITCODE \u2014 execute 'az login' no servidor" -Level WARN
            return $null
        }
        $subs = $json | ConvertFrom-Json
        if (-not $subs -or $subs.Count -eq 0) {
            Write-Log "AzCLI: Nenhuma subscription retornada" -Level WARN
            return $null
        }
        Write-Log "AzCLI: $($subs.Count) subscription(s) encontrada(s)" -Level OK
        return $subs
    }
    catch {
        Write-Log "AzCLI: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ============================================================================
# DESCOBERTA N\u00cdVEL 4 — Metadados dos devices MDE (sem permiss\u00f5es adicionais)
# Extrai subscriptionIds j\u00e1 presentes em vmMetadata.resourceId dos pr\u00f3prios devices.
# Executado no MAIN ap\u00f3s buscar a lista completa de devices.
# Tenta enriquecer nomes via ARM API se ainda n\u00e3o falhou nesta execu\u00e7\u00e3o.
# ============================================================================
function Build-SubscriptionMapFromDevices {
    param ([array]$Devices)

    # Extrair subscriptionIds \u00fanicas dos metadados de vmMetadata
    $subIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($dev in $Devices) {
        $id = $null
        if ($dev.vmMetadata -and $dev.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
            $id = $Matches[1].ToLower()
        }
        elseif ($dev.vmMetadata -and -not [string]::IsNullOrWhiteSpace($dev.vmMetadata.subscriptionId)) {
            $id = $dev.vmMetadata.subscriptionId.ToLower()
        }
        if ($id) { $null = $subIds.Add($id) }
    }

    if ($subIds.Count -eq 0) {
        Write-Log "MDE-Metadata: Nenhuma subscriptionId encontrada nos metadados dos devices" -Level WARN
        return $null
    }
    Write-Log "MDE-Metadata: $($subIds.Count) subscriptionId(s) extra\u00edda(s) dos devices" -Level OK

    # Tentar enriquecer nomes via ARM (se ainda n\u00e3o falhou)
    $nameMap = @{}
    if (-not $script:ArmTokenFailed) {
        $armSubs = Get-SubscriptionsFromArm
        if ($armSubs) {
            foreach ($s in $armSubs) { $nameMap[$s.subscriptionId.ToLower()] = $s.subscriptionName }
            Write-Log "MDE-Metadata: Nomes enriquecidos via ARM API" -Level OK
        }
    }

    # Construir mapa + lista para CSV
    $map = @{}
    $csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $excludeLower = @($excludeSubscriptions | Where-Object { $_ } | ForEach-Object { $_.ToLower() })

    foreach ($id in $subIds) {
        if ($excludeLower -and $id -in $excludeLower) {
            Write-Log "  Sub: $id ignorada (lista de exclus\u00e3o)" -Level DEBUG
            continue
        }
        $name = if ($nameMap.ContainsKey($id)) { $nameMap[$id] } else { $id }
        $tag = ConvertTo-TagName -Name $name
        $map[$id] = @{ Name = $name; Tag = $tag }
        if ($tag -notin $script:MANAGED_TAGS) { $script:MANAGED_TAGS.Add($tag) }
        Write-Log "  Sub: $id \u2192 Tag '$tag' (MDE-Metadata)" -Level DEBUG
        $csvRows.Add([PSCustomObject]@{ subscriptionId = $id; subscriptionName = $name })
    }

    $script:SubscriptionSource = "MDE-Metadata"
    Write-Log "MDE-Metadata: $($map.Count) subscription(s) mapeada(s)" -Level OK

    # Salvar CSV para auditoria e r\u00e1pido reaproveitamento no pr\u00f3ximo run
    if ($saveDiscoveredCsv -and $csvRows.Count -gt 0) {
        try {
            $csvRows | Export-Csv -Path $subscriptionMappingPath `
                -NoTypeInformation -Delimiter ';' -Encoding UTF8
            Write-Log "CSV salvo (MDE-Metadata): $subscriptionMappingPath" -Level OK
        }
        catch {
            Write-Log "Aviso: N\u00e3o foi poss\u00edvel salvar CSV: $($_.Exception.Message)" -Level WARN
        }
    }

    return $map
}

# ============================================================================
# CARREGAR/DESCOBRIR SUBSCRIPTIONS
# Prioridade: (1) CSV existente \u2192 (2) ARM API \u2192 (3) Azure CLI \u2192 (4) Metadados MDE*
# * N\u00edvel 4 requer a lista de devices \u2014 executado no MAIN ap\u00f3s busca dos devices.
#   Retorna $null como sinal para o MAIN executar Build-SubscriptionMapFromDevices.
# ============================================================================
function Get-SubscriptionMap {
    $rawSubs = $null
    $excludeLower = @($excludeSubscriptions | Where-Object { $_ } | ForEach-Object { $_.ToLower() })

    # \u2500\u2500 N\u00edvel 1: CSV (se existir e caminho v\u00e1lido) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    if (-not [string]::IsNullOrWhiteSpace($subscriptionMappingPath) -and (Test-Path $subscriptionMappingPath)) {
        Write-Log "N\u00edvel 1 \u2014 CSV encontrado: $subscriptionMappingPath" -Level OK
        $rawSubs = Get-Content $subscriptionMappingPath -Raw | ConvertFrom-Csv -Delimiter ';'
        $script:SubscriptionSource = "CSV"
    }
    elseif ($autoDiscoverSubscriptions) {
        Write-Log "CSV n\u00e3o encontrado \u2014 iniciando descoberta autom\u00e1tica..." -Level WARN

        # \u2500\u2500 N\u00edvel 2: Azure Resource Manager API \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        Write-Log "N\u00edvel 2 \u2014 Azure Resource Manager API..." -Level INFO
        $rawSubs = Get-SubscriptionsFromArm
        if ($rawSubs) { $script:SubscriptionSource = "ARM API" }

        # \u2500\u2500 N\u00edvel 3: Azure CLI \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (-not $rawSubs) {
            Write-Log "N\u00edvel 3 \u2014 Azure CLI..." -Level INFO
            $rawSubs = Get-SubscriptionsFromAzCli
            if ($rawSubs) { $script:SubscriptionSource = "Azure CLI" }
        }

        # \u2500\u2500 N\u00edvel 4: Metadados MDE (executado no MAIN ap\u00f3s buscar devices) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if (-not $rawSubs) {
            Write-Log "N\u00edvel 4 \u2014 Descoberta via metadados MDE ser\u00e1 feita ap\u00f3s buscar devices." -Level WARN
            return $null  # sinal para o MAIN chamar Build-SubscriptionMapFromDevices
        }

        # Salvar CSV para auditoria e reaproveitamento nos pr\u00f3ximos runs
        if ($saveDiscoveredCsv) {
            try {
                $rawSubs |
                    Select-Object @{N='subscriptionId';   E={$_.subscriptionId}},
                                  @{N='subscriptionName'; E={$_.subscriptionName}} |
                    Export-Csv -Path $subscriptionMappingPath `
                        -NoTypeInformation -Delimiter ';' -Encoding UTF8
                Write-Log "CSV salvo automaticamente: $subscriptionMappingPath (fonte: $($script:SubscriptionSource))" -Level OK
            }
            catch {
                Write-Log "Aviso: N\u00e3o foi poss\u00edvel salvar CSV: $($_.Exception.Message)" -Level WARN
            }
        }
    }
    else {
        # autoDiscoverSubscriptions=$false e CSV n\u00e3o existe \u2014 erro expl\u00edcito
        Write-Log "CSV n\u00e3o encontrado: $subscriptionMappingPath" -Level ERROR
        throw "Mapeamento n\u00e3o encontrado: '$subscriptionMappingPath'`nCrie o arquivo CSV ou use: -autoDiscoverSubscriptions `$true"
    }

    # \u2500\u2500 Construir hashtable de mapeamento \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    $map = @{}
    foreach ($row in $rawSubs) {
        $id   = if ($row.PSObject.Properties['subscriptionId'])   { ($row.subscriptionId   + '').Trim().ToLower() } else { $null }
        $name = if ($row.PSObject.Properties['subscriptionName']) { ($row.subscriptionName + '').Trim() }           else { $null }

        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        # Aplicar lista de exclus\u00e3o
        if ($excludeLower -and $id -in $excludeLower) {
            Write-Log "  Sub: $id ignorada (lista de exclus\u00e3o)" -Level DEBUG
            continue
        }

        if ([string]::IsNullOrWhiteSpace($name)) { $name = $id }

        $tag = ConvertTo-TagName -Name $name
        $map[$id] = @{ Name = $name; Tag = $tag }
        if ($tag -notin $script:MANAGED_TAGS) { $script:MANAGED_TAGS.Add($tag) }
        Write-Log "  Sub: $id \u2192 Tag '$tag' ($($script:SubscriptionSource))" -Level DEBUG
    }

    Write-Log "Subscriptions carregadas: $($map.Count) (fonte: $($script:SubscriptionSource))" -Level OK
    return $map
}

# ============================================================================
# FILTRAR SERVIDORES — Windows Server + Linux (Azure / Arc only)
# ============================================================================
function Get-Servers {
    param ([array]$AllDevices)

    # Distros Linux conhecidas pelo MDE
    $linuxDistros = @(
        "Ubuntu", "RedHatEnterpriseLinux", "SuseLinuxEnterpriseServer",
        "OracleLinux", "CentOS", "Debian", "Fedora", "Linux",
        "AmazonLinux", "Mariner", "AlmaLinux", "RockyLinux"
    )

    $servers = $AllDevices | Where-Object {
        $isServer = $false

        # Windows Server (qualquer edição)
        if ($_.osPlatform -like "*Server*") {
            $isServer = $true
        }

        # Linux — MDE retorna nome da distro, não "Linux" genérico
        if ($_.osPlatform -in $linuxDistros -or
            $_.osPlatform -match '(?i)Linux|Ubuntu|RedHat|SUSE|CentOS|Debian|Oracle|Fedora|Mariner|Alma|Rocky') {
            $isServer = $true
        }

        # Hostname válido
        if ([string]::IsNullOrWhiteSpace($_.computerDnsName) -or $_.computerDnsName.Length -lt 3) {
            $isServer = $false
        }

        $isServer
    }

    Write-Log "Servidores filtrados: $($servers.Count) de $($AllDevices.Count) dispositivos totais" -Level OK
    return $servers
}

# ============================================================================
# PARSE de data — InvariantCulture (funciona em qualquer locale)
# ============================================================================
function Parse-MdeDate {
    param ([string]$DateStr)
    if ([string]::IsNullOrWhiteSpace($DateStr)) { return [datetime]::MinValue }
    try {
        return [datetime]::Parse($DateStr, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { return [datetime]::MinValue }
}

# ============================================================================
# CLASSIFICAR CADA SERVIDOR — lógica de decisão central
# ============================================================================
function Get-ServerClassification {
    param (
        [array]$Servers,
        [hashtable]$SubMap
    )

    $now = Get-Date

    # ── Passo 1: Detectar duplicatas ──
    # Agrupar por hostname normalizado (case-insensitive, sem FQDN suffix para comparação)
    $groups = $Servers | Group-Object { $_.computerDnsName.ToLower() }
    $duplicateIds = @{} # machineId → $true (os que devem receber DUPLICADA_EXCLUIR)

    foreach ($g in $groups) {
        if ($g.Count -le 1) { continue }

        # VMSS pattern — hostname termina em _0, _1, _000000, etc: instâncias legítimas
        if ($g.Name -match '_\d+$|\d{6}$|(?i)vmss|scaleset') {
            Write-Log "VMSS detectado: '$($g.Name)' ($($g.Count) instâncias) — mantendo todas" -Level WARN
            continue
        }

        # Ordenar por lastSeen descending → o primeiro (mais recente) é o válido
        $sorted = $g.Group | Sort-Object { Parse-MdeDate $_.lastSeen } -Descending
        for ($i = 1; $i -lt $sorted.Count; $i++) {
            $duplicateIds[$sorted[$i].id] = $true
        }
        Write-Log "Duplicata: '$($g.Name)' — mantendo ID $($sorted[0].id), marcando $($g.Count - 1) como DUPLICADA_EXCLUIR" -Level WARN
    }
    Write-Log "Total duplicatas detectadas: $($duplicateIds.Count)" -Level INFO

    # ── Passo 2: Classificar cada servidor ──
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($srv in $Servers) {
        $lastSeen  = Parse-MdeDate $srv.lastSeen
        $firstSeen = Parse-MdeDate $srv.firstSeen
        $daysInactive = if ($lastSeen -gt [datetime]::MinValue) { ($now - $lastSeen).TotalDays } else { 999 }
        $lifespanHours = if ($firstSeen -gt [datetime]::MinValue -and $lastSeen -gt [datetime]::MinValue) {
            ($lastSeen - $firstSeen).TotalHours
        } else { 999 }

        # Determinar a tag (por prioridade — primeira match ganha)
        $tag = $null
        $subId = $null
        $action = "SKIP"
        $reason = ""

        # ────── P1: Duplicata ──────
        if ($duplicateIds.ContainsKey($srv.id)) {
            $tag = "DUPLICADA_EXCLUIR"
            $action = "TAG"
            $reason = "Hostname duplicado — registro mais antigo (lastSeen: $($srv.lastSeen))"
        }
        # ────── P2: Efêmero (≤48h de vida E inativo) ──────
        # REGRA v2.1: Se o VM ainda existe na Azure (tem resourceId com subscription
        # mapeada), NÃO é efêmero — recebe a tag da subscription.
        # Só marca EFEMERO se realmente não tem vínculo Azure ativo.
        elseif ($lifespanHours -le 48 -and $srv.healthStatus -in @("Inactive", "NoSensorData") -and $daysInactive -gt 1) {
            # Verificar se o VM existe na Azure (resourceId com subscription mapeada)
            $ephSubId = $null
            if ($srv.vmMetadata -and $srv.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
                $ephSubId = $Matches[1].ToLower()
            }
            elseif ($srv.vmMetadata -and -not [string]::IsNullOrWhiteSpace($srv.vmMetadata.subscriptionId)) {
                $ephSubId = $srv.vmMetadata.subscriptionId.ToLower()
            }

            if ($ephSubId -and $SubMap.ContainsKey($ephSubId)) {
                # VM existe na Azure com subscription mapeada → manter com tag da subscription
                $tag = $SubMap[$ephSubId].Tag
                $subId = $ephSubId
                $action = "TAG"
                $reason = "Efêmero reclassificado — VM existe na Azure (Sub: $($SubMap[$ephSubId].Name)), viveu $([math]::Round($lifespanHours,1))h"
            }
            else {
                $tag = "EFEMERO"
                $action = "TAG"
                $reason = "Máquina efêmera — viveu $([math]::Round($lifespanHours,1))h, sem vínculo Azure ativo, first=$($srv.firstSeen), last=$($srv.lastSeen)"
            }
        }
        # ────── P3: Inativo >40 dias ──────
        elseif ($daysInactive -gt 40) {
            $tag = "INATIVO_40D"
            $action = "TAG"
            $reason = "Sem comunicação há $([math]::Round($daysInactive,0)) dias"
        }
        # ────── P4: Inativo 7-40 dias ──────
        elseif ($daysInactive -gt 7) {
            $tag = "INATIVO_7D"
            $action = "TAG"
            $reason = "Sem comunicação há $([math]::Round($daysInactive,0)) dias"
        }
        # ────── P5: Ativo COM subscription mapeada ──────
        else {
            # Extrair subscriptionId de vmMetadata.resourceId (fonte confiável)
            # vmMetadata.subscriptionId é frequentemente null, mas resourceId sempre contém
            $subId = $null
            if ($srv.vmMetadata -and $srv.vmMetadata.resourceId -match '/subscriptions/([0-9a-f\-]{36})/') {
                $subId = $Matches[1].ToLower()
            }
            elseif ($srv.vmMetadata -and -not [string]::IsNullOrWhiteSpace($srv.vmMetadata.subscriptionId)) {
                $subId = $srv.vmMetadata.subscriptionId.ToLower()
            }

            if ($subId -and $SubMap.ContainsKey($subId)) {
                $tag = $SubMap[$subId].Tag
                $action = "TAG"
                $reason = "Subscription: $($SubMap[$subId].Name)"
            }
            elseif ($subId) {
                $action = "SKIP"
                $reason = "Subscription '$subId' não mapeada no CSV — ignorado"
            }
            else {
                $action = "SKIP"
                $reason = "Ativo sem subscription Azure (on-prem sem Arc?)"
            }
        }

        # ── Verificar tags atuais ──
        $currentTags = @()
        if ($srv.machineTags) { $currentTags = @($srv.machineTags) }

        # Tags gerenciadas + legadas que estão no dispositivo (candidatas a remoção)
        $allKnownTags = @($script:MANAGED_TAGS) + $script:LEGACY_TAGS
        $currentManagedTags = @($currentTags | Where-Object { $_ -in $allKnownTags })
        $tagsToRemove = @($currentManagedTags | Where-Object { $_ -ne $tag })
        $needsAdd = ($tag -and ($tag -notin $currentTags))
        $needsRemove = ($tagsToRemove.Count -gt 0)

        # Se já tem a tag correta e não tem lixo, marcar OK
        if (-not $needsAdd -and -not $needsRemove -and $tag) {
            $action = "OK"
            $reason = "Tag '$tag' já correta"
        }
        # SKIP mas com tags velhas para limpar → CLEAN
        elseif ($action -eq "SKIP" -and $needsRemove) {
            $action = "CLEAN"
            $reason = "$reason — limpando tags legadas: $($tagsToRemove -join ', ')"
        }

        $results.Add([PSCustomObject]@{
            MachineId       = $srv.id
            ComputerDnsName = $srv.computerDnsName
            OsPlatform      = $srv.osPlatform
            HealthStatus    = $srv.healthStatus
            FirstSeen       = $srv.firstSeen
            LastSeen        = $srv.lastSeen
            DaysInactive    = [math]::Round($daysInactive, 0)
            LifespanHours   = [math]::Round($lifespanHours, 1)
            SubscriptionId  = if ($subId) { $subId } else { "" }
            CurrentTags     = ($currentTags -join ", ")
            TargetTag       = if ($tag) { $tag } else { "" }
            TagsToRemove    = ($tagsToRemove -join ", ")
            NeedsAdd        = $needsAdd
            NeedsRemove     = $needsRemove
            Action          = $action
            Reason          = $reason
        })
    }

    # Resumo
    $actionCounts = $results | Group-Object Action
    $tagCount   = @($results | Where-Object Action -eq "TAG").Count
    $okCount    = @($results | Where-Object Action -eq "OK").Count
    $cleanCount = @($results | Where-Object Action -eq "CLEAN").Count
    $skipCount  = @($results | Where-Object Action -eq "SKIP").Count
    Write-Log "Classificação: TAG=$tagCount | OK=$okCount | CLEAN=$cleanCount | SKIP=$skipCount" -Level OK

    return $results
}

# ============================================================================
# APLICAR TAGS — Fase 1: Remove → Fase 2: Add (bulk API, 25/chamada)
# ============================================================================
function Set-Tags {
    param ([System.Collections.Generic.List[PSCustomObject]]$Results)

    if ($reportOnly) {
        Write-Log "═══ REPORT-ONLY — nenhuma tag será alterada ═══" -Level WARN
        return @{ Added = 0; Removed = 0; Errors = 0 }
    }

    Write-Log "═══ APLICANDO TAGS (EXECUÇÃO REAL) ═══" -Level WARN

    # Coletar remoções e adições
    $removals = @{}  # tag → @(machineIds)
    $additions = @{} # tag → @(machineIds)

    foreach ($r in $Results) {
        if ($r.Action -notin @("TAG", "CLEAN")) { continue }

        # Remoções — tags gerenciadas/legadas que não são a target
        if ($r.NeedsRemove -and $r.TagsToRemove) {
            foreach ($old in ($r.TagsToRemove -split ',\s*' | Where-Object { $_ })) {
                if (-not $removals.ContainsKey($old)) { $removals[$old] = @() }
                $removals[$old] += $r.MachineId
            }
        }

        # Adição (só para TAG, não CLEAN)
        if ($r.Action -eq "TAG" -and $r.NeedsAdd -and $r.TargetTag) {
            if (-not $additions.ContainsKey($r.TargetTag)) { $additions[$r.TargetTag] = @() }
            $additions[$r.TargetTag] += $r.MachineId
        }
    }

    $totalRemoved = 0
    $totalAdded = 0
    $errors = 0
    $bulkUri = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"

    # ── FASE 1: Remover tags antigas ──
    $useFallback = $false
    if ($removals.Count -gt 0) {
        Write-Log "── FASE 1: Remoção de tags ──" -Level INFO
        foreach ($tag in $removals.Keys) {
            $ids = @($removals[$tag])
            Write-Log "Removendo '$tag' de $($ids.Count) dispositivos..." -Level INFO
            if (-not $useFallback) {
                # Tentar bulk API primeiro
                for ($i = 0; $i -lt $ids.Count; $i += 25) {
                    $end = [Math]::Min($i + 24, $ids.Count - 1)
                    $chunk = @($ids[$i..$end])
                    $body = @{
                        Value      = $tag
                        Action     = "Remove"
                        MachineIds = $chunk
                    } | ConvertTo-Json -Depth 3

                    try {
                        $null = Call-MdeApi -Uri $bulkUri -Method Post -Body $body
                        $totalRemoved += $chunk.Count
                        Write-Log "  ✓ Removido '$tag' de $($chunk.Count) (lote $([Math]::Floor($i/25)+1))" -Level OK
                    }
                    catch {
                        if ($_.Exception.Message -match '403|Forbidden') {
                            Write-Log "  Bulk API indisponível (403). Usando endpoint individual..." -Level WARN
                            $useFallback = $true
                            # Processar este chunk e o restante via fallback
                            foreach ($mid in $chunk) {
                                try {
                                    $singleBody = @{ Value = $tag; Action = "Remove" } | ConvertTo-Json
                                    $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body $singleBody
                                    $totalRemoved++
                                } catch { $errors++; Write-Log "    ✗ Falha individual $mid : $($_.Exception.Message)" -Level ERROR }
                                Start-Sleep 1
                            }
                            # Processar IDs restantes deste tag
                            for ($j = $i + 25; $j -lt $ids.Count; $j++) {
                                try {
                                    $singleBody = @{ Value = $tag; Action = "Remove" } | ConvertTo-Json
                                    $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$($ids[$j])/tags" -Method Post -Body $singleBody
                                    $totalRemoved++
                                } catch { $errors++; Write-Log "    ✗ Falha individual $($ids[$j]) : $($_.Exception.Message)" -Level ERROR }
                                Start-Sleep 1
                            }
                            break  # sai do for bulk, tags restantes usarão fallback
                        }
                        $errors++
                        Write-Log "  ✗ ERRO removendo '$tag': $($_.Exception.Message)" -Level ERROR
                    }
                    Start-Sleep 5
                }
            } else {
                # Fallback: endpoint individual por máquina
                foreach ($mid in $ids) {
                    try {
                        $singleBody = @{ Value = $tag; Action = "Remove" } | ConvertTo-Json
                        $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body $singleBody
                        $totalRemoved++
                    } catch { $errors++; Write-Log "    ✗ Falha individual $mid : $($_.Exception.Message)" -Level ERROR }
                    Start-Sleep 1
                }
                Write-Log "  ✓ Removido '$tag' de $($ids.Count) (individual)" -Level OK
            }
        }
    }

    # Pausa entre fases para garantir consistência
    if ($totalRemoved -gt 0) {
        Write-Log "Aguardando 15s entre remoção e adição..." -Level INFO
        Start-Sleep 15
    }

    # ── FASE 2: Adicionar tags novas ──
    if ($additions.Count -gt 0) {
        Write-Log "── FASE 2: Adição de tags ──" -Level INFO
        foreach ($tag in $additions.Keys) {
            $ids = @($additions[$tag])
            Write-Log "Adicionando '$tag' a $($ids.Count) dispositivos..." -Level INFO
            if (-not $useFallback) {
                for ($i = 0; $i -lt $ids.Count; $i += 25) {
                    $end = [Math]::Min($i + 24, $ids.Count - 1)
                    $chunk = @($ids[$i..$end])
                    $body = @{
                        Value      = $tag
                        Action     = "Add"
                        MachineIds = $chunk
                    } | ConvertTo-Json -Depth 3

                    try {
                        $null = Call-MdeApi -Uri $bulkUri -Method Post -Body $body
                        $totalAdded += $chunk.Count
                        Write-Log "  ✓ Adicionado '$tag' a $($chunk.Count) (lote $([Math]::Floor($i/25)+1))" -Level OK
                    }
                    catch {
                        if ($_.Exception.Message -match '403|Forbidden') {
                            Write-Log "  Bulk API indisponível (403). Usando endpoint individual..." -Level WARN
                            $useFallback = $true
                            foreach ($mid in $chunk) {
                                try {
                                    $singleBody = @{ Value = $tag; Action = "Add" } | ConvertTo-Json
                                    $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body $singleBody
                                    $totalAdded++
                                } catch { $errors++; Write-Log "    ✗ Falha individual $mid : $($_.Exception.Message)" -Level ERROR }
                                Start-Sleep 1
                            }
                            for ($j = $i + 25; $j -lt $ids.Count; $j++) {
                                try {
                                    $singleBody = @{ Value = $tag; Action = "Add" } | ConvertTo-Json
                                    $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$($ids[$j])/tags" -Method Post -Body $singleBody
                                    $totalAdded++
                                } catch { $errors++; Write-Log "    ✗ Falha individual $($ids[$j]) : $($_.Exception.Message)" -Level ERROR }
                                Start-Sleep 1
                            }
                            break
                        }
                        $errors++
                        Write-Log "  ✗ ERRO adicionando '$tag': $($_.Exception.Message)" -Level ERROR
                    }
                    Start-Sleep 5
                }
            } else {
                # Fallback: endpoint individual
                foreach ($mid in $ids) {
                    try {
                        $singleBody = @{ Value = $tag; Action = "Add" } | ConvertTo-Json
                        $null = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines/$mid/tags" -Method Post -Body $singleBody
                        $totalAdded++
                    } catch { $errors++; Write-Log "    ✗ Falha individual $mid : $($_.Exception.Message)" -Level ERROR }
                    Start-Sleep 1
                }
                Write-Log "  ✓ Adicionado '$tag' a $($ids.Count) (individual)" -Level OK
            }
        }
    }

    Write-Log "Tags aplicadas: +$totalAdded adicionadas, -$totalRemoved removidas, $errors erros" -Level $(if ($errors -gt 0) { "WARN" } else { "OK" })
    return @{ Added = $totalAdded; Removed = $totalRemoved; Errors = $errors }
}

# ============================================================================
# RELATÓRIO — CSV + Sumário Visual
# ============================================================================
function Export-TagReport {
    param (
        [System.Collections.Generic.List[PSCustomObject]]$Results,
        [hashtable]$Stats
    )

    # CSV com campos relevantes
    $Results | Select-Object MachineId, ComputerDnsName, OsPlatform, HealthStatus, `
        FirstSeen, LastSeen, DaysInactive, LifespanHours, SubscriptionId, `
        CurrentTags, TargetTag, TagsToRemove, Action, Reason |
        Export-Csv -Path $script:ReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Write-Log "Relatório CSV: $($script:ReportPath)" -Level OK

    # Sumário visual no console
    $total = $Results.Count
    $tagCount = ($Results | Where-Object Action -eq "TAG").Count
    $okCount = ($Results | Where-Object Action -eq "OK").Count
    $cleanCount = ($Results | Where-Object Action -eq "CLEAN").Count
    $skipCount = ($Results | Where-Object Action -eq "SKIP").Count

    $byTag = $Results | Where-Object { $_.TargetTag } | Group-Object TargetTag | Sort-Object Count -Descending

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                          ║" -ForegroundColor Cyan
    Write-Host "║   Sync-MDE-ServerTags v$($script:Version)                          ║" -ForegroundColor Cyan
    $modeText = if ($reportOnly) { "REPORT-ONLY (simulação)" } else { "EXECUÇÃO (tags aplicadas)" }
    $modeColor = if ($reportOnly) { "Green" } else { "Yellow" }
    Write-Host "║   Modo: $($modeText.PadRight(48))║" -ForegroundColor $modeColor
    Write-Host "║   Subs: $($script:SubscriptionSource.PadRight(48))║" -ForegroundColor Gray
    Write-Host "║   Data: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')                          ║" -ForegroundColor White
    Write-Host "║                                                          ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  SERVIDORES                                              ║" -ForegroundColor Cyan
    Write-Host "║    Total analisados:     $("{0,6}" -f $total)                         ║" -ForegroundColor White
    Write-Host "║    A taguear (TAG):      $("{0,6}" -f $tagCount)                         ║" -ForegroundColor White
    Write-Host "║    Já corretos (OK):     $("{0,6}" -f $okCount)                         ║" -ForegroundColor Green
    Write-Host "║    Limpeza legado (CLEAN):$("{0,6}" -f $cleanCount)                         ║" -ForegroundColor Yellow
    Write-Host "║    Ignorados (SKIP):     $("{0,6}" -f $skipCount)                         ║" -ForegroundColor Gray
    Write-Host "║                                                          ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  DISTRIBUIÇÃO POR TAG                                    ║" -ForegroundColor Cyan

    foreach ($g in $byTag) {
        $name = $g.Name
        if ($name.Length -gt 35) { $name = $name.Substring(0, 32) + "..." }
        Write-Host "║    $("{0,-37}" -f $name)$("{0,4}" -f $g.Count) srv    ║" -ForegroundColor White
    }

    $noTag = ($Results | Where-Object { -not $_.TargetTag }).Count
    if ($noTag -gt 0) {
        Write-Host "║    $("{0,-37}" -f '(sem tag — ignorados)')$("{0,4}" -f $noTag) srv    ║" -ForegroundColor DarkGray
    }

    if (-not $reportOnly -and $Stats) {
        Write-Host "║                                                          ║" -ForegroundColor Cyan
        Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║  AÇÕES EXECUTADAS                                        ║" -ForegroundColor Cyan
        Write-Host "║    Tags adicionadas:     $("{0,6}" -f $Stats.Added)                         ║" -ForegroundColor Green
        Write-Host "║    Tags removidas:       $("{0,6}" -f $Stats.Removed)                         ║" -ForegroundColor Yellow
        Write-Host "║    Erros:                $("{0,6}" -f $Stats.Errors)                         ║" -ForegroundColor $(if ($Stats.Errors -gt 0) { "Red" } else { "Green" })
    }

    Write-Host "║                                                          ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  API: $($script:ApiCalls) chamadas, $($script:ApiErrors) erros                             ║" -ForegroundColor White
    Write-Host "║  Log: $($script:LogPath)" -ForegroundColor White
    Write-Host "║  CSV: $($script:ReportPath)" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# MAIN
# ============================================================================
try {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  Sync-MDE-ServerTags v$($script:Version)        ║" -ForegroundColor Cyan
    Write-Host "  ║  UMA tag por servidor. Simples.       ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Cyan
    if ($reportOnly) {
        Write-Host "  [REPORT-ONLY] Nenhuma alteração será feita." -ForegroundColor Green
    }
    else {
        Write-Host "  [EXECUÇÃO] Tags SERÃO aplicadas!" -ForegroundColor Yellow
    }
    Write-Host ""

    # 1. Auth
    Write-Log "═══ ETAPA 1/6: Autenticação ═══" -Level INFO
    $null = Get-Token

    # 2. Carregar mapeamento de subscriptions
    Write-Log "═══ ETAPA 2/6: Carregando subscriptions ═══" -Level INFO
    $subMap = Get-SubscriptionMap

    # 3. Obter todos os dispositivos do MDE
    Write-Log "═══ ETAPA 3/6: Obtendo dispositivos do MDE ═══" -Level INFO
    $allDevices = Call-MdeApi -Uri "https://api.securitycenter.microsoft.com/api/machines"
    Write-Log "Total dispositivos no MDE: $($allDevices.Count)" -Level INFO

    # 3b. Descoberta Nível 4: metadados MDE — executado SOMENTE quando ARM e CLI não disponíveis.
    #     Extrai subscriptionIds diretamente dos campos vmMetadata dos devices (sem permissões extras).
    if ($null -eq $subMap -and $autoDiscoverSubscriptions) {
        Write-Log "═══ ETAPA 3b: Descoberta Nível 4 — metadados MDE ═══" -Level INFO
        $subMap = Build-SubscriptionMapFromDevices -Devices $allDevices
    }

    # Garantir mapa inicializado (caso autoDiscoverSubscriptions=$false e subMap=$null por algum motivo)
    if ($null -eq $subMap) {
        Write-Log "AVISO: Sem mapeamento de subscriptions. Servidores ativos não receberão tag de subscription." -Level WARN
        $subMap = @{}
    }

    # 4. Filtrar apenas servidores (Windows Server + Linux)
    Write-Log "═══ ETAPA 4/6: Filtrando servidores ═══" -Level INFO
    $servers = Get-Servers -AllDevices $allDevices
    if ($servers.Count -eq 0) {
        Write-Log "Nenhum servidor encontrado! Verifique o ambiente." -Level ERROR
        throw "Nenhum servidor encontrado."
    }

    # 5. Classificar cada servidor
    Write-Log "═══ ETAPA 5/6: Classificando servidores ═══" -Level INFO
    $results = Get-ServerClassification -Servers $servers -SubMap $subMap

    # 6. Aplicar tags (ou apenas relatório)
    Write-Log "═══ ETAPA 6/6: $(if($reportOnly){'Gerando relatório'}else{'Aplicando tags'}) ═══" -Level INFO
    $stats = Set-Tags -Results $results

    # Relatório final
    Export-TagReport -Results $results -Stats $stats

    Write-Log "Script concluído com sucesso!" -Level OK
}
catch {
    Write-Log "ERRO FATAL: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level ERROR
    throw
}
finally {
    Write-Host "### Finalizado — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ###" -ForegroundColor Green
}
