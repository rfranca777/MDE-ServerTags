<#
.SYNOPSIS
    Run-Daily.ps1 — Execução Diária Automatizada do MDE ServerTags
    Carrega config.json, executa classificação, organiza logs, notifica.

.DESCRIPTION
    Este é o script wrapper para execução diária. Ele:
    1. Carrega configuração do config.json
    2. Valida pré-requisitos mínimos
    3. Executa o script principal de classificação
    4. Move relatórios e logs para pastas organizadas
    5. Faz rotação automática de logs antigos
    6. Gera sumário de execução com timestamp
    7. Opcionalmente envia notificação por email

    NÃO EDITE ESTE SCRIPT. Todas as customizações devem ser feitas no config.json.

.NOTES
    Versão: 1.0.0 | Fev 2026 | Microsoft
    Chamado por: Scheduled Task ou execução manual
#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly
)

# ============================================================================
# CONFIGURAÇÃO INICIAL
# ============================================================================
$ErrorActionPreference = "Continue"
$scriptRoot = $PSScriptRoot
$configPath = Join-Path $scriptRoot "config.json"
$runTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$exitCode = 0

function Show-Banner {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Cyan
    Write-Host "  ║   ╔╦╗╔═╗╔═╗  ╔═╗╔═╗╦═╗╦  ╦╔═╗╦═╗  ╔╦╗╔═╗╔═╗╔═╗       ║" -ForegroundColor Cyan
    Write-Host "  ║   ║║║ ║║║╣   ╚═╗║╣ ╠╦╝╚╗╔╝║╣ ╠╦╝   ║ ╠═╣║ ╦╚═╗       ║" -ForegroundColor Cyan
    Write-Host "  ║   ╩ ╩═╩╝╚═╝  ╚═╝╚═╝╩╚═ ╚╝ ╚═╝╩╚═  ╩ ╩ ╩╚═╝╚═╝       ║" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Cyan
    Write-Host "  ║   Execução Diária — $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')                  ║" -ForegroundColor White
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-RunLog {
    param ([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts [$Level] $Msg"
    Add-Content -Path $runLogPath -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        "INFO"  { Write-Host "  [$Level] $Msg" -ForegroundColor Cyan }
        "WARN"  { Write-Host "  [$Level] $Msg" -ForegroundColor Yellow }
        "ERROR" { Write-Host "  [$Level] $Msg" -ForegroundColor Red }
        "OK"    { Write-Host "  [$Level] $Msg" -ForegroundColor Green }
    }
}

# ============================================================================
# BANNER
# ============================================================================
Show-Banner

# ============================================================================
# CARREGAR CONFIGURAÇÃO
# ============================================================================
Write-Host "  ── Carregando config.json ──" -ForegroundColor DarkCyan

if (-not (Test-Path $configPath)) {
    Write-Host "  ❌ config.json não encontrado em: $configPath" -ForegroundColor Red
    Write-Host "  Execute Setup-MDE-ServerTags.ps1 primeiro." -ForegroundColor Yellow
    exit 1
}

try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    Write-Host "  ✅ Configuração carregada" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Erro ao ler config.json: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Validar campos obrigatórios
$requiredFields = @(
    @{ Path = "autenticacao.tenantId"; Value = $config.autenticacao.tenantId },
    @{ Path = "autenticacao.appId"; Value = $config.autenticacao.appId },
    @{ Path = "autenticacao.appSecret"; Value = $config.autenticacao.appSecret }
)

$configValid = $true
foreach ($field in $requiredFields) {
    if ([string]::IsNullOrWhiteSpace($field.Value)) {
        Write-Host "  ❌ Campo obrigatório vazio: $($field.Path)" -ForegroundColor Red
        $configValid = $false
    }
}

if (-not $configValid) {
    Write-Host "  Execute Setup-MDE-ServerTags.ps1 para configurar credenciais." -ForegroundColor Yellow
    exit 1
}

# ============================================================================
# PREPARAR DIRETÓRIOS
# ============================================================================
$logsDir = Join-Path $scriptRoot ($config.caminhos.pastaLogs ?? ".\Logs")
$reportsDir = Join-Path $scriptRoot ($config.caminhos.pastaRelatorios ?? ".\Relatorios")
$runLogPath = Join-Path $logsDir "Run-Daily-$runTimestamp.log"

foreach ($dir in @($logsDir, $reportsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-RunLog "═══ INÍCIO DA EXECUÇÃO DIÁRIA ═══"
Write-RunLog "Versão do wrapper: 1.0.0"
Write-RunLog "Timestamp: $runTimestamp"
Write-RunLog "Hostname: $env:COMPUTERNAME"
Write-RunLog "Usuário: $env:USERNAME"

# ============================================================================
# DETERMINAR MODO DE EXECUÇÃO
# ============================================================================
$isReportOnly = $config.execucao.reportOnly
if ($ReportOnly.IsPresent) { $isReportOnly = $true }

if (-not $isReportOnly -and $config.seguranca.confirmarExecucaoReal -and -not $Force.IsPresent) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║  ⚠️  MODO EXECUÇÃO REAL — Tags SERÃO aplicadas!     ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Confirma a execução REAL? (S/N): " -ForegroundColor Yellow -NoNewline
    $confirm = Read-Host
    if ($confirm -notmatch '^[Ss]') {
        Write-RunLog "Execução cancelada pelo usuário" -Level WARN
        Write-Host "  Execução cancelada." -ForegroundColor Gray
        exit 0
    }
}

$modeText = if ($isReportOnly) { "REPORT-ONLY (sem alterações)" } else { "EXECUÇÃO REAL (tags serão aplicadas)" }
$modeColor = if ($isReportOnly) { "Green" } else { "Yellow" }
Write-Host ""
Write-Host "  Modo: $modeText" -ForegroundColor $modeColor
Write-RunLog "Modo: $modeText"

# ============================================================================
# MOSTRAR RESUMO PRÉ-EXECUÇÃO
# ============================================================================
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  CONFIGURAÇÃO ATIVA                                     │" -ForegroundColor White
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  Tenant: $($config.autenticacao.tenantId)" -ForegroundColor Gray
Write-Host "  │  App ID: $($config.autenticacao.appId)" -ForegroundColor Gray  Write-Host "  │  Subscriptions: $(if($autoDiscover){'Auto-descoberta ativa (ARM→CLI→MDE-metadata)'}else{'CSV manual: '+$csvPath})" -ForegroundColor $(if($autoDiscover){'Green'}else{'Gray'})Write-Host "  │  Thresholds:                                            │" -ForegroundColor White
Write-Host "  │    INATIVO_7D ≥ $($config.classificacao.diasInativo7d) dias" -ForegroundColor Cyan
Write-Host "  │    INATIVO_40D ≥ $($config.classificacao.diasInativo40d) dias" -ForegroundColor Cyan
Write-Host "  │    EFEMERO ≤ $($config.classificacao.horasEfemero) horas" -ForegroundColor Cyan
Write-Host "  │  Logs: $logsDir" -ForegroundColor Gray
Write-Host "  │  Relatórios: $reportsDir" -ForegroundColor Gray
Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

# ============================================================================
# EXECUTAR SCRIPT PRINCIPAL
# ============================================================================
Write-RunLog "── Executando script de classificação ──"
Write-Host "  ── Executando Sync-MDE-ServerTags-BySubscription.ps1 ──" -ForegroundColor DarkCyan
Write-Host ""

$mainScript = Join-Path $scriptRoot ($config.caminhos.scriptClassificacao ?? ".\01-Classificacao-Servidores\Sync-MDE-ServerTags-BySubscription.ps1")
$csvPath = Join-Path $scriptRoot ($config.caminhos.subscriptionMappingCsv ?? ".\subscription_mapping.csv")

# Lêr configuração de descoberta automática (padrão: tudo habilitado)
$autoDiscover = $true
$saveCsv     = $true
$excludeSubs = @()
if ($null -ne $config.descoberta) {
    if ($null -ne $config.descoberta.autoDiscoverSubscriptions) { $autoDiscover = [bool]$config.descoberta.autoDiscoverSubscriptions }
    if ($null -ne $config.descoberta.salvarCsvAposDiscovery)    { $saveCsv     = [bool]$config.descoberta.salvarCsvAposDiscovery }
    if ($config.descoberta.excluirSubscriptions)                 { $excludeSubs = @($config.descoberta.excluirSubscriptions) }
}

if (-not (Test-Path $mainScript)) {
    Write-RunLog "Script principal não encontrado: $mainScript" -Level ERROR
    exit 1
}

$startTime = Get-Date

# Executar no diretório do script principal para que os relatórios sejam gerados lá
$scriptDir = Split-Path $mainScript -Parent
Push-Location $scriptDir

try {
    & $mainScript `
        -tenantId                  $config.autenticacao.tenantId `
        -appId                     $config.autenticacao.appId `
        -appSecret                 $config.autenticacao.appSecret `
        -subscriptionMappingPath   $csvPath `
        -autoDiscoverSubscriptions $autoDiscover `
        -saveDiscoveredCsv         $saveCsv `
        -excludeSubscriptions      $excludeSubs `
        -reportOnly                $isReportOnly

    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }

    $duration = (Get-Date) - $startTime
    Write-RunLog "Script concluído em $([math]::Round($duration.TotalSeconds, 1))s — Exit code: $exitCode" -Level OK

} catch {
    $exitCode = 1
    $duration = (Get-Date) - $startTime
    Write-RunLog "ERRO durante execução: $($_.Exception.Message)" -Level ERROR
    Write-RunLog "Stack: $($_.ScriptStackTrace)" -Level ERROR
} finally {
    Pop-Location
}

# ============================================================================
# MOVER ARTEFATOS PARA PASTAS ORGANIZADAS
# ============================================================================
Write-Host ""
Write-Host "  ── Organizando artefatos ──" -ForegroundColor DarkCyan

$movedFiles = 0

# Mover relatórios CSV
Get-ChildItem (Join-Path $scriptDir "ServerTags-Report-*.csv") -ErrorAction SilentlyContinue | ForEach-Object {
    Move-Item $_.FullName -Destination $reportsDir -Force
    Write-RunLog "Relatório movido: $($_.Name) → $reportsDir"
    $movedFiles++
}

# Mover logs
Get-ChildItem (Join-Path $scriptDir "ServerTags-Log-*.log") -ErrorAction SilentlyContinue | ForEach-Object {
    Move-Item $_.FullName -Destination $logsDir -Force
    Write-RunLog "Log movido: $($_.Name) → $logsDir"
    $movedFiles++
}

# Mover sumários
Get-ChildItem (Join-Path $scriptDir "ServerTags-Summary-*.txt") -ErrorAction SilentlyContinue | ForEach-Object {
    Move-Item $_.FullName -Destination $reportsDir -Force
    $movedFiles++
}

Write-Host "  ✅ $movedFiles artefatos organizados" -ForegroundColor Green

# ============================================================================
# ROTAÇÃO DE LOGS ANTIGOS
# ============================================================================
$retentionDays = $config.execucao.logRetentionDays ?? 30
$cutoffDate = (Get-Date).AddDays(-$retentionDays)
$cleaned = 0

foreach ($dir in @($logsDir, $reportsDir)) {
    Get-ChildItem $dir -File -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -lt $cutoffDate
    } | ForEach-Object {
        Remove-Item $_.FullName -Force
        $cleaned++
    }
}

if ($cleaned -gt 0) {
    Write-RunLog "$cleaned arquivo(s) antigo(s) removido(s) (retenção: $retentionDays dias)" -Level INFO
    Write-Host "  🗑️  $cleaned arquivo(s) antigo(s) removido(s) (> $retentionDays dias)" -ForegroundColor Gray
}

# ============================================================================
# GERAR SUMÁRIO DE AUDITORIA
# ============================================================================
if ($config.seguranca.auditarAlteracoes) {
    $auditPath = Join-Path $logsDir "AUDIT-$runTimestamp.txt"
    $auditContent = @"
═══════════════════════════════════════════════════
MDE ServerTags — Registro de Auditoria
═══════════════════════════════════════════════════
Timestamp:    $runTimestamp
Hostname:     $env:COMPUTERNAME
Usuário:      $env:USERNAME
Modo:         $modeText
Duração:      $([math]::Round($duration.TotalSeconds, 1))s
Exit Code:    $exitCode
Config:       $configPath
Script:       $mainScript
CSV Map:      $csvPath
AutoDiscover: $autoDiscover
SalvarCSV:    $saveCsv
ExcluirSubs:  $($excludeSubs -join ', ')
═══════════════════════════════════════════════════
"@
    $auditContent | Set-Content $auditPath -Encoding UTF8
    Write-RunLog "Auditoria gravada: $auditPath"
}

# ============================================================================
# NOTIFICAÇÃO POR EMAIL (OPCIONAL)
# ============================================================================
if ($config.notificacao.habilitado) {
    Write-Host "  ── Enviando notificação por email ──" -ForegroundColor DarkCyan

    # Encontrar relatório mais recente
    $latestReport = Get-ChildItem $reportsDir -Filter "ServerTags-Report-*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    $emailSubject = "MDE ServerTags — Execução Diária $(Get-Date -Format 'dd/MM/yyyy') — $(if($exitCode -eq 0){'OK'}else{'ERRO'})"
    $emailBody = @"
<html><body style="font-family: Consolas, monospace;">
<h2>MDE ServerTags — Relatório de Execução Diária</h2>
<table border="1" cellpadding="5" style="border-collapse: collapse;">
<tr><td><b>Data</b></td><td>$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</td></tr>
<tr><td><b>Modo</b></td><td>$modeText</td></tr>
<tr><td><b>Duração</b></td><td>$([math]::Round($duration.TotalSeconds, 1))s</td></tr>
<tr><td><b>Status</b></td><td>$(if($exitCode -eq 0){'<span style="color:green">SUCESSO</span>'}else{'<span style="color:red">ERRO</span>'})</td></tr>
<tr><td><b>Servidor</b></td><td>$env:COMPUTERNAME</td></tr>
</table>
<p>Relatório CSV anexo (se disponível).</p>
<p><i>Este email foi gerado automaticamente pelo sistema MDE ServerTags.</i></p>
</body></html>
"@

    try {
        $mailParams = @{
            From       = $config.notificacao.remetente
            To         = $config.notificacao.destinatarios
            Subject    = $emailSubject
            Body       = $emailBody
            BodyAsHtml = $true
            SmtpServer = $config.notificacao.smtpServer
            Port       = $config.notificacao.smtpPort
            UseSsl     = $config.notificacao.smtpUseSsl
        }

        if ($latestReport) {
            $mailParams.Attachments = $latestReport.FullName
        }

        Send-MailMessage @mailParams -ErrorAction Stop
        Write-RunLog "Email enviado para: $($config.notificacao.destinatarios -join ', ')" -Level OK
        Write-Host "  ✅ Email enviado" -ForegroundColor Green
    } catch {
        Write-RunLog "Falha ao enviar email: $($_.Exception.Message)" -Level WARN
        Write-Host "  ⚠️  Falha ao enviar email: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ============================================================================
# RESUMO FINAL
# ============================================================================
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "  ║  EXECUÇÃO DIÁRIA — $(if($exitCode -eq 0){'CONCLUÍDA'}else{'FALHOU'})" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "  ║" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host "  ║  Duração: $([math]::Round($duration.TotalSeconds, 1))s" -ForegroundColor White
Write-Host "  ║  Logs:    $logsDir" -ForegroundColor Gray
Write-Host "  ║  Reports: $reportsDir" -ForegroundColor Gray
Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
Write-Host ""

Write-RunLog "═══ FIM DA EXECUÇÃO DIÁRIA (exit: $exitCode) ═══"

exit $exitCode
