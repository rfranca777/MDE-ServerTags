<#
.SYNOPSIS
    Install-ScheduledTask.ps1 — Instalar Tarefa Agendada do Windows
    Cria Scheduled Task para execução diária automática do Run-Daily.ps1

.DESCRIPTION
    Este script cria uma Scheduled Task no Windows que:
    - Executa Run-Daily.ps1 automaticamente no horário configurado
    - Roda como conta SYSTEM (não requer login)
    - Mantém histórico de execução no Event Log
    - Pode ser gerenciada via Task Scheduler GUI

    REQUER: Execução como Administrador

.NOTES
    Versão: 1.0.0 | Fev 2026 | Microsoft
#>

# ============================================================================
# VALIDAÇÕES
# ============================================================================
$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
$configPath = Join-Path $scriptRoot "config.json"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   INSTALAÇÃO — Scheduled Task MDE ServerTags             ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verificar admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ❌ Este script requer execução como ADMINISTRADOR." -ForegroundColor Red
    Write-Host "  Abra o PowerShell como Administrador e execute novamente." -ForegroundColor Yellow
    exit 1
}

# Carregar config
if (-not (Test-Path $configPath)) {
    Write-Host "  ❌ config.json não encontrado. Execute Setup-MDE-ServerTags.ps1 primeiro." -ForegroundColor Red
    exit 1
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json

$taskName = $config.agendamento.nomeTask ?? "MDE-ServerTags-DailySync"
$taskDesc = $config.agendamento.descricaoTask ?? "Sincronização diária de tags MDE por subscription Azure"
$scheduleTime = $config.agendamento.horarioExecucao ?? "06:00"
$intervalHours = $config.agendamento.intervaloHoras ?? 24
$runDailyScript = Join-Path $scriptRoot "Run-Daily.ps1"

if (-not (Test-Path $runDailyScript)) {
    Write-Host "  ❌ Run-Daily.ps1 não encontrado em: $runDailyScript" -ForegroundColor Red
    exit 1
}

# ============================================================================
# INFORMAÇÕES
# ============================================================================
Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCHEDULED TASK A SER CRIADA                            │" -ForegroundColor White
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  Nome:      $taskName" -ForegroundColor Cyan
Write-Host "  │  Descrição: $taskDesc" -ForegroundColor Gray
Write-Host "  │  Horário:   $scheduleTime (a cada ${intervalHours}h)" -ForegroundColor Cyan
Write-Host "  │  Script:    $runDailyScript" -ForegroundColor Gray
Write-Host "  │  Usuário:   SYSTEM (sem necessidade de login)" -ForegroundColor Gray
Write-Host "  │  Diretório: $scriptRoot" -ForegroundColor Gray
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  O QUE ISSO FAZ?                                       │" -ForegroundColor Yellow
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  O Windows executará automaticamente o script de        │" -ForegroundColor White
Write-Host "  │  classificação MDE ServerTags no horário configurado.   │" -ForegroundColor White
Write-Host "  │  Não é necessário estar logado no servidor.             │" -ForegroundColor White
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  COMO GERENCIAR DEPOIS:                                 │" -ForegroundColor Yellow
Write-Host "  │                                                         │" -ForegroundColor DarkGray
Write-Host "  │  • Abrir: taskschd.msc (Task Scheduler)                │" -ForegroundColor White
Write-Host "  │  • Localizar: $taskName" -ForegroundColor White
Write-Host "  │  • Parar: schtasks /end /tn '$taskName'" -ForegroundColor White
Write-Host "  │  • Remover: schtasks /delete /tn '$taskName' /f" -ForegroundColor White
Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

# Verificar se task já existe
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "  ⚠️  Scheduled Task '$taskName' já existe." -ForegroundColor Yellow
    Write-Host "  Deseja SUBSTITUIR? (S/N): " -ForegroundColor Yellow -NoNewline
    $resp = Read-Host
    if ($resp -notmatch '^[Ss]') {
        Write-Host "  Instalação cancelada." -ForegroundColor Gray
        exit 0
    }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  Task anterior removida." -ForegroundColor Gray
}

Write-Host "  Deseja criar a Scheduled Task? (S/N): " -ForegroundColor Yellow -NoNewline
$confirm = Read-Host
if ($confirm -notmatch '^[Ss]') {
    Write-Host "  Instalação cancelada." -ForegroundColor Gray
    exit 0
}

# ============================================================================
# CRIAR SCHEDULED TASK
# ============================================================================
Write-Host ""
Write-Host "  Criando Scheduled Task..." -ForegroundColor Cyan

# Determinar o executável PowerShell
$pwshExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    (Get-Command pwsh).Source
} else {
    "powershell.exe"
}

# Action: executar Run-Daily.ps1 com -Force (sem prompt interativo)
$action = New-ScheduledTaskAction `
    -Execute $pwshExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runDailyScript`" -Force" `
    -WorkingDirectory $scriptRoot

# Trigger: horário + repetição
$triggerParams = @{
    Once = $true
    At = (Get-Date -Hour ([int]$scheduleTime.Split(':')[0]) -Minute ([int]$scheduleTime.Split(':')[1]) -Second 0)
    RepetitionInterval = (New-TimeSpan -Hours $intervalHours)
}
$trigger = New-ScheduledTaskTrigger @triggerParams

# Settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 10)

# Principal: SYSTEM
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -RunLevel Highest `
    -LogonType ServiceAccount

# Registrar
try {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Description $taskDesc `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Force | Out-Null

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  ✅ Scheduled Task criada com sucesso!                    ║" -ForegroundColor Green
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  Nome:     $taskName" -ForegroundColor White
    Write-Host "  ║  Horário:  $scheduleTime (a cada ${intervalHours}h)" -ForegroundColor White
    Write-Host "  ║  Status:   Habilitada" -ForegroundColor Green
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  COMANDOS ÚTEIS:                                          ║" -ForegroundColor Yellow
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  Executar agora:                                          ║" -ForegroundColor White
    Write-Host "  ║    schtasks /run /tn '$taskName'" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  Ver status:                                              ║" -ForegroundColor White
    Write-Host "  ║    schtasks /query /tn '$taskName' /v" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  Desabilitar:                                             ║" -ForegroundColor White
    Write-Host "  ║    schtasks /change /tn '$taskName' /disable" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ║  Remover:                                                 ║" -ForegroundColor White
    Write-Host "  ║    schtasks /delete /tn '$taskName' /f" -ForegroundColor Cyan
    Write-Host "  ║                                                           ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host "  ❌ Erro ao criar Scheduled Task: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
