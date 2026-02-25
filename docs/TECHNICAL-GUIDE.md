# 📘 Technical Guide — MDE ServerTags

> Complete technical documentation for installation, configuration, and operation.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [App Registration Setup](#app-registration-setup)
4. [Configuration Reference](#configuration-reference)
5. [Subscription Discovery](#subscription-discovery)
6. [Execution Modes](#execution-modes)
7. [Scheduled Task](#scheduled-task)
8. [Azure Policy Integration](#azure-policy-integration)
9. [Monitoring & Logs](#monitoring--logs)
10. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

MDE ServerTags is a PowerShell-based automation that:

1. **Authenticates** to Azure AD via OAuth2 (client credentials grant)
2. **Queries** Microsoft Defender for Endpoint API for all server devices
3. **Discovers** Azure subscriptions via 4-level hierarchy
4. **Classifies** each server based on priority rules
5. **Applies** tags via MDE Machine API (batch of 25)
6. **Reports** results via console, CSV, and optional email

### API Endpoints Used

| API | Endpoint | Permission |
|-----|----------|------------|
| MDE | `https://api.securitycenter.microsoft.com/api/machines` | `Machine.ReadWrite.All` |
| ARM | `https://management.azure.com/subscriptions` | `Reader` role (optional) |
| Graph | `https://graph.microsoft.com/v1.0/groups` | `Group.ReadWrite.All` (optional, for Device Groups) |

---

## Prerequisites

### Required

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| PowerShell | 5.1 | 7.x |
| MDE License | P1 | P2 |
| Azure AD | App Registration | Managed Identity |
| Network | HTTPS to Microsoft APIs | Direct (no proxy) |

### Network URLs

The execution server must reach:

```
api.securitycenter.microsoft.com     (MDE API)
login.microsoftonline.com            (OAuth2)
management.azure.com                 (ARM API, optional)
graph.microsoft.com                  (Graph API, optional)
```

---

## App Registration Setup

### Step 1: Create the App

```
Azure Portal → Azure Active Directory → App Registrations → New Registration
  Name: MDE-ServerTags-Automation
  Supported account types: Single tenant
  Redirect URI: (leave blank)
```

### Step 2: Add API Permissions

```
API Permissions → Add a permission
  → APIs my organization uses → "WindowsDefenderATP"
  → Application permissions → Machine.ReadWrite.All
  → Add permissions
  → Grant admin consent ✅
```

### Step 3: Create Client Secret

```
Certificates & secrets → New client secret
  Description: MDE-ServerTags
  Expires: 12 months (recommended)
  → Copy the Value immediately (only shown once!)
```

### Step 4: Note the IDs

```
Overview page:
  Application (client) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Directory (tenant) ID:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## Configuration Reference

### `config.json` Structure

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| `autenticacao` | `tenantId` | string | — | Azure AD Tenant ID |
| `autenticacao` | `appId` | string | — | App Registration Client ID |
| `autenticacao` | `appSecret` | string | — | Client Secret value |
| `execucao` | `reportOnly` | bool | `true` | Simulation mode (no changes) |
| `execucao` | `maxRetries` | int | `3` | API retry attempts |
| `execucao` | `batchSize` | int | `25` | Machines per API call |
| `execucao` | `logRetentionDays` | int | `30` | Days to keep log files |
| `classificacao` | `inativoDias7` | int | `7` | Days for INATIVO_7D |
| `classificacao` | `inativoDias40` | int | `40` | Days for INATIVO_40D |
| `classificacao` | `efemeroHoras` | int | `48` | Hours for EFEMERO |
| `descoberta` | `usarArmApi` | bool | `true` | Use ARM API for discovery |
| `descoberta` | `usarAzCli` | bool | `true` | Use Azure CLI for discovery |
| `notificacao` | `habilitado` | bool | `false` | Enable email notifications |

---

## Subscription Discovery

The script uses a 4-level fallback hierarchy:

### Level 1: CSV File
```
subscription_mapping.csv
SubscriptionId,SubscriptionName,TagName
12345-abcde-...,Production,PRODUCTION
67890-fghij-...,Staging,STAGING
```

### Level 2: ARM API
```powershell
# Requires Reader role on subscriptions
GET https://management.azure.com/subscriptions?api-version=2022-12-01
```

### Level 3: Azure CLI
```powershell
# Requires az login
az account list --query "[].{id:id,name:name}" -o json
```

### Level 4: MDE Metadata
```powershell
# Extracts subscription info from MDE device properties
# (azureResourceId contains subscription ID)
```

---

## Execution Modes

### Report-Only (Default)
```powershell
.\Run-Daily.ps1
# With config.json: "reportOnly": true
# Shows what WOULD change, applies nothing
```

### Execute Mode
```powershell
.\Run-Daily.ps1
# With config.json: "reportOnly": false
# Applies tags via MDE API
```

### Direct Script Execution
```powershell
.\01-Server-Classification\Sync-MDE-ServerTags-BySubscription.ps1 `
    -TenantId "your-tenant-id" `
    -AppId "your-app-id" `
    -AppSecret "your-secret" `
    -ReportOnly
```

---

## Scheduled Task

### Install
```powershell
# Run as Administrator
.\Install-ScheduledTask.ps1
```

### Configuration
Edit `config.json` → `agendamento`:
```json
{
    "agendamento": {
        "horarioExecucao": "02:00",
        "intervaloHoras": 24,
        "taskName": "MDE-ServerTags-DailySync"
    }
}
```

### Manual trigger
```powershell
schtasks /run /tn "MDE-ServerTags-DailySync"
```

---

## Azure Policy Integration

The `03-Azure-Policy/` module provides optional Azure Policy that automatically deploys MDE device tags at the VM level.

### Deploy Policy
```powershell
.\03-Azure-Policy\azure-policy\Deploy-MDEPolicy.ps1 `
    -SubscriptionId "your-sub-id" `
    -TagValue "PRODUCTION"
```

### Remediate Existing VMs
```powershell
.\03-Azure-Policy\azure-policy\Remediate-Existing-VMs.ps1 `
    -SubscriptionId "your-sub-id"
```

---

## Monitoring & Logs

### Log Location
```
.\logs\MDE-ServerTags-YYYY-MM-DD.log
```

### Log Retention
Configured via `config.json` → `execucao.logRetentionDays` (default: 30 days)

### Key Metrics to Monitor

| Metric | Where | Alert If |
|--------|-------|----------|
| Exit code | Scheduled Task history | ≠ 0 |
| TAG count | Console output | Suddenly high (bulk change?) |
| INATIVO_40D count | CSV report | Growing (servers not coming back) |
| DUPLICADA_EXCLUIR count | CSV report | Growing (re-imaging issues?) |
| API errors | Log file | Any 401, 403, 429 |

---

## Troubleshooting

### Common Issues

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` | Invalid/expired credentials | Regenerate client secret |
| `403 Forbidden` | Missing API permission | Grant `Machine.ReadWrite.All` + admin consent |
| `429 Too Many Requests` | API throttling | Increase `retryDelaySec` in config |
| No subscriptions found | No CSV + no ARM/CLI access | Manually populate `subscription_mapping.csv` |
| Tags not visible | MDE sync delay | Wait 5-10 minutes, refresh portal |
| `Network error` | Firewall/proxy blocking | Whitelist API URLs (see Prerequisites) |

### Debug Mode
```powershell
# Verbose output for troubleshooting
.\01-Server-Classification\Sync-MDE-ServerTags-BySubscription.ps1 `
    -TenantId "..." -AppId "..." -AppSecret "..." `
    -ReportOnly -Verbose
```

---

*Technical Guide v1.0 | MDE ServerTags v2.2.0*
