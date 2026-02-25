# 🚀 Quick Start Guide — MDE ServerTags

> Get up and running in **5 minutes**.

---

## Step 1: Prerequisites

| Requirement | How to check |
|-------------|-------------|
| PowerShell 5.1+ | `$PSVersionTable.PSVersion` |
| Azure AD App Registration | [Create one](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) |
| MDE API Permission | `Machine.ReadWrite.All` (Application) |
| Network connectivity | `Invoke-WebRequest https://api.securitycenter.microsoft.com -UseBasicParsing` |

## Step 2: Clone & Configure

```powershell
git clone https://github.com/rfranca777/MDE-ServerTags.git
cd MDE-ServerTags

# Create your config from the template
Copy-Item config.example.json config.json

# Edit with your Azure AD App credentials
notepad config.json
```

**Required fields in `config.json`:**
```json
{
    "autenticacao": {
        "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "appSecret": "your-app-secret-value"
    }
}
```

## Step 3: Run Setup Wizard

```powershell
.\Setup-MDE-ServerTags.ps1
```

The wizard auto-discovers your tenant, subscriptions, and validates connectivity.

## Step 4: First Run (Safe Mode)

```powershell
# Report-only mode — see what would happen without changing anything
.\Run-Daily.ps1
```

Review the console output and CSV report. No tags are applied in report mode.

## Step 5: Apply Tags

```powershell
# Edit config.json: set "reportOnly": false
.\Run-Daily.ps1
```

## Step 6: Schedule (Optional)

```powershell
# Run as Administrator — installs a daily Windows Scheduled Task
.\Install-ScheduledTask.ps1
```

---

## 📂 What Gets Created

After running the scripts, you'll find:

| File | Description |
|------|-------------|
| `subscription_mapping.csv` | Auto-generated subscription-to-tag mapping |
| `logs/` | Execution logs with timestamps |
| Console output | Classification summary with statistics |

## 🏷️ Tags You'll See in MDE

| Tag | Meaning |
|-----|---------|
| `{SUBSCRIPTION_NAME}` | Active server in that subscription |
| `INATIVO_7D` | No communication for 7+ days |
| `INATIVO_40D` | No communication for 40+ days |
| `EFEMERO` | Short-lived server (≤48h lifespan) |
| `DUPLICADA_EXCLUIR` | Duplicate MDE registration (oldest) |

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|---------|
| `401 Unauthorized` | Check App Registration permissions and admin consent |
| `403 Forbidden` | Ensure `Machine.ReadWrite.All` is granted (not just requested) |
| No subscriptions found | Run `az login` first, or populate `subscription_mapping.csv` manually |
| Tags not appearing | Wait 5-10 min for MDE to sync, then refresh Device Inventory |

---

**Next:** Read the full [Technical Guide](TECHNICAL-GUIDE.md) for advanced configuration.
