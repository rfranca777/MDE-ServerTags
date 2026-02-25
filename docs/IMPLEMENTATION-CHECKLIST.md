# ✅ Implementation Checklist — MDE ServerTags

> **Use this checklist as a step-by-step guide to deploy the solution.**  
> Check each item as you complete it.

---

## Phase 0: Planning (Day 1)

- [ ] **Read** `README.md` for overview
- [ ] **Read** `docs/TECHNICAL-GUIDE.md` for architecture details
- [ ] **Define** the server where the script will run (recommended: management server / jump box)
- [ ] **Define** service account or automation process (Scheduled Task vs Azure Automation)
- [ ] **Gather** list of Azure subscriptions to be mapped
- [ ] **Align** with SOC on tag names and Device Group names

---

## Phase 1: Azure AD Prerequisites (Day 1)

### App Registration

- [ ] Go to **portal.azure.com** > **App Registrations** > **New Registration**
- [ ] Name: `MDE-ServerTags-Automation`
- [ ] Type: **Single Tenant**
- [ ] Note **Application (Client) ID**: `________________________________`
- [ ] Note **Directory (Tenant) ID**: `________________________________`
- [ ] Go to **Certificates & Secrets** > **New Client Secret**
- [ ] Set expiration (recommended: 12 months)
- [ ] Note **Secret value**: `________________________________` ⚠️ Save it now!

### API Permissions

- [ ] Go to **API Permissions** > **Add a permission**
- [ ] Select **APIs my organization uses** > search **WindowsDefenderATP**
- [ ] Select **Application permissions** (NOT Delegated)
- [ ] Check **Machine.ReadWrite.All**
- [ ] Click **Add permissions**
- [ ] Click **Grant admin consent for [Tenant]** ⚠️ REQUIRED
- [ ] Confirm status shows **Granted** ✅

---

## Phase 2: Package Setup (Day 1)

### Install the package

- [ ] Clone or copy `MDE-ServerTags` to the execution server
- [ ] Recommended path: `C:\MDE-ServerTags\`
- [ ] Verify PowerShell 5.1+ is available: `$PSVersionTable.PSVersion`
- [ ] Verify connectivity: `Invoke-WebRequest https://api.securitycenter.microsoft.com -UseBasicParsing`

### Run Setup

- [ ] Open PowerShell **as Administrator**
- [ ] `cd C:\MDE-ServerTags`
- [ ] `Copy-Item config.example.json config.json`
- [ ] `.\Setup-MDE-ServerTags.ps1`
- [ ] Follow the wizard (7 steps)
- [ ] Confirm connectivity test passed ✅
- [ ] Confirm report-only output was generated ✅

### Configure Subscriptions

- [ ] Edit `subscription_mapping.csv` with your actual subscriptions
- [ ] Format: `SubscriptionId,SubscriptionName,TagName`
- [ ] To get IDs: `az account list --query "[].{id:id,name:name}" -o table`
- [ ] Verify no example/template lines remain in CSV
- [ ] Confirm UTF-8 encoding

---

## Phase 3: Report-Only Validation (Day 2)

### First safe run

- [ ] Confirm `config.json` has `"reportOnly": true`
- [ ] Run: `.\Run-Daily.ps1`
- [ ] Wait for completion (typically 1-3 minutes)
- [ ] Verify exit code = 0

### Analyze report

- [ ] Open the latest CSV report
- [ ] Check tag distribution:
  ```powershell
  Import-Csv .\subscription_mapping.csv |
      Group-Object TagName | Sort-Object Count -Desc | Format-Table Name, Count
  ```
- [ ] Confirm production servers have the correct tag
- [ ] Confirm inactive servers are identified
- [ ] Check servers with Action = SKIP (unmapped subscription?)
- [ ] If needed, add missing subscriptions to CSV and re-run

### Second run (validation)

- [ ] Run again: `.\Run-Daily.ps1`
- [ ] Confirm consistency with the first run (idempotency)

---

## Phase 4: Activate Real Execution (Day 3)

### Enable real mode

- [ ] Edit `config.json`:
  - Change `"reportOnly"` from `true` to `false`
- [ ] Run: `.\Run-Daily.ps1`
- [ ] Confirm at the prompt: `Y` to proceed
- [ ] Verify tags were applied successfully (0 errors)

### Validate in MDE portal

- [ ] Go to **security.microsoft.com** > **Devices** > **Device inventory**
- [ ] Filter by Tag: verify servers have correct tags
- [ ] Check at least 3 servers from each subscription
- [ ] Verify inactive servers are tagged

### Idempotency test

- [ ] Run again: `.\Run-Daily.ps1`
- [ ] Confirm TAG = 0 (no changes needed)
- [ ] Confirm OK = [total servers]

---

## Phase 5: Create Device Groups in MDE (Day 3-4)

- [ ] Go to **security.microsoft.com** > **Settings** > **Endpoints** > **Device groups**

### Device Groups to create:

- [ ] **Servers-Production**
  - Tag filter: `YOUR-PRODUCTION-TAG` (your subscription tag name)
  - Automation level: `Semi-automated`
  
- [ ] **Servers-Staging**
  - Tag filter: `YOUR-STAGING-TAG`
  - Automation level: `Full automation`

- [ ] **Servers-Development**
  - Tag filter: `YOUR-DEV-TAG`
  - Automation level: `Full automation`

- [ ] **Servers-Inactive-7d**
  - Tag filter: `INATIVO_7D`
  - Automation level: `Semi-automated`

- [ ] **Servers-Inactive-40d**
  - Tag filter: `INATIVO_40D`
  - Automation level: `No automated response`

- [ ] **Servers-Duplicates**
  - Tag filter: `DUPLICADA_EXCLUIR`
  - Automation level: `No automated response`

- [ ] **Servers-Ephemeral**
  - Tag filter: `EFEMERO`
  - Automation level: `No automated response`

---

## Phase 6: Automated Scheduling (Day 4)

- [ ] Decide frequency: daily (24h) or 2x/day (12h)
- [ ] Edit `config.json` > `agendamento`:
  - `horarioExecucao`: desired time (e.g., `"06:00"`)
  - `intervaloHoras`: `24` (daily) or `12` (2x/day)
- [ ] Run as Admin: `.\Install-ScheduledTask.ps1`
- [ ] Confirm task was created
- [ ] Verify in Task Scheduler (`taskschd.msc`)
- [ ] Force manual execution for testing: `schtasks /run /tn "MDE-ServerTags-DailySync"`
- [ ] Check logs after execution

---

## Phase 7: Email Notifications (Optional)

- [ ] Edit `config.json` > `notificacao`:
  - `habilitado`: `true`
  - `smtpServer`: your SMTP server address
  - `smtpPort`: port (typically 587 with TLS)
  - `remetente`: sender email
  - `destinatarios`: recipient list
- [ ] Test: run `.\Run-Daily.ps1` and verify email receipt

---

## Phase 8: Ongoing Operations

### Weekly

- [ ] Check logs — confirm daily executions
- [ ] Review reports — monitor inactive server trends
- [ ] Verify Device Groups in MDE portal — confirm segmentation

### Monthly

- [ ] Review subscriptions — add new subs to CSV if needed
- [ ] Renew Client Secret before expiration (12 months)
- [ ] Investigate `INATIVO_40D` servers — candidates for offboarding
- [ ] Investigate `DUPLICADA_EXCLUIR` servers — candidates for removal
- [ ] Clean up `EFEMERO` if patterns changed (new VMSS, CI/CD)

### Annual

- [ ] Renew App Registration Client Secret
- [ ] Review thresholds (7d, 40d, 48h) per environment SLA
- [ ] Check for script updates (new versions)
- [ ] Document changes in CHANGELOG

---

## 📝 Implementation Record

| Field | Value |
|-------|-------|
| **Implementation date** | ___/___/______ |
| **Responsible** | __________________________ |
| **Execution server** | __________________________ |
| **App Registration Name** | __________________________ |
| **App ID** | __________________________ |
| **Tenant ID** | __________________________ |
| **Secret expires on** | ___/___/______ |
| **Subscriptions mapped** | _______ |
| **Total servers** | _______ |
| **Execution frequency** | Every _______ hours |
| **Device Groups created** | _______ |

---

*Checklist v1.0 | MDE ServerTags v2.2.0*
