<div align="center">

<img src="assets/banner.svg" alt="MDE ServerTags — Automated Server Classification for Microsoft Defender for Endpoint" width="100%"/>

<br/>

[![Version](https://img.shields.io/badge/Version-2.2.0-00ff88?style=for-the-badge&logo=github)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![MDE](https://img.shields.io/badge/Microsoft_Defender-Endpoint-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
[![ODefender](https://img.shields.io/badge/ODefender-Community-FF6F00?style=for-the-badge)](https://github.com/rfranca777/odefender-community)

<br/>

### Classify. Tag. Automate. Sleep.

**Stop spending hours manually tagging servers in MDE.**  
**Let automation do it in minutes — every single day.**

<br/>

</div>

---

## ⚡ The 30-Second Pitch

You have **hundreds of servers** across multiple Azure subscriptions. Microsoft Defender for Endpoint sees them all — but without proper **tags and Device Groups**, you're flying blind:

- Same AV policy for production and dev? 😬
- Inactive servers cluttering your dashboard? 😤
- Duplicate MDE registrations nobody notices? 🤦
- A new subscription was added last week and... nobody tagged those servers? 🫠

**MDE ServerTags fixes all of this. Automatically. Daily. While you sleep.**

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│    ███╗   ███╗██████╗ ███████╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗      │
│    ████╗ ████║██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝      │
│    ██╔████╔██║██║  ██║█████╗      ███████╗█████╗  ██████╔╝██║   ██║█████╗        │
│    ██║╚██╔╝██║██║  ██║██╔══╝      ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝        │
│    ██║ ╚═╝ ██║██████╔╝███████╗    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗      │
│    ╚═╝     ╚═╝╚═════╝ ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝      │
│                                                                                  │
│              ████████╗ █████╗  ██████╗ ███████╗                                  │
│              ╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝                                  │
│                 ██║   ███████║██║  ███╗███████╗                                   │
│                 ██║   ██╔══██║██║   ██║╚════██║                                   │
│                 ██║   ██║  ██║╚██████╔╝███████║                                   │
│                 ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝                                   │
│                                                                                  │
│    ┌──────────────────────────────────────────────────────────────────────┐       │
│    │  🛡️  Automated Server Classification                                │       │
│    │  📊  Zero-Touch Daily Execution                                     │       │
│    │  🔍  Lifecycle Tracking: Inactive • Ephemeral • Duplicate           │       │
│    │  🏷️  ONE Tag Per Server — Deterministic, Auditable, Reliable       │       │
│    └──────────────────────────────────────────────────────────────────────┘       │
│                                                                                  │
│    v2.2.0 │ Community Edition │ MIT License │ PowerShell 7.x                     │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 The Impact

<table>
<tr>
<td width="50%" align="center">

### ⏱️ Before
**Manual Process**

</td>
<td width="50%" align="center">

### ⚡ After
**MDE ServerTags**

</td>
</tr>
<tr>
<td>

❌ 4-6 hours/week managing tags manually  
❌ Human errors in classification  
❌ Stale data — servers missed for weeks  
❌ No lifecycle tracking  
❌ Duplicate MDE IDs go unnoticed  
❌ New subscriptions = days of manual work  
❌ "Who changed that tag?" — nobody knows  

</td>
<td>

✅ **0 hours/week** — fully automated  
✅ Deterministic, auditable classification  
✅ Daily sync — always current  
✅ Lifecycle: Inactive (7d/40d), Ephemeral, Duplicate  
✅ Duplicates detected and tagged automatically  
✅ New subs auto-discovered via ARM/CLI/MDE  
✅ Complete CSV + HTML reports every run  

</td>
</tr>
</table>

> **Estimated time saved**: 200-300 hours/year for a typical 500-server environment.  
> *That's 8 weeks of analyst time. Doing something useful instead of clicking through portals.*

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🏷️ **ONE Tag Per Server** | Clean, deterministic classification — no tag conflicts, ever |
| 🔍 **4-Level Auto-Discovery** | CSV → ARM API → Azure CLI → MDE metadata (automatic fallback) |
| 🔄 **Lifecycle Management** | Detects inactive (7d/40d), ephemeral (VMSS/CI-CD), and duplicate servers |
| 📊 **Report-First** | Safe `reportOnly` mode — see what WOULD change before applying |
| 🛡️ **Zero-Touch Setup** | Interactive Setup Wizard auto-discovers your tenant, credentials, subscriptions |
| ⏰ **Scheduled Execution** | Windows Scheduled Task for daily automated runs |
| 📧 **Email Notifications** | Optional SMTP notifications when tags change |
| 🧪 **End-to-End Validation** | Full test script with 10 automated validation stages |
| 📋 **Azure Policy** | Optional Azure Policy integration for VM-level MDE tag deployment |
| 🌐 **Multi-Platform** | Windows Server + Linux (Ubuntu, RHEL, SUSE, Oracle, Debian, etc.) |

---

## 🏗️ How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MDE ServerTags — Classification Flow                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────┐    ┌───────────────────┐    ┌────────────────────────┐  │
│   │  Azure AD     │    │  MDE API          │    │  ARM API / Az CLI     │  │
│   │  OAuth2       │───▶│  /api/machines    │◀───│  /subscriptions       │  │
│   └──────────────┘    └───────────────────┘    └────────────────────────┘  │
│                               │                          │                  │
│                               ▼                          ▼                  │
│                     ┌───────────────────┐    ┌────────────────────────┐    │
│                     │  Filter: Win+Lin  │    │  Build Subscription    │    │
│                     │  Servers Only     │    │  Map (4-level)         │    │
│                     └───────────────────┘    └────────────────────────┘    │
│                               │                          │                  │
│                               ▼                          │                  │
│                     ┌────────────────────────────────────┐│                  │
│                     │     CLASSIFICATION ENGINE          ││                  │
│                     │                                    ││                  │
│                     │  P1: DUPLICADA_EXCLUIR  (oldest)   ││                  │
│                     │  P2: EFEMERO           (≤48h)     ││                  │
│                     │  P3: INATIVO_40D       (>40 days) ││                  │
│                     │  P4: INATIVO_7D        (>7 days)  ││                  │
│                     │  P5: {SUBSCRIPTION}    (active)    │◀                  │
│                     │  --: No tag            (on-prem)   │                   │
│                     └────────────────────────────────────┘                   │
│                               │                                             │
│                               ▼                                             │
│                     ┌───────────────────┐    ┌────────────────────────┐    │
│                     │  Apply Tags       │    │  CSV Report            │    │
│                     │  Batch API (25/r) │    │  Console Summary       │    │
│                     └───────────────────┘    └────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Classification Priority

| Priority | Tag | Condition | Action |
|----------|-----|-----------|--------|
| P1 | `DUPLICADA_EXCLUIR` | Same hostname, multiple MDE IDs → oldest | Candidate for cleanup |
| P2 | `EFEMERO` | Lifespan ≤ 48h AND inactive | VMSS/CI-CD, auto-managed |
| P3 | `INATIVO_40D` | No communication > 40 days | Candidate for offboard |
| P4 | `INATIVO_7D` | No communication 7–40 days | Monitor and investigate |
| P5 | `{SUBSCRIPTION}` | Active + mapped subscription | Primary operational tag |
| — | *(no tag)* | On-premises, no Arc | Script doesn't touch |

> **Guarantee**: Each server gets **exactly ONE** managed tag. Manual tags are **always preserved**.

---

## 📁 Project Structure

```
MDE-ServerTags/
├── 📄 README.md                           ← You are here
├── 📄 config.example.json                 ← Configuration template
├── 📄 subscription_mapping.csv            ← Auto-generated mapping
│
├── 🔧 Setup-MDE-ServerTags.ps1            ← START HERE — Setup Wizard
├── 🔧 Run-Daily.ps1                       ← Daily execution wrapper
├── 🔧 Install-ScheduledTask.ps1           ← Scheduled Task installer
├── 🧪 TEST-Lab-E2E.ps1                    ← E2E validation (10 stages)
│
├── 01-Server-Classification/
│   └── 🔧 Sync-MDE-ServerTags-BySubscription.ps1  ← Core engine (1100+ lines)
│
├── 02-Infrastructure-Deploy/
│   └── 🔧 Deploy-MDE-Infrastructure.ps1   ← Azure Automation deployment
│
├── 03-Azure-Policy/
│   ├── azure-policy/                      ← Policy definition + remediation
│   └── scripts/                           ← Deployment & automation scripts
│
└── docs/
    ├── 📄 QUICK-START.md                  ← 5-minute quick start
    ├── 📄 TECHNICAL-GUIDE.md              ← Complete technical docs
    ├── 📄 IMPLEMENTATION-CHECKLIST.md     ← Step-by-step checklist
    └── 📄 CLASSIFICATION-LOGIC.md         ← Detailed classification rules
```

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

| Requirement | How to Verify |
|-------------|--------------|
| PowerShell 5.1+ (7.x recommended) | `$PSVersionTable.PSVersion` |
| Azure AD App Registration | [Create one →](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) |
| MDE API Permission | `Machine.ReadWrite.All` (Application, not Delegated) |
| Admin Consent | Granted ✅ |

### 1. Clone & Configure

```powershell
git clone https://github.com/rfranca777/MDE-ServerTags.git
cd MDE-ServerTags

Copy-Item config.example.json config.json
# Edit config.json with your credentials
```

### 2. Run Setup Wizard

```powershell
.\Setup-MDE-ServerTags.ps1
```

### 3. First Run (Safe Mode)

```powershell
.\Run-Daily.ps1   # reportOnly: true by default — nothing changes
```

### 4. Apply Tags

```powershell
# After reviewing output, set reportOnly: false in config.json
.\Run-Daily.ps1   # Tags are applied!
```

### 5. Schedule Daily

```powershell
.\Install-ScheduledTask.ps1   # Run as Administrator
```

> **📖 Full guide**: [docs/QUICK-START.md](docs/QUICK-START.md) | [docs/TECHNICAL-GUIDE.md](docs/TECHNICAL-GUIDE.md)

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║  Sync-MDE-ServerTags v2.2.0                                                     ║
║  Mode: REPORT-ONLY (simulation — no changes applied)                             ║
║  Subscriptions: ARM API auto-discovery                                           ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  SERVERS                                                                         ║
║    Total analyzed:           142                                                 ║
║    To tag (TAG):              38                                                 ║
║    Already correct (OK):      89                                                 ║
║    Legacy cleanup (CLEAN):     5                                                 ║
║    Skipped (SKIP):            10                                                 ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  TAG DISTRIBUTION                                                                ║
║    PRODUCTION                              52 servers                            ║
║    STAGING                                 28 servers                            ║
║    DEVELOPMENT                             15 servers                            ║
║    SHARED-SERVICES                         12 servers                            ║
║    INATIVO_7D                               8 servers                            ║
║    INATIVO_40D                              5 servers                            ║
║    DUPLICADA_EXCLUIR                        3 servers                            ║
║    EFEMERO                                  2 servers                            ║
║                                                                                  ║
║  Duration: 47 seconds | Batch: 25/request | Retries: 0                          ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 🔮 Roadmap: What's Coming

### 🤖 AI Agents — *Q3 2025*

This is **v1** — the classification engine. It **identifies** issues, but a human still acts on them.

**Version 2 changes that.** We're building AI agents that will:

| Agent | What It Does |
|-------|-------------|
| 🧹 **Cleanup Agent** | Auto-offboard `DUPLICADA_EXCLUIR` machines after cross-referencing with Azure and CMDB |
| 🔍 **Lifecycle Agent** | Investigate `INATIVO_40D` servers — check Azure VM status, DNS, last login — then escalate or offboard |
| ⚡ **Fleet Agent** | Manage ephemeral server lifecycle, auto-tagging VMSS instances and CI/CD runners |
| 📋 **Group Agent** | Auto-create and maintain MDE Device Groups via Microsoft Graph API |

```
  TODAY:   Script tags → Human reviews → Human acts → Human reports
  SOON:    Script tags → Agent validates → Agent acts → Agent reports → Human approves
```

> *The goal: analysts spend time on strategy and threat hunting, not on tag management.*

---

## 🏷️ Classification Deep Dive

For the full classification logic documentation, see [docs/CLASSIFICATION-LOGIC.md](docs/CLASSIFICATION-LOGIC.md).

```
New VM → MDE onboards → Script runs → Tag: PRODUCTION
                                            │
                         VM goes offline ────┘
                              │
                   7 days ────┤──→ Tag changes: INATIVO_7D
                              │
                  40 days ────┤──→ Tag changes: INATIVO_40D
                              │
                VM comes back online ──→ Tag reverts: PRODUCTION ✅
```

---

## ⚙️ Configuration Reference

See [config.example.json](config.example.json) for all settings:

| Section | Key Settings |
|---------|-------------|
| `autenticacao` | Tenant ID, App ID, App Secret |
| `execucao` | `reportOnly`, `maxRetries`, `logRetentionDays` |
| `classificacao` | Inactive thresholds (7d, 40d), ephemeral hours (48h) |
| `descoberta` | Auto-discovery toggles (ARM API, Azure CLI, MDE metadata) |
| `agendamento` | Schedule time, interval, task name |
| `notificacao` | SMTP server, recipients, send-on-changes-only |

---

## 🧪 Testing

```powershell
# Report mode (safe — no changes)
.\TEST-Lab-E2E.ps1 -Report

# Execute mode (applies tags + creates Device Groups)
.\TEST-Lab-E2E.ps1 -Execute -AppSecret 'your-secret-here'
```

**10 Validation Stages:**

| Stage | What It Tests |
|-------|--------------|
| 0 | PowerShell 7 verification |
| 1 | Prerequisites (OS, files, network, Graph API) |
| 2 | Service Principal & credentials |
| 3 | OAuth2 authentication (MDE + ARM + Graph) |
| 4 | App Registration & permissions |
| 5 | Active configuration |
| 6 | Server classification engine |
| 7 | Device Groups (AAD Security Groups) |
| 8 | VM extensions verification |
| 9 | HTML report generation |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 👤 Author

**Rafael França**  
**Customer Success Architect — Cyber Security @ Microsoft**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rafael_França-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rfranca777/)
[![Email](https://img.shields.io/badge/Email-rafael.franca@live.com-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:rafael.franca@live.com)
[![ODefender](https://img.shields.io/badge/ODefender-Community-FF6F00?style=for-the-badge)](https://github.com/rfranca777/odefender-community)

> *This project is part of [ODefender Community](https://github.com/rfranca777/odefender-community) — open-source security automation for the real world.*

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This project is **not officially supported by Microsoft**. It is an independent community contribution by a Microsoft employee, shared under MIT license. Use at your own risk. Always test with `reportOnly: true` first.

Microsoft Defender for Endpoint, Azure, and related trademarks are property of Microsoft Corporation.

---

<div align="center">

**Part of the [ODefender Community](https://github.com/rfranca777/odefender-community) initiative.**

*Empowering security teams to achieve more — one automation at a time.*

<br/>

[![Stars](https://img.shields.io/github/stars/rfranca777/MDE-ServerTags?style=social)](https://github.com/rfranca777/MDE-ServerTags)

</div>
