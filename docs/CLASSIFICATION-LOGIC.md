# 🏷️ Classification Logic — MDE ServerTags

> Detailed documentation on how servers are classified and tagged.

---

## Overview

MDE ServerTags uses a **priority-based classification engine**. Each server is evaluated against rules in order — the **first matching rule** determines the tag. This guarantees **exactly ONE managed tag** per server.

---

## Priority Chain

```
┌─────────────────────────────────────────────────────────┐
│  Server enters classification pipeline                   │
└──────────┬──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  P1: Is there another MDE ID with the same hostname?    │
│      AND this is the OLDEST registration?               │
│  ──► YES: Tag = DUPLICADA_EXCLUIR                       │
│  ──► NO:  Continue                                      │
└──────────┬──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  P2: Is the server lifespan ≤ 48 hours?                 │
│      AND currently inactive?                            │
│  ──► YES: Tag = EFEMERO                                 │
│  ──► NO:  Continue                                      │
└──────────┬──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  P3: Last communication > 40 days ago?                  │
│  ──► YES: Tag = INATIVO_40D                             │
│  ──► NO:  Continue                                      │
└──────────┬──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  P4: Last communication > 7 days ago?                   │
│  ──► YES: Tag = INATIVO_7D                              │
│  ──► NO:  Continue                                      │
└──────────┬──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  P5: Does the server's Azure subscription match a       │
│      known subscription in the mapping?                 │
│  ──► YES: Tag = {SUBSCRIPTION_NAME}                     │
│  ──► NO:  SKIP (on-premises / no Azure Arc)             │
└─────────────────────────────────────────────────────────┘
```

---

## Detailed Rules

### P1: Duplicate Detection (`DUPLICADA_EXCLUIR`)

**Purpose**: Clean up duplicate MDE device registrations caused by OS re-imaging, re-onboarding, or VM re-creation.

**Logic**:
- Group all MDE devices by hostname (case-insensitive)
- If a hostname has multiple MDE machine IDs:
  - Sort by `lastSeen` (most recent first)
  - The **newest** entry keeps its normal tag
  - All **older** entries get `DUPLICADA_EXCLUIR`

**Example**:
```
WEBSRV01  (MDE ID: abc123, lastSeen: 2025-06-10) → PRODUCTION     ← newest, keeps tag
WEBSRV01  (MDE ID: def456, lastSeen: 2025-01-15) → DUPLICADA_EXCLUIR ← oldest, marked for cleanup
```

---

### P2: Ephemeral Server (`EFEMERO`)

**Purpose**: Identify short-lived servers that shouldn't be in persistent Device Groups (VMSS instances, CI/CD runners, container hosts).

**Logic**:
- Calculate lifespan: `firstSeen` to `lastSeen`
- If lifespan ≤ 48 hours AND server is currently inactive → `EFEMERO`
- The 48-hour threshold is configurable via `config.json` → `classificacao.efemeroHoras`

**Note**: Active short-lived servers are NOT tagged as ephemeral (they might still be valid).

---

### P3: Long Inactive (`INATIVO_40D`)

**Purpose**: Identify decommissioned or abandoned servers that haven't communicated with MDE in over 40 days.

**Recommended action**: Investigate and offboard from MDE if confirmed decommissioned.

---

### P4: Recently Inactive (`INATIVO_7D`)

**Purpose**: Identify servers with recent communication gaps (7-40 days). Could be due to maintenance, vacation, or network issues.

**Recommended action**: Monitor — if they don't come back within 40 days, they'll graduate to `INATIVO_40D`.

---

### P5: Subscription Tag (`{SUBSCRIPTION_NAME}`)

**Purpose**: The primary operational tag. Active servers are tagged with their Azure subscription name.

**Discovery hierarchy** (4 levels):
1. **CSV**: Manual `subscription_mapping.csv` file
2. **ARM API**: Azure Resource Manager API query
3. **Azure CLI**: `az account list` output
4. **MDE Metadata**: Subscription info from MDE device properties

---

## Tag Lifecycle

```
New VM created  ──►  MDE onboards  ──►  Script runs  ──►  Tag = PRODUCTION
                                                              │
                                          VM goes offline ────┘
                                               │
                                    7 days ─────┤
                                               │
                                    Tag changes: INATIVO_7D
                                               │
                                   40 days ─────┤
                                               │
                                    Tag changes: INATIVO_40D
                                               │
                                  VM comes back online ──► Tag reverts: PRODUCTION
```

---

## Non-Managed Servers

Servers that are **NOT tagged** by this script:
- On-premises servers without Azure Arc
- Servers with no matching subscription in the mapping
- Servers explicitly excluded via configuration

> **Important**: The script NEVER removes manually-applied tags. It only manages tags that match the configured naming pattern.

---

## Configuration Reference

```json
{
    "classificacao": {
        "inativoDias7": 7,         // Days until INATIVO_7D
        "inativoDias40": 40,       // Days until INATIVO_40D  
        "efemeroHoras": 48,        // Hours threshold for ephemeral
        "duplicadaTag": "DUPLICADA_EXCLUIR",
        "efemeroTag": "EFEMERO",
        "inativo7Tag": "INATIVO_7D",
        "inativo40Tag": "INATIVO_40D"
    }
}
```

All thresholds and tag names are fully customizable.
