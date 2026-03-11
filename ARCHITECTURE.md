# SovereignShield Mobile — Architecture

## Purpose

SovereignShield Mobile is a Shiny for Python sovereign cloud compliance app (Mobile-First). It ingests Terraform state, evaluates resources against OPA policies, and provides AI-assisted remediation via agents and RAG. Optimized for touch and narrow viewports.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   SovereignShield Mobile (Shiny App)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  app.py (main)                                                              │
│    ├── CloudResource dataclass (typed)                                      │
│    ├── core/tf_parser.py — parse .tfstate JSON → list[LegacyCloudResource]   │
│    ├── core/opa_eval.py — OPA policy evaluation                             │
│    ├── agents/ — AI orchestration (Anthropic)                                │
│    ├── rag/ — embedding + retrieval for context                             │
│    └── assets/ — Base64 QR codes for portfolio                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Inventory

| Module | Role |
|--------|------|
| `app.py` | Main Shiny UI + server |
| `core/tf_parser.py` | Terraform state parser — `parse_tfstate(path)`, `parse_tfstate_dict(state)` |
| `core/opa_eval.py` | OPA evaluation against policies |
| `core/charts.py` | Plotnine chart generators: heatmap_data, mttr_trend_data, donut_data, kb_growth_data, compliance_heatmap, mttr_trend, violation_donut, kb_growth |
| `core/audit_db.py` | Supabase agent_interactions + local fallback |
| `agents/` | AI agents (planner, worker, reviewer) |
| `rag/` | RAG pipeline for policy/docs context |
| `assets/` | Base64 QR code files for portfolio app cards |

Module path: `Artifacts/project/sovereignshield_mobile/`

---

## UI Layer

| Tab | Content |
|-----|---------|
| Tab 1 Catalogue | 5 columns, color-coded rows, violation detail panel |
| Tab 2 Agent Loop | 5 OPA checks, HCL diff view, MTTR timer, severity |
| Tab 3 Intelligence | Live Supabase KPIs, heatmap, trend, donut charts |
| Tab 4 About + Services | Compliance branding, portfolio QR codes, service tiers, Gold CTA |

**Mobile-only differences (vs Desktop):**
- No HCL diff view
- No CSV export
- No Analytics tab
- 4 tabs instead of 6 (About and Services combined)

---

## Data Flow

```
.tfstate JSON → tf_parser → list[LegacyCloudResource]
                                   │
                                   ├──► OPA eval → violations
                                   ├──► RAG → context for agents
                                   └──► Supabase agent_interactions
```

---

## Deployment

| Item | Value |
|------|-------|
| App Name | SovereignShield Mobile |
| Repo | reichert-science-intelligence/sovereignshield-mobile |
| HF Space | https://rreichert-sovereignshield-mobile.hf.space |
| Port | 7860 |

---

## Supabase Schema

Table: `agent_interactions`

| Column | Type | Notes |
|--------|------|-------|
| task_id | TEXT | PK |
| timestamp | TIMESTAMPTZ | |
| violation_type | TEXT | |
| resource_id | TEXT | |
| planner_output | TEXT | |
| worker_output | TEXT | |
| reviewer_verdict | TEXT | APPROVED, NEEDS_REVISION, REJECTED |
| reviewer_notes | TEXT | |
| is_compliant | BOOLEAN | |
| mttr_seconds | NUMERIC | |
| tokens_used | INTEGER | |
| rag_hit | BOOLEAN | |
| severity | TEXT | CHECK (HIGH\|MEDIUM\|LOW\|INFO) |

---

## Sprint History

- **Sprint 3 completed:** March 2026  
  Features: pyproject.toml, mypy strict, 19 pytest tests, CI pipeline, ARCHITECTURE.md, .cursorrules sync
