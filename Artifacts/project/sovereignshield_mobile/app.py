"""
SovereignShield Mobile — mobile-first Shiny for Python sovereign cloud compliance app.
Mirrors StarGuard Mobile layout/CSS. Port 7860. Launch: shiny run app.py --host 0.0.0.0 --port 7860
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Graceful import fallback — run with simulated data if any module fails
_USE_REAL_MODULES = True
try:
    from project.sovereignshield_mobile.core.opa_eval import evaluate, Violation
    from project.sovereignshield_mobile.core.audit_db import db
    from project.sovereignshield_mobile.core.audit_log import write_run, fetch_history
    from project.sovereignshield_mobile.agents.planner import planner
    from project.sovereignshield_mobile.agents.worker import worker
    from project.sovereignshield_mobile.agents.reviewer import reviewer
    from project.sovereignshield_mobile.rag.retriever import embed_and_store, retrieve_similar
except ImportError:
    _USE_REAL_MODULES = False
    evaluate = None
    db = None
    write_run = None  # type: ignore[assignment]
    fetch_history = None  # type: ignore[assignment]
    planner = None
    worker = None
    reviewer = None
    embed_and_store = None
    retrieve_similar = None
    Violation = dict

# CloudResource from models (tf_parser imports LegacyCloudResource, not CloudResource)
from project.sovereignshield_mobile.models import CloudResource

try:
    from shiny import App, reactive, render, ui
except ImportError:
    raise ImportError("shiny is required. Run: pip install shiny")

from datetime import datetime

# S17-02-A: Cross-app findings telemetry (fire-and-forget)
try:
    from sovereignshield_platform_integration import record_finding as _record_cross_app_finding
except Exception:
    _record_cross_app_finding = None

# Full 5-resource catalogue (same as desktop)


def parse_terraform(file_path: str) -> list[dict[str, Any]]:
    """
    Parse Terraform .tf or .tfstate file and extract resources.
    Returns list of dicts with keys: resource_id, resource_type, region, encryption_enabled, is_public, tags.
    Falls back to empty list if parsing fails (caller uses RESOURCES when empty).
    """
    result: list[dict[str, Any]] = []
    path = Path(file_path)
    if not path.exists():
        return []
    try:
        suffix = path.suffix.lower()
        if suffix in (".tfstate", ".json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            resources = data.get("resources") or []
            for r in resources:
                res_type = str(r.get("type", ""))
                res_name = str(r.get("name", ""))
                resource_id = f"{res_type}-{res_name}".replace("aws_", "").replace("_", "-") if res_type and res_name else res_name or res_type
                instances = r.get("instances") or []
                region = ""
                tags: dict[str, str] = {}
                if instances:
                    attrs = instances[0].get("attributes") or {}
                    region = str(attrs.get("region") or attrs.get("region_name") or "")
                    if not region and attrs.get("availability_zone"):
                        az = str(attrs["availability_zone"])
                        match = re.match(r"^([a-z]+-[a-z]+-\d+)", az)
                        region = match.group(1) if match else "us-east-1"
                    raw_tags = attrs.get("tags") or {}
                    if isinstance(raw_tags, dict):
                        tags = {str(k): str(v) for k, v in raw_tags.items()}
                if not region:
                    region = "us-east-1"
                result.append({
                    "resource_id": resource_id or f"resource-{len(result)}",
                    "resource_type": res_type,
                    "region": region,
                    "encryption_enabled": False,
                    "is_public": False,
                    "tags": tags,
                })
        elif suffix == ".tf":
            content = path.read_text(encoding="utf-8")
            pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
            for m in pattern.finditer(content):
                res_type = m.group(1).strip()
                res_name = m.group(2).strip()
                resource_id = f"{res_type}-{res_name}".replace("aws_", "").replace("_", "-") if res_type and res_name else res_name or res_type
                result.append({
                    "resource_id": resource_id or f"resource-{len(result)}",
                    "resource_type": res_type,
                    "region": "us-east-1",
                    "encryption_enabled": False,
                    "is_public": False,
                    "tags": {},
                })
    except Exception:
        return []
    return result


RESOURCES: list[CloudResource] = [
    CloudResource(
        resource_id="s3-phi-claims-001",
        resource_type="aws_s3_bucket",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-001",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
    CloudResource(
        resource_id="s3-staging-analytics",
        resource_type="aws_s3_bucket",
        region="eu-central-1",
        encryption_enabled=False,
        cmk_key_id=None,
        is_public=False,
        tags={"Environment": "staging"},
    ),
    CloudResource(
        resource_id="rds-member-records",
        resource_type="aws_db_instance",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-002",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
    CloudResource(
        resource_id="rds-dev-sandbox",
        resource_type="aws_db_instance",
        region="us-west-2",
        encryption_enabled=False,
        cmk_key_id=None,
        is_public=True,
        tags={"Environment": "dev"},
    ),
    CloudResource(
        resource_id="lambda-eligibility",
        resource_type="aws_lambda_function",
        region="us-east-1",
        encryption_enabled=True,
        cmk_key_id="arn:aws:kms:us-east-1:123456789:key/abc-003",
        is_public=False,
        tags={"DataClass": "PHI", "Environment": "prod"},
    ),
]

# Synthetic history when Supabase empty/unavailable
_SYNTHETIC_HISTORY: list[dict[str, Any]] = [
    {"run_at": "2026-03-12 14:22", "total": 5, "compliance_rate": "60.0%", "avg_mttr": "3.8s", "trend": "−"},
    {"run_at": "2026-03-13 09:15", "total": 5, "compliance_rate": "80.0%", "avg_mttr": "2.1s", "trend": "↑"},
    {"run_at": "2026-03-14 11:45", "total": 5, "compliance_rate": "62.0%", "avg_mttr": "4.2s", "trend": "↓"},
]

# Seed events for fallback when db unavailable
_SEED_EVENTS: list[dict[str, Any]] = [
    {
        "task_id": "seed-001",
        "timestamp": "2025-03-09T12:00:00",
        "violation_type": "data_residency",
        "resource_id": "s3-staging-analytics",
        "severity": "HIGH",
        "planner_output": "Add CMK encryption and region constraint",
        "worker_output": 'resource "aws_s3_bucket_server_side_encryption_configuration" ...',
        "reviewer_verdict": "APPROVED",
        "reviewer_notes": "Compliant",
        "is_compliant": True,
        "mttr_seconds": 4.2,
        "tokens_used": 646,
        "rag_hit": False,
    },
]


def _highest_severity(violations: list[dict[str, Any]]) -> str:
    """Return highest severity among violations. HIGH > MEDIUM > LOW > INFO."""
    order: dict[str, int] = {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    best = "INFO"
    for v in violations:
        s = str(v.get("severity", "INFO")).upper().strip()
        if order.get(s, 0) > order.get(best, 0):
            best = s
    return best


def _effective_log(limit: int = 10) -> list[dict[str, Any]]:
    """Fetch recent events with local fallback."""
    if _USE_REAL_MODULES and db is not None:
        result = db.fetch_recent(limit)
        return cast(list[dict[str, Any]], result)
    return list(_SEED_EVENTS)[:limit]


def _run_agents(resource_id: str, violation_type: str, resources: list[CloudResource]) -> dict[str, Any]:
    """Run agent loop: evaluate → planner → worker → reviewer."""
    if not _USE_REAL_MODULES or evaluate is None or planner is None or worker is None or reviewer is None:
        return {
            "trace": "  [Simulated] Region check: ✓\n  [Simulated] CMK check: ✓\n  [Simulated] PHI tag: ✗\n",
            "verdict": "NEEDS_REVISION",
            "checks_passed": ["Region check", "CMK check"],
            "checks_failed": ["PHI DataClass tag missing"],
            "result": None,
            "plan": None,
            "work": None,
            "mttr_seconds": 4.2,
        }

    violations = evaluate(resources)
    selected = next(
        (
            v
            for v in violations
            if str(v.get("resource_id", "")) == resource_id
            and str(v.get("violation_type", "")) == violation_type
        ),
        None,
    )
    if not selected:
        return {
            "trace": "  No matching violation found.\n",
            "verdict": "REJECTED",
            "checks_passed": [],
            "checks_failed": ["Violation not found"],
            "result": None,
            "plan": None,
            "work": None,
            "mttr_seconds": 0.0,
        }

    t0 = datetime.now()
    plan = planner.run(selected)
    work = worker.run(plan)
    result = reviewer.run(plan, work, started_at=t0)

    trace = ""
    for check in result.checks_passed:
        trace += f"  ✓ {check}\n"
    for check in result.checks_failed:
        trace += f"  ✗ {check}\n"
    if not trace:
        trace = "  (no checks reported)\n"

    if result.verdict == "APPROVED" and embed_and_store is not None:
        detail = selected.get("detail") or (
            f"{selected.get('violation_type', '')} {selected.get('resource_id', '')} "
            f"{selected.get('regulation_cited', '')}"
        )
        embed_and_store(
            detail,
            work.hcl_code,
            {
                "regulatory_context": str(selected.get("regulation_cited", "")),
                "confidence_score": "0.95",
            },
        )

    if db is not None:
        event: dict[str, Any] = {
            "task_id": plan.task_id,
            "timestamp": datetime.now().isoformat(),
            "violation_type": plan.violation_type,
            "resource_id": plan.resource_id,
            "planner_output": plan.fix_strategy,
            "worker_output": work.hcl_code,
            "reviewer_verdict": result.verdict,
            "reviewer_notes": result.notes,
            "is_compliant": result.is_compliant,
            "mttr_seconds": result.mttr_seconds,
            "tokens_used": plan.tokens_used + work.tokens_used + result.tokens_used,
            "rag_hit": plan.rag_hit,
        }
        db.insert(event)

    return {
        "trace": trace,
        "verdict": result.verdict,
        "checks_passed": result.checks_passed,
        "checks_failed": result.checks_failed,
        "result": result,
        "plan": plan,
        "work": work,
        "mttr_seconds": result.mttr_seconds,
    }


# ── Mobile CSS (StarGuard-style) ──────────────────────────────────────────────
_NAV_CSS = """
.nav-tabs, .nav-pills { display: flex !important; flex-wrap: nowrap !important; overflow-x: auto !important; white-space: nowrap !important; -webkit-overflow-scrolling: touch; scrollbar-width: none; }
.nav-tabs::-webkit-scrollbar, .nav-pills::-webkit-scrollbar { display: none; }
.nav-tabs .nav-item, .nav-pills .nav-item { flex-shrink: 0; }
.nav-tabs .nav-link, .nav-pills .nav-link { padding: 8px 12px !important; font-size: 0.85rem !important; }
"""
_MOBILE_CSS = """
body { max-width: 480px; margin: 0 auto; background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
.ss-header { background: #4A3E8F; color: white; height: 56px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.25rem; }
.ss-card { background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 16px; margin-bottom: 12px; }
.severity-high { background: #dc3545; color: white; padding: 8px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }
.severity-medium { background: #fd7e14; color: white; padding: 8px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }
.severity-low { background: #28a745; color: white; padding: 8px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }
.severity-compliant { background: #28a745; color: white; padding: 8px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; display: inline-block; }
button, .btn { min-height: 44px !important; }
.ss-run-btn { width: 100%; height: 52px; background: #D4AF37; color: black; font-weight: bold; border-radius: 8px; border: none; }
.violation-card { border-left: 4px solid #dc3545; }
.compliant-card { border-left: 4px solid #28a745; }
.nav-pill-button { background: #4A3E8F; color: white; }
.kpi-tile { background: white; border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); padding: 16px; text-align: center; }
.ss-gold-btn { background: #D4AF37; color: black; font-weight: bold; min-height: 44px; }
.nav-tabs, .nav-pills, [class*="navset"] > div:first-child {
    display: flex !important;
    flex-wrap: nowrap !important;
    overflow-x: auto !important;
    white-space: nowrap !important;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
}
.nav-tabs::-webkit-scrollbar, .nav-pills::-webkit-scrollbar,
[class*="navset"] > div:first-child::-webkit-scrollbar { display: none; }
.nav-tabs .nav-item, .nav-pills .nav-item,
[class*="navset"] [role="tablist"] > * { flex-shrink: 0; }
.nav-tabs .nav-link, .nav-pills .nav-link,
[class*="navset"] [role="tab"] {
    padding: 8px 12px !important;
    font-size: 0.85rem !important;
}
"""


@dataclass
class PortfolioApp:
    """Portfolio app item for About tab."""

    name: str
    description: str
    url: str
    qr_file: str


_PORTFOLIO_APPS: list[PortfolioApp] = [
    PortfolioApp("AuditShield Live", "RADV Audit Defense Platform", "https://huggingface.co/spaces/rreichert/auditshield-live", "QR_AuditShield_Live.b64.txt"),
    PortfolioApp("StarGuard Desktop", "MA Intelligence Platform", "https://rreichert-starguard-desktop.hf.space", "QR_StarGuard_Desktop.b64.txt"),
    PortfolioApp("StarGuard Mobile", "MA Intelligence on Mobile", "https://rreichert-starguardai.hf.space", "QR_Mobile_Tiny_Sized.b64.txt"),
    PortfolioApp("SovereignShield Mobile", "Sovereign Cloud Compliance", "https://rreichert-sovereignshield-mobile.hf.space", "QR_SovereignShield_Mobile.b64.txt"),
]


def _load_avatar() -> str:
    """Load avatar from assets/avatar.b64.txt as data URI."""
    try:
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        path = os.path.join(assets_dir, "avatar.b64.txt")
        with open(path, "r") as f:
            data = f.read().strip().replace("\n", "").replace("\r", "")
        if not data.startswith("data:"):
            data = f"data:image/png;base64,{data}"
        return data
    except Exception:
        return ""


_AVATAR_SRC: str = _load_avatar()


def _load_qr(filename: str) -> str:
    """Load base64 image from assets/*.b64.txt. Handles whitespace, MIME detection."""
    try:
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        path = os.path.join(assets_dir, filename)
        with open(path, "r") as f:
            raw = f.read()
        b64 = "".join(raw.split())  # strip all whitespace/newlines
        if not b64 or b64.startswith("data:"):
            return b64
        if b64.startswith("/9j/"):
            return f"data:image/jpeg;base64,{b64}"
        if b64.startswith("iVBORw0KGgo"):
            return f"data:image/png;base64,{b64}"
        return f"data:image/png;base64,{b64}"  # fallback
    except Exception:
        return ""


# ── UI ──────────────────────────────────────────────────────────────────────

def _footer() -> Any:
    """Synthetic data disclaimer footer for all tabs."""
    return ui.div(
        ui.hr(style="margin: 24px 0 8px 0; border-color: #dee2e6;"),
        ui.p(
            "© 2026 Robert Reichert | Sovereign Cloud & AI. "
            "All data shown is synthetic and generated for demonstration purposes only. "
            "No real patient, member, or infrastructure data is used.",
            style="font-size: 11px; color: #6c757d; text-align: center; "
                  "padding: 0 16px 16px 16px; line-height: 1.5;",
        ),
        style="width: 100%;",
    )


def _catalogue_ui() -> Any:
    """Tab 1: Resource Catalogue — server-rendered cards with violation details."""
    return ui.div(
        ui.div("Resource Catalogue", class_="ss-header", style="margin-bottom: 16px; border-radius: 0 0 12px 12px;"),
        ui.input_file(
            "tf_upload",
            "Upload Terraform File",
            accept=[".tf", ".tfstate", ".json"],
            placeholder="Drop .tf or .tfstate file here",
        ),
        ui.output_text("upload_status"),
        ui.output_ui("catalogue_content"),
        _footer(),
    )


def _agent_loop_ui() -> Any:
    """Tab 2: Run Remediation with condensed trace and verdict."""
    return ui.div(
        ui.div("Run Remediation", class_="ss-header", style="margin-bottom: 16px; border-radius: 0 0 12px 12px;"),
        ui.div(
            ui.div(
                ui.input_checkbox("policy_encryption", "Enforce encryption_enabled", value=True),
                ui.input_checkbox("policy_public", "Enforce is_public == False", value=True),
                ui.input_checkbox("policy_region", "Enforce approved regions only", value=True),
                ui.input_action_button(
                    "apply_policy",
                    "⚡ Apply Policy",
                    style="background:#4A3E8F; color:white; "
                          "border:none; padding:8px 16px; "
                          "border-radius:6px; margin-top:8px; width:100%;",
                ),
                ui.output_text("policy_status"),
                style="margin-bottom: 12px;",
            ),
            ui.input_select("violation_select", "Violation", choices={"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}),
            ui.input_action_button("run_btn", "Run", class_="ss-run-btn"),
            ui.input_action_button(
                "run_all",
                "⚡ Run All Resources",
                style="background:#D4AF37; color:#1A1633; font-weight:700; "
                      "border:none; padding:10px; border-radius:8px; "
                      "width:100%; margin-top:8px;",
            ),
            ui.output_ui("batch_results_panel"),
            ui.input_action_button("record_run_btn", "📋 Record run", class_="btn-secondary", style="margin-top:8px; width:100%;"),
            ui.output_ui("record_run_status"),
            ui.output_ui("trace_condensed"),
            ui.output_ui("verdict_line"),
            ui.output_ui("mttr_line"),
            class_="ss-card",
            style="width: 100%;",
        ),
        _footer(),
    )


def _intelligence_ui() -> Any:
    """Tab 3: Intelligence — 2×2 KPI tiles + violation donut."""
    return ui.div(
        ui.div("Intelligence", class_="ss-header", style="margin-bottom: 16px; border-radius: 0 0 12px 12px;"),
        ui.div(
            ui.div(
                ui.output_ui("kpi_mttr"),
                ui.output_ui("kpi_rag"),
                ui.output_ui("kpi_compliance"),
                ui.output_ui("kpi_kb"),
                class_="row",
                style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;",
            ),
            ui.div(ui.output_ui("violation_chart"), class_="ss-card"),
            ui.input_action_button("refresh_btn", "Refresh", class_="btn nav-pill-button", style="width: 100%; margin-top: 12px; color: white;"),
            ui.download_button(
                "export_pdf",
                "📄 Export Report",
                style="background:#4A3E8F; color:white; border:none; "
                      "padding:10px; border-radius:8px; "
                      "margin-top:8px; width:100%;"
            ),
        ),
        _footer(),
    )


def _about_ui() -> Any:
    """Tab 4: About + Services."""
    return ui.div(
        ui.div("Robert Reichert", class_="ss-header", style="margin-bottom: 16px; border-radius: 0 0 12px 12px;"),
        ui.div(
            ui.div(
                (
                    ui.div(
                        ui.img(
                            src=_AVATAR_SRC,
                            style="width: 96px; height: 96px; border-radius: 50%; "
                                  "object-fit: cover; object-position: center top; "
                                  "border: 3px solid #4A3E8F; display: block; margin: 0 auto 12px auto;",
                        ),
                        style="text-align: center;",
                    )
                    if _AVATAR_SRC
                    else ui.div("RR", style="width: 72px; height: 72px; border-radius: 50%; background: #4A3E8F; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.5rem; margin: 0 auto 12px;")
                ),
                ui.div("Robert Reichert", style="font-weight: 700; font-size: 1.25rem; text-align: center;"),
                ui.div("Principal, Sovereign Cloud & AI", style="text-align: center; color: #666; margin-bottom: 8px;"),
                ui.div(
                    ui.span("Cloud Compliance", class_="badge bg-secondary", style="margin: 4px;"),
                    ui.span("Agentic AI", class_="badge bg-secondary", style="margin: 4px;"),
                    ui.span("Healthcare Analytics", class_="badge bg-secondary", style="margin: 4px;"),
                    style="display: flex; flex-wrap: wrap; justify-content: center; gap: 4px; margin-bottom: 12px;",
                ),
                ui.div(
                    ui.a("reichert.starguardai@email.com", href="mailto:reichert.starguardai@email.com", style="margin: 0 8px;"),
                    ui.a("LinkedIn", href="https://www.linkedin.com/in/robertreichert-healthcareai/", style="margin: 0 8px;"),
                    ui.span("+1 (480) 767-1337", style="margin: 0 8px;"),
                    style="text-align: center; font-size: 14px; margin-bottom: 12px;",
                ),
                ui.div("Available March 2026", class_="severity-compliant", style="display: inline-block; background: #D4AF37 !important; color: black !important; margin: 0 auto;"),
                class_="ss-card",
                style="text-align: center;",
            ),
            style="margin-bottom: 16px;",
        ),
        ui.h6("Portfolio Apps", style="margin-bottom: 12px;"),
        ui.div(
            *[
                ui.div(
                    ui.div(app.name, style="font-weight: 600; margin-bottom: 4px;"),
                    ui.div(app.description, style="font-size: 13px; color: #666; margin-bottom: 4px;"),
                    ui.a(app.url, href=app.url, target="_blank", style="font-size: 12px; margin-bottom: 8px; display: block;"),
                    ui.img(src=_load_qr(app.qr_file), style="width:80px; height:80px; object-fit:contain;", alt=app.name) if _load_qr(app.qr_file) else ui.span("(QR)", style="font-size: 12px; color: #999;"),
                    class_="ss-card",
                    style="margin-bottom: 12px;",
                )
                for app in _PORTFOLIO_APPS
            ],
        ),
        ui.h6("Services", style="margin-top: 24px; margin-bottom: 12px;"),
        ui.accordion(
            ui.accordion_panel(
                "Sovereign Cloud Compliance Audit — Senior Consultant Rate",
                ui.p("HIPAA-compliant cloud resource audit with OPA policy evaluation and Terraform remediation."),
                ui.tags.ul(ui.tags.li("Policy-as-code review"), ui.tags.li("Violation report"), ui.tags.li("Terraform fix generation")),
                ui.p("Typical engagement: 2–4 weeks", style="margin-top: 8px;"),
            ),
            ui.accordion_panel(
                "Agentic AI System Design — Senior Consultant Rate",
                ui.p("Design and implement agentic workflows (Planner → Worker → Reviewer) for compliance and automation."),
                ui.tags.ul(ui.tags.li("Architecture design"), ui.tags.li("RAG integration"), ui.tags.li("Claude API integration")),
                ui.p("Typical engagement: 4–8 weeks", style="margin-top: 8px;"),
            ),
            ui.accordion_panel(
                "HEDIS/RADV Analytics Consulting — Consulting Rate",
                ui.p("Healthcare quality measure analytics, RADV exposure scoring, and star rating optimization."),
                ui.tags.ul(ui.tags.li("HEDIS measure analysis"), ui.tags.li("RADV scenario modeling"), ui.tags.li("ROI projections")),
                ui.p("Typical engagement: 2–6 weeks", style="margin-top: 8px;"),
            ),
        ),
        ui.div(
            ui.a("Discuss Engagement: reichert.starguardai@email.com", href="mailto:reichert.starguardai@email.com",
            class_="btn ss-gold-btn", style="width: 100%; margin-top: 16px; display: block; text-align: center; text-decoration: none; line-height: 44px;"),
        ),
        _footer(),
    )


def _history_ui() -> Any:
    """Sprint 6: Past audit runs — compliance trending."""
    return ui.div(
        ui.div("History", class_="ss-header", style="margin-bottom: 16px; border-radius: 0 0 12px 12px;"),
        ui.div(
            ui.input_action_button("history_refresh_btn", "Refresh", class_="btn nav-pill-button", style="width: 100%; margin-bottom: 12px; color: white;"),
            ui.div(ui.output_ui("history_table"), class_="ss-card", style="margin-top: 12px; overflow-x: auto;"),
        ),
        _footer(),
    )


app_ui = ui.page_fluid(
    ui.tags.head(
        ui.tags.meta(name="viewport", content="width=device-width, initial-scale=1.0, maximum-scale=5.0"),
        ui.tags.title("SovereignShield Mobile"),
        ui.tags.style(_MOBILE_CSS),
        ui.tags.style(_NAV_CSS),
    ),
    ui.navset_pill(
        ui.nav_panel("Catalogue", _catalogue_ui(), value="catalogue"),
        ui.nav_panel("Agent Loop", _agent_loop_ui(), value="agent"),
        ui.nav_panel("Intelligence", _intelligence_ui(), value="intel"),
        ui.nav_panel("History", _history_ui(), value="history"),
        ui.nav_panel("About", _about_ui(), value="about"),
    ),
)

DEFAULT_POLICY_FLAGS: dict[str, bool] = {
    "encryption": True,
    "public": True,
    "region": True
}


def server(input: Any, output: Any, session: Any) -> None:
    active_policy_flags: reactive.Value[dict[str, bool]] = reactive.Value({
        "encryption": True,
        "public": True,
        "region": True,
    })

    @reactive.effect
    @reactive.event(input.apply_policy)
    def _apply_policy() -> None:
        active_policy_flags.set({
            "encryption": input.policy_encryption(),
            "public": input.policy_public(),
            "region": input.policy_region(),
        })

    @render.text
    def policy_status() -> str:
        if input.apply_policy() > 0:
            return "✅ Policy updated"
        return ""

    def _dict_to_cloud_resource(d: dict[str, Any]) -> CloudResource:
        """Convert parsed Terraform dict to CloudResource."""
        return CloudResource(
            resource_id=str(d.get("resource_id", "")),
            resource_type=str(d.get("resource_type", "unknown")),
            region=str(d.get("region", "us-east-1")),
            encryption_enabled=bool(d.get("encryption_enabled", False)),
            cmk_key_id=None,
            is_public=bool(d.get("is_public", False)),
            tags=dict(d.get("tags") or {}),
        )

    @reactive.calc
    def active_resources() -> list[CloudResource]:
        f = input.tf_upload()
        if f is None or len(f) == 0:
            return RESOURCES
        try:
            parsed = parse_terraform(f[0]["datapath"])
            if not parsed:
                return RESOURCES
            return [_dict_to_cloud_resource(d) for d in parsed]
        except Exception:
            return RESOURCES

    @render.text
    def upload_status() -> str:
        f = input.tf_upload()
        if f is None or len(f) == 0:
            return "Demo data active"
        r = active_resources()
        return f"{len(r)} resources loaded"

    @reactive.calc
    def _violations() -> list[dict[str, Any]]:
        v = list(evaluate(active_resources())) if _USE_REAL_MODULES and evaluate else []
        if not v:
            v = [{"resource_id": "s3-staging-analytics", "violation_type": "data_residency", "severity": "HIGH"}]
        flags = active_policy_flags()
        filtered: list[dict[str, Any]] = []
        for item in v:
            vtype = str(item.get("violation_type", ""))
            if vtype in ("hipaa_encryption", "cmk_required") and not flags.get("encryption", True):
                continue
            if vtype == "public_exposure" and not flags.get("public", True):
                continue
            if vtype == "data_residency" and not flags.get("region", True):
                continue
            filtered.append(item)
        return filtered

    @reactive.calc
    def _violation_choices() -> dict[str, str]:
        violations = _violations()
        choices = {
            f"{v.get('resource_id', '')}|{v.get('violation_type', '')}": f"{v.get('resource_id', '')} / {v.get('violation_type', '')}"
            for v in violations
        }
        if not choices:
            choices = {"s3-staging-analytics|data_residency": "s3-staging-analytics / data_residency"}
        return choices

    @reactive.effect
    def _update_choices() -> None:
        ui.update_select("violation_select", choices=_violation_choices())

    agent_result: reactive.Value[dict[str, Any] | None] = reactive.Value(None)
    batch_results: reactive.Value[list[dict[str, Any]]] = reactive.Value([])

    @reactive.effect
    @reactive.event(input.run_all)
    async def _run_batch() -> None:
        resources = active_resources()
        results: list[dict[str, Any]] = []
        violations_all = _violations()
        for resource in resources:
            res_violations = [
                v for v in violations_all
                if str(v.get("resource_id", "")) == resource.resource_id
            ]
            if not res_violations:
                results.append({
                    "resource_id": resource.resource_id,
                    "resource_type": resource.resource_type,
                    "verdict": "COMPLIANT",
                    "violations": 0,
                    "mttr_seconds": 0,
                })
                continue
            mttr: float = 0.0
            try:
                out = await asyncio.to_thread(
                    _run_agents,
                    resource.resource_id,
                    res_violations[0]["violation_type"],
                    resources,
                )
                verdict = out.get("verdict", "ERROR")
                mttr = float(out.get("mttr_seconds", 0) or 0)
            except Exception:
                verdict = "ERROR"
            verdict_pdf = "COMPLIANT" if verdict == "APPROVED" else verdict
            results.append({
                "resource_id": resource.resource_id,
                "resource_type": resource.resource_type,
                "verdict": verdict_pdf,
                "violations": len(res_violations),
                "mttr_seconds": mttr,
            })
        batch_results.set(results)
        # Sprint 6: Persist to Supabase audit_runs + audit_results
        if results and write_run is not None:
            tf = input.tf_upload()
            source_filename = tf[0]["name"] if tf and len(tf) > 0 else ""
            write_run(batch_results=results, source_filename=source_filename, policy_text="")

    @reactive.effect
    @reactive.event(input.run_btn)
    def _on_run() -> None:
        sel = input.violation_select()
        if not sel:
            return
        parts = str(sel).split("|", 1)
        rid = parts[0] if len(parts) > 0 else ""
        vtype = parts[1] if len(parts) > 1 else ""
        agent_result.set(_run_agents(rid, vtype, active_resources()))

    # Catalogue: server-rendered cards with inline violation details
    @render.ui
    def catalogue_content() -> Any:
        out: list[Any] = []
        resources = active_resources()
        v_all = _violations()
        if not v_all:
            v_all = [{"resource_id": "s3-staging-analytics", "violation_type": "data_residency", "severity": "HIGH", "detail": "Region not in allowed sovereign regions"}]
        for r in resources:
            res_v = [v for v in v_all if str(v.get("resource_id", "")) == r.resource_id]
            sev = _highest_severity(res_v) if res_v else ""
            is_compliant = len(res_v) == 0
            badge_cls = "severity-compliant" if is_compliant else f"severity-{sev.lower()}"
            badge_text = "✓ Compliant" if is_compliant else sev
            card_children: list[Any] = [
                ui.div(ui.span(r.resource_id, style="font-weight: bold;"), ui.span(r.resource_type, class_="badge bg-secondary", style="margin-left: 8px; font-size: 11px;"), style="display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;"),
                ui.div("Region: " + r.region, style="font-size: 14px; color: #666; margin-bottom: 8px;"),
                ui.span(badge_text, class_=badge_cls),
            ]
            if res_v:
                card_children.append(
                    ui.div(
                        ui.h6("Violations", style="margin-top: 12px;"),
                        *[ui.div(ui.strong(f"{v.get('violation_type', '')} ({v.get('severity', '')})"), ui.p(str(v.get("detail", "")), style="margin: 4px 0 0 0; font-size: 13px;"), style="padding: 8px; border-bottom: 1px solid #eee;") for v in res_v],
                        style="margin-top: 12px;",
                    )
                )
            card_cls = "compliant-card ss-card" if is_compliant else "violation-card ss-card"
            out.append(ui.div(*card_children, class_=card_cls))
        return ui.div(*out)

    # Agent Loop outputs
    @render.ui
    def trace_condensed() -> Any:
        r = agent_result()
        if r is None:
            return ui.div("Select a resource and click Run to start the agent loop.", style="font-size: 14px; color: #666;")
        passed = r.get("checks_passed") or []
        failed = r.get("checks_failed") or []
        lines: list[str] = [f"✓ {c}" for c in passed[:2]] + [f"✗ {c}" for c in failed[:1]]
        if len(lines) < 3 and passed:
            lines = [f"✓ {c}" for c in passed[:3]]
        elif len(lines) < 3 and failed:
            lines = lines + [f"✗ {c}" for c in failed[: 3 - len(lines)]]
        text = "\n".join(lines[:3]) if lines else ((r.get("trace") or "").split("\n")[0] or "—")
        return ui.div(
            ui.pre(text, style="font-family: monospace; font-size: 13px; white-space: pre-wrap;"),
            style="margin-top: 12px;",
        )

    @render.ui
    def verdict_line() -> Any:
        r = agent_result()
        if r is None:
            return ui.div("Verdict will appear here after running the agent loop.", style="font-size: 14px; color: #666;")
        v = r.get("verdict", "")
        color: str = {"APPROVED": "#28a745", "REJECTED": "#dc3545", "NEEDS_REVISION": "#fd7e14"}.get(v, "#333")
        return ui.div(v, style=f"font-size: 1.25rem; font-weight: bold; color: {color}; margin-top: 12px;")

    @render.ui
    def mttr_line() -> Any:
        r = agent_result()
        if r is None:
            return ui.div()
        mttr = r.get("mttr_seconds", 0)
        return ui.div(f"MTTR: {mttr:.1f}s", style="font-size: 12px; color: #666; margin-top: 4px;")

    @render.ui
    def batch_results_panel() -> Any:
        results = batch_results()
        if not results:
            return ui.div()
        compliant = sum(1 for r in results if r["verdict"] == "COMPLIANT")
        total = len(results)
        cards = "".join(
            f"<div style='display:flex; justify-content:space-between; "
            f"padding:8px; margin-bottom:6px; background:#1A1633; "
            f"border-radius:8px; border-left:3px solid "
            f"{'#10B981' if r['verdict']=='COMPLIANT' else '#EF4444'};'>"
            f"<span style='color:#eee; font-size:0.8rem'>{r['resource_id']}</span>"
            f"<span style='color:{'#10B981' if r['verdict']=='COMPLIANT' else '#EF4444'}; "
            f"font-size:0.8rem; font-weight:700'>{r['verdict']}</span>"
            f"</div>"
            for r in results
        )
        return ui.HTML(
            f"""
            <div style='margin-top:12px;'>
                <div style='color:#D4AF37; font-weight:700; '
                            'margin-bottom:8px; font-size:0.9rem;'>
                    {compliant}/{total} Compliant
                </div>
                {cards}
            </div>
            """
        )

    # Intelligence
    refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.refresh_btn)
    def _refresh() -> None:
        refresh_trigger.set(refresh_trigger() + 1)

    @reactive.calc
    def _kpi_data() -> tuple[float, float, float, int]:
        refresh_trigger()
        runs = _effective_log(100)
        if _USE_REAL_MODULES and db is not None:
            avg_mttr = db.avg_mttr()
            rag_rate = db.rag_hit_rate()
            kb = db.kb_count()
            compliant = sum(1 for e in runs if e.get("is_compliant"))
            total = len(runs)
            compliance_rate = (compliant / total * 100) if total else 0.0
            return (avg_mttr, rag_rate * 100, compliance_rate, kb)
        # Synthetic faux data on load
        if not runs:
            return (4.2, 87.0, 62.0, 24)
        compliant = sum(1 for e in runs if e.get("is_compliant"))
        total = len(runs)
        compliance_rate = (compliant / total * 100) if total else 62.0
        return (4.2, 87.0, compliance_rate, 24)

    @render.ui
    def kpi_mttr() -> Any:
        v = _kpi_data()[0]
        return ui.div(ui.div(f"{v:.1f}s", style="font-size: 1.25rem; font-weight: bold;"), ui.div("Avg MTTR", style="font-size: 12px; color: #666;"), class_="kpi-tile")

    @render.ui
    def kpi_rag() -> Any:
        v = _kpi_data()[1]
        return ui.div(ui.div(f"{v:.1f}%", style="font-size: 1.25rem; font-weight: bold;"), ui.div("RAG Hit Rate", style="font-size: 12px; color: #666;"), class_="kpi-tile")

    @render.ui
    def kpi_compliance() -> Any:
        v = _kpi_data()[2]
        return ui.div(ui.div(f"{v:.1f}%", style="font-size: 1.25rem; font-weight: bold;"), ui.div("Compliance Rate", style="font-size: 12px; color: #666;"), class_="kpi-tile")

    @render.ui
    def kpi_kb() -> Any:
        v = _kpi_data()[3]
        return ui.div(ui.div(str(v), style="font-size: 1.25rem; font-weight: bold;"), ui.div("KB Entries", style="font-size: 12px; color: #666;"), class_="kpi-tile")

    @render.ui
    def violation_chart():
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import io, base64

            types = ["Encryption", "Public Access", "Region",
                     "PHI Tag", "CMK"]
            counts = [4, 3, 2, 2, 1]
            colors = ["#EF4444", "#F97316", "#F97316",
                      "#EAB308", "#10B981"]

            fig, ax = plt.subplots(figsize=(5, 3))
            ax.barh(types, counts, color=colors)
            ax.set_xlabel("Count")
            ax.set_title("Violation Distribution")
            ax.set_facecolor("#1A1633")
            fig.set_facecolor("#1A1633")
            ax.tick_params(colors="white")
            ax.title.set_color("white")
            ax.xaxis.label.set_color("white")
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format="png",
                        facecolor="#1A1633", bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            b64 = base64.b64encode(buf.read()).decode()
            return ui.HTML(
                f'<img src="data:image/png;base64,{b64}" '
                f'style="width:100%; border-radius:8px;">'
            )
        except Exception as e:
            return ui.div(
                f"Chart error: {str(e)}",
                style="color:#aaa; padding:16px;"
            )

    # Sprint 6: Record run & History
    _record_run_msg: reactive.Value[str] = reactive.Value("")
    history_refresh_trigger: reactive.Value[int] = reactive.Value(0)

    @reactive.effect
    @reactive.event(input.record_run_btn)
    def _on_record_run() -> None:
        results = batch_results()
        if not results:
            _record_run_msg.set("No resources to record. Run batch first.")
            return
        tf = input.tf_upload()
        source_filename = tf[0]["name"] if tf and len(tf) > 0 else ""
        flags = active_policy_flags()
        policy_text = f"encryption={flags.get('encryption')} public={flags.get('public')} region={flags.get('region')}"
        run_id = None
        if write_run is not None:
            run_id = write_run(batch_results=results, source_filename=source_filename, policy_text=policy_text)
        if run_id:
            _record_run_msg.set(f"Run recorded (id: {str(run_id)[:8]}...)")
            history_refresh_trigger.set(history_refresh_trigger() + 1)
            # S17-02-A: Mirror the run as a cross-app finding (fire-and-forget)
            if _record_cross_app_finding is not None:
                try:
                    _record_cross_app_finding(
                        finding_type="audit_run",
                        title="Mobile audit run recorded",
                        description=f"Mobile audit run {str(run_id)[:8]} recorded with {len(results)} resources from {source_filename or 'unspecified source'}",
                        severity="info",
                        session_id=None,
                    )
                except Exception:
                    pass  # Fire-and-forget; never break UI on telemetry failure
        else:
            _record_run_msg.set("Supabase unavailable. Check SOVEREIGN_SUPABASE_URL and SOVEREIGN_SUPABASE_ANON_KEY.")

    @reactive.effect
    @reactive.event(input.history_refresh_btn)
    def _on_history_refresh() -> None:
        history_refresh_trigger.set(history_refresh_trigger() + 1)

    @render.ui
    def record_run_status() -> Any:
        msg = _record_run_msg()
        if not msg:
            return ui.div()
        color = "#28a745" if "recorded" in msg.lower() else "#dc3545"
        return ui.p(msg, style=f"color:{color}; margin:8px 0; font-size:14px;")

    @reactive.calc
    def _history_runs() -> list[dict[str, Any]]:
        history_refresh_trigger()
        if fetch_history is not None:
            return fetch_history(limit=50)
        return []

    _SYNTHETIC_HISTORY: list[dict[str, Any]] = [
        {"run_at": "2026-03-12 14:22", "total": 5, "compliance_rate": "60.0%", "avg_mttr": "3.8s", "trend": "−"},
        {"run_at": "2026-03-13 09:15", "total": 5, "compliance_rate": "80.0%", "avg_mttr": "2.1s", "trend": "↑"},
        {"run_at": "2026-03-14 11:45", "total": 5, "compliance_rate": "62.0%", "avg_mttr": "4.2s", "trend": "↓"},
    ]

    @render.ui
    def history_table() -> Any:
        import pandas as pd
        runs = _history_runs()
        if not runs:
            rows = _SYNTHETIC_HISTORY
        else:
            rows = []
            for r in runs:
                run_at = r.get("run_at", "")
                if run_at:
                    try:
                        if hasattr(run_at, "strftime"):
                            run_at = run_at.strftime("%Y-%m-%d %H:%M")
                        else:
                            run_at = str(run_at)[:19]
                    except Exception:
                        run_at = str(run_at)[:19]
                rate = r.get("compliance_rate", 0)
                mttr = r.get("avg_mttr_seconds", 0) or 0
                trend = r.get("trending", "stable")
                arrow = "↑" if trend == "up" else "↓" if trend == "down" else "−"
                rows.append({
                    "run_at": run_at,
                    "total": r.get("total_resources", 0),
                    "compliance_rate": f"{rate:.1f}%",
                    "avg_mttr": f"{float(mttr):.1f}s",
                    "trend": arrow,
                })
        df = pd.DataFrame(rows)
        return ui.HTML(df.to_html(index=False, classes="table", na_rep=""))

    @render.download(filename=lambda: f"sovereignshield_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    async def export_pdf():  # type: ignore[no-untyped-def]
        from pdf_report import generate_report
        results = batch_results()
        if not results:
            resources = active_resources()
            results = [
                {
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type,
                    "verdict": "NOT RUN",
                    "violations": 0,
                    "mttr_seconds": 0,
                }
                for r in resources
            ]
        flags = active_policy_flags()
        policy_text = (
            f"Encryption enforced: {flags['encryption']}\n"
            f"Public access enforced: {flags['public']}\n"
            f"Region enforced: {flags['region']}"
        )
        tf = input.tf_upload()
        source_filename = (
            tf[0]["name"] if tf and len(tf) > 0 else "synthetic demo data"
        )
        pdf_bytes = generate_report(
            batch_results=results,
            policy_text=policy_text,
            source_filename=source_filename,
        )
        yield pdf_bytes


app = App(app_ui, server, debug=True)