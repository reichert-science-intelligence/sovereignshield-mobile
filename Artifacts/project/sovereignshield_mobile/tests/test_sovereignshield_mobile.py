"""SovereignShield Mobile test suite — OPA eval, tf_parser, audit_db, agents, charts, retriever."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# Ensure Artifacts is on path for project.sovereignshield_mobile imports
_artifacts = Path(__file__).resolve().parents[3]
if str(_artifacts) not in sys.path:
    sys.path.insert(0, str(_artifacts))

# Synthetic RESOURCES list — no external calls
RESOURCES: list[object] = []


# ── OPA eval: 5 policies + compliant resource ──────────────────────────────────


@pytest.mark.unit
def test_opa_eval_data_residency_violation() -> None:
    """Region outside us-east-1/us-gov-east-1 triggers data_residency violation."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="s3-eu",
            resource_type="aws_s3_bucket",
            region="eu-central-1",
            encryption_enabled=True,
            cmk_key_id="arn:aws:kms:us-east-1:123:key/x",
            is_public=False,
            tags={"DataClass": "PHI"},
        ),
    ]
    violations = evaluate(resources)
    assert any(v["violation_type"] == "data_residency" for v in violations)


@pytest.mark.unit
def test_opa_eval_cmk_encryption_violation() -> None:
    """S3/RDS without CMK encryption triggers hipaa_encryption or cmk_required."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="s3-no-enc",
            resource_type="aws_s3_bucket",
            region="us-east-1",
            encryption_enabled=False,
            cmk_key_id=None,
            is_public=False,
            tags={"DataClass": "PHI"},
        ),
    ]
    violations = evaluate(resources)
    assert any(
        v["violation_type"] in ("hipaa_encryption", "cmk_required")
        for v in violations
    )


@pytest.mark.unit
def test_opa_eval_phi_tag_violation() -> None:
    """Missing DataClass=PHI tag triggers phi_tagging violation."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="s3-staging",
            resource_type="aws_s3_bucket",
            region="us-east-1",
            encryption_enabled=True,
            cmk_key_id="arn:aws:kms:us-east-1:123:key/x",
            is_public=False,
            tags={"Environment": "staging"},
        ),
    ]
    violations = evaluate(resources)
    assert any(v["violation_type"] == "phi_tagging" for v in violations)


@pytest.mark.unit
def test_opa_eval_is_public_violation() -> None:
    """is_public=True triggers public_exposure violation."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="rds-public",
            resource_type="aws_db_instance",
            region="us-east-1",
            encryption_enabled=True,
            cmk_key_id="arn:aws:kms:us-east-1:123:key/x",
            is_public=True,
            tags={"DataClass": "PHI"},
        ),
    ]
    violations = evaluate(resources)
    assert any(v["violation_type"] == "public_exposure" for v in violations)


@pytest.mark.unit
def test_opa_eval_approved_regions_compliant() -> None:
    """us-east-1 and us-gov-east-1 are approved — no data_residency for compliant resource."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="s3-compliant",
            resource_type="aws_s3_bucket",
            region="us-east-1",
            encryption_enabled=True,
            cmk_key_id="arn:aws:kms:us-east-1:123:key/x",
            is_public=False,
            tags={"DataClass": "PHI"},
        ),
    ]
    violations = evaluate(resources)
    assert not any(v["violation_type"] == "data_residency" for v in violations)


@pytest.mark.unit
def test_opa_eval_fully_compliant_returns_no_violations() -> None:
    """Fully compliant resource (region, encryption, CMK, PHI tag, not public) returns empty."""
    from project.sovereignshield_mobile.core.opa_eval import evaluate
    from project.sovereignshield_mobile.models import CloudResource

    resources = [
        CloudResource(
            resource_id="s3-phi-001",
            resource_type="aws_s3_bucket",
            region="us-east-1",
            encryption_enabled=True,
            cmk_key_id="arn:aws:kms:us-east-1:123:key/abc",
            is_public=False,
            tags={"DataClass": "PHI", "Environment": "prod"},
        ),
    ]
    violations = evaluate(resources)
    assert len(violations) == 0


# ── tf_parser ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_tf_parser_parse_tfstate_dict_valid() -> None:
    """parse_tfstate_dict with valid state dict returns list of LegacyCloudResource."""
    from project.sovereignshield_mobile.core.tf_parser import parse_tfstate_dict

    state: dict[str, Any] = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "test_bucket",
                "instances": [
                    {"attributes": {"id": "s3-test", "region": "us-east-1"}},
                ],
            },
        ],
    }
    result = parse_tfstate_dict(state)
    assert len(result) == 1
    assert result[0].type == "aws_s3_bucket"
    assert result[0].name == "test_bucket"
    assert result[0].attributes.get("id") == "s3-test"


@pytest.mark.unit
def test_tf_parser_parse_tfstate_dict_missing_fields() -> None:
    """parse_tfstate_dict with missing resources returns empty list."""
    from project.sovereignshield_mobile.core.tf_parser import parse_tfstate_dict

    assert parse_tfstate_dict({}) == []
    assert parse_tfstate_dict({"resources": []}) == []


# ── AuditDB ───────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_audit_db_instantiates() -> None:
    """AuditDB instantiates and is_connected is bool."""
    from project.sovereignshield_mobile.core.audit_db import AuditDB, db

    assert isinstance(db, AuditDB)
    assert isinstance(db.is_connected, bool)


@pytest.mark.unit
def test_audit_db_insert_returns_bool() -> None:
    """insert returns True (Supabase) or False (local fallback)."""
    from project.sovereignshield_mobile.core.audit_db import db

    event = {
        "task_id": "test-task-001",
        "timestamp": "2025-03-10T12:00:00",
        "violation_type": "data_residency",
        "resource_id": "s3-test",
        "planner_output": "",
        "worker_output": "",
        "reviewer_verdict": "APPROVED",
        "reviewer_notes": "",
        "is_compliant": True,
        "mttr_seconds": 1.0,
        "tokens_used": 0,
        "rag_hit": False,
    }
    result = db.insert(event)
    assert isinstance(result, bool)


@pytest.mark.unit
def test_audit_db_fetch_recent_returns_list() -> None:
    """fetch_recent returns list of dicts."""
    from project.sovereignshield_mobile.core.audit_db import db

    runs = db.fetch_recent(limit=5)
    assert isinstance(runs, list)
    for r in runs:
        assert isinstance(r, dict)


# ── agents ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_planner_run_returns_non_empty_fix_strategy() -> None:
    """planner.run() returns PlannerResult with non-empty fix_strategy (mocked)."""
    from project.sovereignshield_mobile.agents.planner import PlannerAgent

    violation = {
        "resource_id": "s3-test",
        "violation_type": "data_residency",
        "regulation_cited": "HIPAA",
        "detail": "Region not allowed",
    }
    with patch.dict("os.environ", {}, clear=False):
        planner = PlannerAgent()
        result = planner.run(violation)
    assert result.fix_strategy != ""
    assert isinstance(result.fix_strategy, str)


@pytest.mark.unit
def test_worker_run_returns_non_empty_hcl_code() -> None:
    """worker.run() returns WorkerResult with non-empty hcl_code (mocked)."""
    from project.sovereignshield_mobile.agents.planner import PlannerResult
    from project.sovereignshield_mobile.agents.worker import WorkerAgent

    plan = PlannerResult(
        task_id="t-001",
        resource_id="s3-test",
        violation_type="data_residency",
        regulation_cited="HIPAA",
        fix_strategy="Add encryption",
        priority="HIGH",
        rag_hit=False,
        rag_source=None,
        tokens_used=0,
    )
    with patch.dict("os.environ", {}, clear=False):
        worker = WorkerAgent()
        result = worker.run(plan)
    assert len(result.hcl_code) > 0


@pytest.mark.unit
def test_reviewer_run_returns_approved_rejected_or_needs_revision() -> None:
    """reviewer.run() returns ReviewerResult with verdict in APPROVED/REJECTED/NEEDS_REVISION."""
    from project.sovereignshield_mobile.agents.planner import PlannerResult
    from project.sovereignshield_mobile.agents.reviewer import ReviewerAgent
    from project.sovereignshield_mobile.agents.worker import WorkerResult

    plan = PlannerResult(
        task_id="t",
        resource_id="s3",
        violation_type="data_residency",
        regulation_cited="HIPAA",
        fix_strategy="Encrypt",
        priority="HIGH",
        rag_hit=False,
        rag_source=None,
        tokens_used=0,
    )
    work = WorkerResult(
        task_id="t",
        resource_id="s3",
        violation_type="data_residency",
        hcl_code='resource "aws_s3_bucket_server_side_encryption_configuration" "x" {}',
        hcl_line_count=1,
        tokens_used=0,
    )
    with patch.dict("os.environ", {}, clear=False):
        reviewer = ReviewerAgent()
        result = reviewer.run(plan, work)
    assert result.verdict in ("APPROVED", "REJECTED", "NEEDS_REVISION")


# ── charts (plotnine) ─────────────────────────────────────────────────────────


@pytest.mark.unit
def test_compliance_heatmap_returns_ggplot() -> None:
    """compliance_heatmap returns plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield_mobile.core.charts import compliance_heatmap

    runs = [
        {"resource_id": "s3-x", "violation_type": "data_residency", "is_compliant": True},
    ]
    p = compliance_heatmap(runs)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__


@pytest.mark.unit
def test_mttr_trend_returns_ggplot() -> None:
    """mttr_trend returns plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield_mobile.core.charts import mttr_trend

    runs = [
        {"timestamp": "2025-03-09T10:00:00", "mttr_seconds": 4.2},
    ]
    p = mttr_trend(runs, limit=20)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__


@pytest.mark.unit
def test_violation_donut_returns_ggplot() -> None:
    """violation_donut returns plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield_mobile.core.charts import violation_donut

    runs = [{"severity": "HIGH"}]
    p = violation_donut(runs)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__


@pytest.mark.unit
def test_kb_growth_returns_ggplot() -> None:
    """kb_growth returns plotnine ggplot object."""
    pytest.importorskip("plotnine")
    from project.sovereignshield_mobile.core.charts import kb_growth

    runs = [{"timestamp": "2025-03-09T10:00:00", "is_compliant": True}]
    p = kb_growth(runs)
    assert p is not None
    assert hasattr(p, "draw") or "ggplot" in type(p).__name__


# ── retriever ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_embed_and_store_runs_without_error() -> None:
    """embed_and_store runs without raising (returns bool)."""
    from project.sovereignshield_mobile.rag.retriever import embed_and_store

    result = embed_and_store("test violation", "resource \"x\" {}", {"key": "val"})
    assert isinstance(result, bool)


@pytest.mark.unit
def test_retrieve_similar_returns_tuple() -> None:
    """retrieve_similar returns tuple (str|None, float)."""
    from project.sovereignshield_mobile.rag.retriever import retrieve_similar

    text, score = retrieve_similar("data residency violation")
    assert text is None or isinstance(text, str)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
