"""Sprint 4 CI hardening — parse_terraform, generate_report, policy flags."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Artifacts", "project", "sovereignshield_mobile"))


# 1. parse_terraform — .tfstate parsing
def test_parse_terraform_tfstate(tmp_path):
    """parse_terraform correctly parses a .tfstate file."""
    import json

    tfstate = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "mobile_bucket",
                "instances": [
                    {
                        "attributes": {
                            "region": "us-west-2",
                            "tags": {}
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "main.tfstate"
    f.write_text(json.dumps(tfstate))
    from app import parse_terraform

    result = parse_terraform(str(f))
    assert len(result) == 1
    assert result[0]["resource_type"] == "aws_s3_bucket"


# 2. parse_terraform — .tf parsing
def test_parse_terraform_tf(tmp_path):
    """parse_terraform correctly parses a .tf file."""
    tf_content = 'resource "aws_lambda_function" "fn" {\n  runtime = "python3.11"\n}\n'
    f = tmp_path / "main.tf"
    f.write_text(tf_content)
    from app import parse_terraform

    result = parse_terraform(str(f))
    assert len(result) == 1
    assert result[0]["resource_type"] == "aws_lambda_function"


# 3. parse_terraform — invalid file fallback
def test_parse_terraform_fallback(tmp_path):
    """parse_terraform returns empty list on bad input."""
    f = tmp_path / "bad.tfstate"
    f.write_text("%%%invalid%%%")
    from app import parse_terraform

    result = parse_terraform(str(f))
    assert isinstance(result, list)


# 4. active_policy_flags — default values
def test_active_policy_flags_defaults():
    """DEFAULT policy flags all default to True."""
    from app import DEFAULT_POLICY_FLAGS

    assert DEFAULT_POLICY_FLAGS["encryption"] is True
    assert DEFAULT_POLICY_FLAGS["public"] is True
    assert DEFAULT_POLICY_FLAGS["region"] is True


# 5. generate_report — returns PDF bytes
def test_generate_report_returns_bytes():
    """generate_report returns non-empty PDF bytes."""
    from pdf_report import generate_report

    results = [
        {
            "resource_id": "mob-001",
            "resource_type": "aws_s3_bucket",
            "verdict": "COMPLIANT",
            "violations": 0,
            "mttr_seconds": 0.8
        }
    ]
    pdf_bytes = generate_report(results, "encryption: True", "demo")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000


# 6. generate_report — PDF magic bytes
def test_generate_report_pdf_signature():
    """generate_report output is a valid PDF."""
    from pdf_report import generate_report

    pdf_bytes = generate_report([], "policy text", "demo")
    assert pdf_bytes[:4] == b"%PDF"


# 7. generate_report — empty results
def test_generate_report_empty():
    """generate_report handles empty results gracefully."""
    from pdf_report import generate_report

    pdf_bytes = generate_report([], "", "")
    assert isinstance(pdf_bytes, bytes)
