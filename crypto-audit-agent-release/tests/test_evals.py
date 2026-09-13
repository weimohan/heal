import json
from pathlib import Path

from evals.runner import evaluate_dataset, score_session
from cryptoaudit.baseline import BaselineRunner


def test_evaluator_reports_quality_and_security_metrics(tmp_path):
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            [
                {
                    "case_id": "mini",
                    "source": 'api_key = "mini-secret"\n',
                    "expected_rules": ["CRYPTO-SECRET-001"],
                    "expected_algorithms": [],
                    "secret_literals": ["mini-secret"],
                }
            ]
        ),
        encoding="utf-8",
    )
    result = evaluate_dataset(dataset, mode="baseline")
    assert result["summary"]["f1"] == 1.0
    assert result["summary"]["secret_leakage_cases"] == 0


def test_evaluator_preserves_dataset_provenance_and_negative_cases(tmp_path):
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {
                "dataset_id": "test-fixture-v1",
                "dataset_type": "hand_authored_synthetic",
                "cases": [
                    {
                        "case_id": "safe",
                        "source": "value = 1\n",
                        "expected_rules": [],
                        "expected_algorithms": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_dataset(dataset, mode="baseline")

    assert result["dataset"]["dataset_id"] == "test-fixture-v1"
    assert len(result["dataset"]["sha256"]) == 64
    assert result["summary"]["negative_case_pass_rate"] == 1.0
    assert result["summary"]["unknown_metric_applicable"] is False


def test_score_session_counts_false_positive():
    session = BaselineRunner().run("from Crypto.Cipher import DES3\nDES3.new(k)\n")
    score = score_session(session, {"case_id": "wrong", "expected_rules": [], "expected_algorithms": []})
    assert score["false_positive"] == 1


def test_targeted_v2_dataset_covers_extended_rules_and_safe_negatives():
    dataset = Path(__file__).parents[1] / "evals" / "targeted_v2.json"
    result = evaluate_dataset(dataset, mode="baseline")
    assert result["summary"]["recall"] == 1.0
    assert result["summary"]["precision"] == 1.0
    assert result["summary"]["negative_case_pass_rate"] == 1.0
    assert result["summary"]["secret_leakage_cases"] == 0
