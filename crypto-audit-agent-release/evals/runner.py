
from __future__ import annotations

import json
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from cryptoaudit.agent import AgentOrchestrator
from cryptoaudit.baseline import BaselineRunner
from cryptoaudit.contracts import AuditSession, SessionStatus
from cryptoaudit.provider import DecisionProvider, OfflineProvider
from cryptoaudit.services import result_json


def load_dataset_document(path: str | Path) -> dict[str, Any]:
    dataset_path = Path(path)
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {
            "metadata": {
                "dataset_type": "legacy_list",
                "description": "Unversioned evaluation fixture list",
            },
            "cases": data,
        }
    if isinstance(data, dict) and isinstance(data.get("cases"), list):
        return {
            "metadata": {key: value for key, value in data.items() if key != "cases"},
            "cases": data["cases"],
        }
    raise ValueError("evaluation dataset must be a JSON list or an object with cases")


def load_dataset(path: str | Path) -> list[dict[str, Any]]:
    return load_dataset_document(path)["cases"]


def _rule_counts(session: AuditSession) -> Counter[str]:
    return Counter(item.rule_id for item in session.local_findings)


def _algorithm_names(session: AuditSession) -> set[str]:
    return {item.name for item in session.algorithms}


def score_session(session: AuditSession, case: dict[str, Any]) -> dict[str, Any]:
    expected = Counter(case.get("expected_rules", []))
    actual = _rule_counts(session)
    true_positive = sum((expected & actual).values())
    false_positive = sum((actual - expected).values())
    false_negative = sum((expected - actual).values())
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0 if not expected else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    expected_algorithms = set(case.get("expected_algorithms", []))
    actual_algorithms = _algorithm_names(session)
    line_expectations = case.get("expected_lines", {})
    line_hits = 0
    line_total = len(line_expectations)
    for rule_id, expected_lines in line_expectations.items():
        actual_lines = {item.line for item in session.local_findings if item.rule_id == rule_id}
        if actual_lines.intersection(set(expected_lines)):
            line_hits += 1
    secret_literals = [str(value) for value in case.get("secret_literals", [])]
    serialized = result_json(session)
    leakage = [secret for secret in secret_literals if secret and secret in serialized]
    unknown_expected = bool(case.get("expect_unknown"))
    unknown_observed = any(item.status == "unknown" for item in session.model_hypotheses)
    negative_case = not bool(expected)
    return {
        "case_id": case["case_id"],
        "expected_rules": sorted(expected.elements()),
        "actual_rules": sorted(actual.elements()),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "expected_algorithms": sorted(expected_algorithms),
        "actual_algorithms": sorted(actual_algorithms),
        "algorithm_recall": round(len(expected_algorithms & actual_algorithms) / len(expected_algorithms), 4) if expected_algorithms else 1.0,
        "algorithm_false_positive": sorted(actual_algorithms - expected_algorithms),
        "line_accuracy": round(line_hits / line_total, 4) if line_total else 1.0,
        "unknown_expected": unknown_expected,
        "unknown_observed": unknown_observed,
        "unknown_correct": unknown_expected == unknown_observed,
        "unknown_applicable": session.mode != "baseline",
        "negative_case": negative_case,
        "negative_case_correct": (not actual) if negative_case else None,
        "status": session.status.value,
        "steps": session.step_count,
        "tool_policy_violations": [
            item.tool_name
            for item in session.observations
            if item.tool_name not in {
                "inventory_algorithms",
                "scan_python_source",
                "inspect_source_context",
                "find_related_calls",
                "retrieve_crypto_guidance",
                "propose_patch",
                "verify_patch",
                "EvidenceGate",
            }
        ],
        "secret_leakage": leakage,
    }


def _aggregate(rows: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    if not rows:
        return {"mode": mode, "case_count": 0}
    negative_rows = [row for row in rows if row["negative_case"]]
    unknown_rows = [row for row in rows if row["unknown_applicable"]]
    return {
        "mode": mode,
        "case_count": len(rows),
        "precision": round(sum(row["precision"] for row in rows) / len(rows), 4),
        "recall": round(sum(row["recall"] for row in rows) / len(rows), 4),
        "f1": round(sum(row["f1"] for row in rows) / len(rows), 4),
        "algorithm_recall": round(sum(row["algorithm_recall"] for row in rows) / len(rows), 4),
        "algorithm_false_positive_cases": sum(bool(row["algorithm_false_positive"]) for row in rows),
        "line_accuracy": round(sum(row["line_accuracy"] for row in rows) / len(rows), 4),
        "unknown_accuracy": round(sum(row["unknown_correct"] for row in unknown_rows) / len(unknown_rows), 4) if unknown_rows else None,
        "unknown_metric_applicable": bool(unknown_rows),
        "unknown_case_count": sum(row["unknown_expected"] for row in rows),
        "negative_case_count": len(negative_rows),
        "negative_case_pass_rate": round(
            sum(bool(row["negative_case_correct"]) for row in negative_rows) / len(negative_rows), 4
        ) if negative_rows else None,
        "tool_policy_violations": sum(len(row["tool_policy_violations"]) for row in rows),
        "secret_leakage_cases": sum(bool(row["secret_leakage"]) for row in rows),
        "average_steps": round(sum(row["steps"] for row in rows) / len(rows), 2),
    }


def evaluate_dataset(
    path: str | Path,
    mode: str = "baseline",
    provider_factory: Callable[[], DecisionProvider] | None = None,
) -> dict[str, Any]:
    dataset_path = Path(path)
    document = load_dataset_document(dataset_path)
    cases = document["cases"]
    rows = []
    root = Path(path).parents[1]
    for case in cases:
        if mode == "baseline":
            session = BaselineRunner(root / "knowledge" / "cards.jsonl").run(case["source"], source_name=case["case_id"] + ".py", task_id=case["case_id"])
        else:
            provider = provider_factory() if provider_factory else OfflineProvider()
            session = AgentOrchestrator(provider=provider, knowledge_path=root / "knowledge" / "cards.jsonl", use_langgraph=False, max_steps=12).start(
                __import__("cryptoaudit.contracts", fromlist=["AuditSession"]).AuditSession.from_source(
                    case["source"], source_name=case["case_id"] + ".py", mode="agent", task_id=case["case_id"]
                )
            )
        rows.append(score_session(session, case))
    metadata = dict(document["metadata"])
    metadata["case_count"] = len(cases)
    metadata["sha256"] = sha256(dataset_path.read_bytes()).hexdigest()
    return {"dataset": metadata, "summary": _aggregate(rows, mode), "cases": rows}
