import json

import pytest

from cryptoaudit.baseline import BaselineRunner
from cryptoaudit.contracts import AuditSession, Observation
from cryptoaudit.services import compare_sessions, load_checkpoint, render_markdown, result_json, save_checkpoint


def test_checkpoint_and_report_redact_source_values(tmp_path):
    session = BaselineRunner().run('api_key = "do-not-persist"\n')
    path = save_checkpoint(session, tmp_path)
    raw = path.read_text(encoding="utf-8")
    assert "do-not-persist" not in raw
    assert '"source"' not in raw
    assert "<REDACTED>" in raw or "api_key" not in raw
    report = render_markdown(session)
    assert "do-not-persist" not in report
    assert "<REDACTED>" in report or "api_key" not in report


def test_checkpoint_requires_same_source(tmp_path):
    session = BaselineRunner().run("print('one')\n")
    path = save_checkpoint(session, tmp_path)
    with pytest.raises(ValueError):
        load_checkpoint("print('two')\n", path)


def test_checkpoint_removes_source_context_and_patch_code(tmp_path):
    session = AuditSession.from_source('api_key = "checkpoint-secret"\n')
    session.observations.append(
        Observation(
            observation_id="O-1",
            tool_name="inspect_source_context",
            success=True,
            payload={"context": 'api_key = "checkpoint-secret"'},
            evidence_ids=["E-1"],
            duration_ms=1,
        )
    )
    path = save_checkpoint(session, tmp_path)
    raw = path.read_text(encoding="utf-8")
    assert "checkpoint-secret" not in raw
    assert "<omitted from checkpoint>" in raw


def test_result_json_contains_separate_provenance_sections():
    session = BaselineRunner().run("from Crypto.Cipher import DES3\nDES3.new(k)\n")
    data = json.loads(result_json(session))
    assert "local_findings" in data
    assert "model_hypotheses" in data
    assert "report_markdown" in data


def test_result_and_comparison_keep_decision_source_visible():
    baseline = BaselineRunner().run("print('safe')\n")
    agent = AuditSession.from_source("print('safe')\n")
    agent.decision_source = "offline"

    data = json.loads(result_json(agent))
    comparison = compare_sessions(baseline, agent)

    assert data["decision_source"] == "offline"
    assert "决策来源：`offline`" in data["report_markdown"]
    assert comparison["baseline_decision_source"] == "baseline"
    assert comparison["agent_decision_source"] == "offline"
