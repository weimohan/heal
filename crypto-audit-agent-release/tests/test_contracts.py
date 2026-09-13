from pydantic import ValidationError
import pytest

from cryptoaudit.contracts import (
    AgentAction,
    AuditSession,
    LocalFinding,
    ModelHypothesis,
    Severity,
    source_sha256,
)


def test_session_from_source_records_fingerprint_but_excludes_source_from_checkpoint():
    source = "print('hello')\n"
    session = AuditSession.from_source(source)

    assert session.source_sha256 == source_sha256(source)
    checkpoint = session.checkpoint_dict()
    assert "source" not in checkpoint
    assert "source_for_model" not in checkpoint


def test_local_finding_is_confirmed_and_has_stable_location():
    finding = LocalFinding(
        finding_id="CRYPTO-DES-001:4",
        rule_id="CRYPTO-DES-001",
        title="Deprecated DES cipher",
        severity=Severity.HIGH,
        confidence=0.98,
        line=4,
        end_line=4,
        evidence="DES.new",
        cwe="CWE-327",
        remediation="Migrate after compatibility review.",
        origin="policy",
    )
    assert finding.status == "confirmed"


def test_model_hypothesis_cannot_be_confirmed():
    hypothesis = ModelHypothesis(
        hypothesis_id="H-1",
        title="Possible fixed nonce",
        summary="A wrapper may reuse a nonce.",
        status="likely",
    )
    assert hypothesis.status in {"likely", "unknown"}
    with pytest.raises(ValidationError):
        ModelHypothesis(
            hypothesis_id="H-2",
            title="Invalid state",
            summary="A model hypothesis cannot be confirmed directly.",
            status="confirmed",
        )


def test_action_requires_payload_for_call_or_question():
    with pytest.raises(ValidationError):
        AgentAction(action="call_tool")
    with pytest.raises(ValidationError):
        AgentAction(action="ask_user")
