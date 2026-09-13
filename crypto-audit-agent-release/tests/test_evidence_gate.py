from cryptoaudit.contracts import AuditSession
from cryptoaudit.tools import ToolRegistry
from cryptoaudit.verifier import EvidenceGate, refresh_evidence_state


def _session():
    return AuditSession.from_source('from Crypto.Cipher import DES\ncipher = DES.new(key)\n')


def test_finish_is_rejected_before_required_tools_run():
    decision = EvidenceGate().evaluate(_session())
    assert not decision.accepted
    assert "algorithm_inventory" in decision.missing_evidence
    assert "verification" in decision.missing_evidence


def test_gate_accepts_complete_local_evidence_and_verification():
    session = _session()
    registry = ToolRegistry(session.source, approval="approved")
    for name in ("inventory_algorithms", "scan_python_source", "verify_patch"):
        result = registry.call(name)
        from cryptoaudit.contracts import Observation

        session.observations.append(
            Observation(
                observation_id=f"O-{name}",
                tool_name=name,
                success=result.success,
                payload=result.payload,
                evidence_ids=result.evidence_ids,
                duration_ms=result.duration_ms,
                error=result.error,
            )
        )
        if name == "inventory_algorithms":
            session.algorithms = [item for item in session.algorithms]
            session.algorithms = [
                __import__("cryptoaudit.contracts", fromlist=["AlgorithmUse"]).AlgorithmUse.model_validate(row)
                for row in result.payload["algorithms"]
            ]
        if name == "scan_python_source":
            from cryptoaudit.contracts import LocalFinding

            session.local_findings = [LocalFinding.model_validate(row) for row in result.payload["findings"]]
        if name == "verify_patch":
            from cryptoaudit.contracts import PatchProposal, VerificationResult

            session.patch = PatchProposal.model_validate(result.payload["proposal"])
            session.verification = VerificationResult.model_validate(result.payload["verification"])
            session.human_decision = "approved"
    refresh_evidence_state(session)
    decision = EvidenceGate().evaluate(session)
    assert decision.accepted


def test_gate_requires_human_decision_for_legacy_migration():
    session = _session()
    session.evidence.inventory_complete = True
    session.evidence.local_scan_complete = True
    session.evidence.verification_complete = True
    session.patch = __import__("cryptoaudit.contracts", fromlist=["PatchProposal"]).PatchProposal(
        status="requires_review",
        rationale="compatibility",
        requires_human_review=True,
    )
    session.evidence.patch_integrity_complete = True
    session.evidence.claim_links_complete = True
    decision = EvidenceGate().evaluate(session)
    assert not decision.accepted
    assert "human_review_decision" in decision.missing_evidence
