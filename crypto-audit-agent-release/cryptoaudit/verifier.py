"""Independent verification and deterministic completion gate."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import AuditSession, LocalFinding, PatchProposal, VerificationResult, source_sha256
from .tools import apply_patch_to_source, scan_python_source


def verify_source(
    source: str,
    findings: list[LocalFinding],
    proposal: PatchProposal,
    human_decision: str = "",
) -> VerificationResult:
    before = source_sha256(source)
    evidence = [f"E-VERIFY-BEFORE:{before}", f"E-FINDINGS-BEFORE:{len(findings)}"]
    if proposal.requires_human_review and human_decision != "approved":
        conclusion = "Human review is required before applying this compatibility-sensitive repair."
        if human_decision == "rejected":
            conclusion = "Human review rejected the repair; original source was preserved."
        evidence.append("E-VERIFY:NO-AUTO-PATCH")
        return VerificationResult(
            patch_applied=False,
            remaining_findings=findings,
            conclusion=conclusion,
            source_sha256_before=before,
            source_sha256_after=before,
            rescan_completed=True,
            evidence_ids=evidence,
        )
    if proposal.status != "proposed":
        evidence.append("E-VERIFY:NO-PATCH")
        return VerificationResult(
            patch_applied=False,
            remaining_findings=findings,
            conclusion="No automatic patch was applicable; the source review is complete.",
            source_sha256_before=before,
            source_sha256_after=before,
            rescan_completed=True,
            evidence_ids=evidence,
        )
    try:
        patched = apply_patch_to_source(source, proposal)
    except ValueError as exc:
        evidence.append("E-VERIFY:PATCH-REJECTED")
        return VerificationResult(
            patch_applied=False,
            remaining_findings=findings,
            conclusion=f"Patch validation failed: {exc}",
            source_sha256_before=before,
            source_sha256_after=before,
            rescan_completed=False,
            evidence_ids=evidence,
        )
    remaining = scan_python_source(patched)
    remaining_ids = {item.finding_id for item in remaining}
    resolved = [item.finding_id for item in findings if item.finding_id not in remaining_ids]
    after = source_sha256(patched)
    evidence.extend([f"E-VERIFY-AFTER:{after}", f"E-FINDINGS-AFTER:{len(remaining)}", "E-VERIFY:RESCAN"])
    return VerificationResult(
        patch_applied=True,
        resolved_finding_ids=resolved,
        remaining_findings=remaining,
        conclusion="Verification completed with no remaining findings." if not remaining else "Verification completed; residual findings require review.",
        source_sha256_before=before,
        source_sha256_after=after,
        rescan_completed=True,
        evidence_ids=evidence,
    )


@dataclass(frozen=True)
class GateDecision:
    accepted: bool
    missing_evidence: list[str]
    reason: str


class EvidenceGate:
    """A provider's finish request is accepted only after these local checks."""

    def evaluate(self, session: AuditSession) -> GateDecision:
        missing: list[str] = []
        if source_sha256(session.source) != session.source_sha256:
            missing.append("source_fingerprint")
        if not session.evidence.inventory_complete:
            missing.append("algorithm_inventory")
        if not session.evidence.local_scan_complete:
            missing.append("local_scan")
        if not session.evidence.claim_links_complete:
            missing.append("claim_evidence_links")
        if not session.local_findings and not session.evidence.local_scan_complete:
            missing.append("local_findings_or_empty_scan")
        if any(not finding.evidence_ids for finding in session.local_findings):
            missing.append("finding_evidence_links")
        if any(not hypothesis.evidence_ids for hypothesis in session.model_hypotheses):
            missing.append("hypothesis_evidence_links")
        if not session.evidence.verification_complete:
            missing.append("verification")
        proposal = session.patch
        if proposal and proposal.status == "proposed":
            if not session.evidence.patch_integrity_complete:
                missing.append("patch_integrity_and_rescan")
        if proposal and proposal.requires_human_review and session.human_decision not in {"approved", "rejected"}:
            missing.append("human_review_decision")
        unique_missing = list(dict.fromkeys(missing))
        if unique_missing:
            return GateDecision(False, unique_missing, "Finish rejected until required evidence is present.")
        return GateDecision(True, [], "Required evidence is complete.")


def refresh_evidence_state(session: AuditSession) -> None:
    tool_names = {item.tool_name for item in session.observations if item.success}
    session.evidence.source_fingerprint = source_sha256(session.source) == session.source_sha256
    session.evidence.inventory_complete = "inventory_algorithms" in tool_names
    session.evidence.local_scan_complete = "scan_python_source" in tool_names
    session.evidence.claim_links_complete = all(bool(item.evidence_ids) for item in session.local_findings)
    session.evidence.verification_complete = bool(session.verification and session.verification.rescan_completed)
    session.evidence.patch_integrity_complete = bool(
        not session.patch
        or session.patch.status != "proposed"
        or (
            session.verification
            and session.verification.patch_applied
            and session.verification.source_sha256_before == session.source_sha256
            and session.verification.source_sha256_after
        )
    )
    session.evidence.human_review_complete = not bool(session.patch and session.patch.requires_human_review) or session.human_decision in {"approved", "rejected"}
