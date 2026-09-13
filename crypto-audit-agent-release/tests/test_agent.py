from cryptoaudit.agent import AgentOrchestrator
from cryptoaudit.contracts import AgentAction, AuditSession, SessionStatus
from cryptoaudit.provider import OfflineProvider, ScriptedProvider


SOURCE = '''
from Crypto.Cipher import DES
import hashlib
api_key = "secret-value"
def encrypt(data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)
digest = hashlib.md5(data).hexdigest()
'''


def test_agent_rejects_early_finish_and_continues_after_gate_observation():
    provider = ScriptedProvider(
        [
            AgentAction(action="finish", summary="too early"),
            AgentAction(action="call_tool", tool_name="inventory_algorithms"),
            AgentAction(action="call_tool", tool_name="scan_python_source"),
            AgentAction(action="call_tool", tool_name="propose_patch"),
            AgentAction(action="call_tool", tool_name="verify_patch"),
            AgentAction(action="finish", summary="verified"),
        ]
    )
    session = AuditSession.from_source('import hashlib\napi_key = "secret-value"\ndigest = hashlib.md5(data).hexdigest()\n')
    result = AgentOrchestrator(provider=provider, use_langgraph=False, max_steps=8).start(session)

    assert result.status == SessionStatus.COMPLETED_WITH_REVIEW
    assert any(item.tool_name == "EvidenceGate" and item.error == "finish_rejected" for item in result.observations)
    assert result.local_findings
    assert result.model_hypotheses == []


def test_agent_keeps_model_hypothesis_separate():
    provider = ScriptedProvider(
        [
            AgentAction(action="call_tool", tool_name="inventory_algorithms"),
            AgentAction(action="call_tool", tool_name="scan_python_source"),
            AgentAction(action="call_tool", tool_name="verify_patch"),
            AgentAction(
                action="finish",
                summary="there is an uncertain issue",
                hypotheses=[
                    {
                        "hypothesis_id": "H-1",
                        "title": "Possible fixed nonce",
                        "summary": "The nonce may be reused by a caller.",
                        "status": "unknown",
                        "requested_evidence": ["caller lifecycle"],
                    }
                ],
            ),
        ]
    )
    result = AgentOrchestrator(provider=provider, use_langgraph=False, max_steps=6).start(AuditSession.from_source("from Crypto.Cipher import AES\nAES.new(k, AES.MODE_GCM)\n"))
    assert result.status == SessionStatus.COMPLETED_WITH_REVIEW
    assert result.model_hypotheses[0].status == "unknown"
    assert result.local_findings == []


def test_agent_asks_and_resumes_human_approval():
    provider = ScriptedProvider(
        [
            AgentAction(action="call_tool", tool_name="inventory_algorithms"),
            AgentAction(action="call_tool", tool_name="scan_python_source"),
            AgentAction(action="call_tool", tool_name="propose_patch"),
            AgentAction(action="ask_user", question="approve?", question_kind="approval"),
            AgentAction(action="call_tool", tool_name="verify_patch"),
            AgentAction(action="finish", summary="approved and verified"),
        ]
    )
    orchestrator = AgentOrchestrator(provider=provider, use_langgraph=False, max_steps=8)
    session = orchestrator.start(AuditSession.from_source("api_key = 'value'\n"))
    assert session.status == SessionStatus.AWAITING_USER
    session = orchestrator.resume(session, "批准")
    assert session.status == SessionStatus.COMPLETED


def test_provider_failure_preserves_degraded_local_result():
    provider = ScriptedProvider([])
    result = AgentOrchestrator(provider=provider, use_langgraph=False).start(AuditSession.from_source(SOURCE))
    assert result.status == SessionStatus.DEGRADED
    assert result.local_findings
    assert "preserved offline result" in result.completion_reason


def test_optional_langgraph_runtime_wraps_the_same_dynamic_loop():
    result = AgentOrchestrator(provider=OfflineProvider(), max_steps=12).start(
        AuditSession.from_source("from Crypto.Cipher import AES\nAES.new(k, AES.MODE_GCM)\n")
    )
    assert result.status == SessionStatus.COMPLETED
    assert result.step_count == 5
    assert result.decision_source == "offline"
