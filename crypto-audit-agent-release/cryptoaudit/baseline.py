"""Deterministic offline comparator for the dynamic Agent."""

from __future__ import annotations

import time
from pathlib import Path

from .agent import _observation_from_result, apply_tool_result
from .contracts import AuditSession, SessionStatus, TraceEvent
from .knowledge import KnowledgeBase
from .tools import ToolRegistry
from .verifier import refresh_evidence_state


class BaselineRunner:
    """A transparent fixed sequence used as an experiment baseline."""

    def __init__(self, knowledge_path: str | Path = "knowledge/cards.jsonl"):
        self.knowledge_path = Path(knowledge_path)
        if not self.knowledge_path.is_absolute():
            project_path = Path(__file__).resolve().parents[1] / self.knowledge_path
            if project_path.exists():
                self.knowledge_path = project_path

    def run(self, source: str, source_name: str = "inline.py", task_id: str | None = None) -> AuditSession:
        session = AuditSession.from_source(source, source_name=source_name, task_id=task_id, mode="baseline")
        session.decision_source = "baseline"
        registry = ToolRegistry(source, knowledge=KnowledgeBase(self.knowledge_path))
        stages = ["inventory_algorithms", "scan_python_source"]
        for name in stages:
            started = time.perf_counter()
            result = registry.call(name)
            session.step_count += 1
            session.observations.append(_observation_from_result(session.step_count, name, result))
            apply_tool_result(session, name, result)
            session.trace.append(
                TraceEvent(
                    actor="BaselineRunner",
                    action=name,
                    detail="fixed baseline stage",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            )
        if session.local_findings:
            query = "\n".join(sorted({item.title for item in session.local_findings}))
            started = time.perf_counter()
            result = registry.call("retrieve_crypto_guidance", {"query": query})
            session.step_count += 1
            session.observations.append(_observation_from_result(session.step_count, "retrieve_crypto_guidance", result))
            apply_tool_result(session, "retrieve_crypto_guidance", result)
            session.trace.append(
                TraceEvent(
                    actor="BaselineRunner",
                    action="retrieve_crypto_guidance",
                    detail="fixed local knowledge stage",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            )
        for name in ("propose_patch", "verify_patch"):
            started = time.perf_counter()
            result = registry.call(name)
            session.step_count += 1
            session.observations.append(_observation_from_result(session.step_count, name, result))
            apply_tool_result(session, name, result)
            session.trace.append(
                TraceEvent(
                    actor="BaselineRunner",
                    action=name,
                    detail="fixed baseline stage",
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            )
        refresh_evidence_state(session)
        session.phase = "reported"
        session.status = SessionStatus.COMPLETED_WITH_REVIEW if session.patch and session.patch.requires_human_review else SessionStatus.COMPLETED
        session.completion_reason = "Offline deterministic baseline completed."
        return session
