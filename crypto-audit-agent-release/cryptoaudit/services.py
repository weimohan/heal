"""Safe checkpoints, reports, and baseline/Agent comparison helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .contracts import AuditSession, SessionStatus, source_sha256
from .tools import redact_sensitive_text


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}
    return value


def safe_session_dump(session: AuditSession, checkpoint: bool = True) -> dict[str, Any]:
    data = _safe_value(session.checkpoint_dict())
    if not checkpoint:
        return data
    if data.get("patch"):
        data["patch"]["diff"] = "<omitted from checkpoint>"
        data["patch"]["patched_code"] = "<omitted from checkpoint>"
    for observation in data.get("observations", []):
        payload = observation.get("payload")
        if not isinstance(payload, dict):
            continue
        if observation.get("tool_name") == "inspect_source_context":
            payload["context"] = "<omitted from checkpoint>"
        if observation.get("tool_name") == "find_related_calls":
            for call in payload.get("calls", []):
                if isinstance(call, dict):
                    call.pop("expression", None)
        for key in ("proposal", "patch"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                nested["diff"] = "<omitted from checkpoint>"
                nested["patched_code"] = "<omitted from checkpoint>"
    return data


def save_checkpoint(session: AuditSession, directory: str | Path) -> Path:
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{session.task_id}.json"
    path.write_text(json.dumps(safe_session_dump(session), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_checkpoint(source: str, path: str | Path) -> AuditSession:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("source_sha256") != source_sha256(source):
        raise ValueError("source fingerprint does not match checkpoint")
    session = AuditSession.model_validate(data)
    session.source = source
    session.source_for_model = redact_sensitive_text(source)
    return session


def render_markdown(session: AuditSession) -> str:
    lines = [
        "# CryptoAudit Agent 审计报告",
        "",
        f"- 任务：`{session.task_id}`",
        f"- 模式：`{session.mode}`",
        f"- 决策来源：`{session.decision_source}`",
        f"- 状态：`{session.status.value}`",
        f"- 源码：`{session.source_name}`",
        f"- SHA-256：`{session.source_sha256}`",
        f"- 完成说明：{redact_sensitive_text(session.completion_reason)}",
        "",
        "## 算法盘点",
        "",
    ]
    if session.algorithms:
        lines.extend(
            f"- `{item.name}`，{item.status}，第 {item.line} 行：{redact_sensitive_text(item.evidence)}"
            for item in session.algorithms
        )
    else:
        lines.append("- 未识别到已支持的密码算法。")
    lines.extend(["", "## 本地确认 Finding", ""])
    if session.local_findings:
        for item in session.local_findings:
            lines.extend(
                [
                    f"### {item.finding_id} {item.title}",
                    f"- 严重度：`{item.severity.value}`；置信度：`{item.confidence:.2f}`",
                    f"- 位置：第 {item.line} 行；CWE：`{item.cwe}`；来源：`{item.origin}`",
                    f"- 证据：`{redact_sensitive_text(item.evidence)}`",
                    f"- 整改：{item.remediation}",
                    f"- 证据编号：{', '.join(item.evidence_ids)}",
                    "",
                ]
            )
    else:
        lines.append("未发现本地策略确认的问题。\n")
    lines.extend(["## Agent 假设", ""])
    if session.model_hypotheses:
        for item in session.model_hypotheses:
            lines.extend(
                [
                    f"- `{item.hypothesis_id}` `{item.status}`：{redact_sensitive_text(item.title)}；{redact_sensitive_text(item.summary)}",
                    f"  - 相关行：{', '.join(map(str, item.related_lines)) or '未确定'}",
                    f"  - 还需证据：{'; '.join(item.requested_evidence) or '无'}",
                    "",
                ]
            )
    else:
        lines.append("本次没有额外的模型假设。\n")
    lines.extend(["## 知识库引用", ""])
    if session.citations:
        lines.extend(
            f"- `{item.knowledge_id}` {item.title}，来源：{item.source_name}（{item.source_ref}，{item.version}）"
            for item in session.citations
        )
    else:
        lines.append("本次没有使用知识库引用。")
    lines.extend(["", "## 补丁与验证", ""])
    if session.patch:
        lines.extend(
            [
                f"- 补丁状态：`{session.patch.status}`",
                f"- 需要人工复核：`{session.patch.requires_human_review}`",
                f"- 补丁说明：{session.patch.rationale}",
            ]
        )
        if session.patch.diff:
            lines.extend(["", "```diff", redact_sensitive_text(session.patch.diff), "```"])
    if session.verification:
        lines.extend(
            [
                f"- 验证结论：{redact_sensitive_text(session.verification.conclusion)}",
                f"- 补丁已应用：`{session.verification.patch_applied}`",
                f"- 复扫完成：`{session.verification.rescan_completed}`",
                f"- 剩余 Finding：`{len(session.verification.remaining_findings)}`",
            ]
        )
    lines.extend(["", "## Agent Trace", ""])
    for event in session.trace:
        lines.append(f"- `{event.actor}` `{event.action}`：{redact_sensitive_text(event.detail)}（{event.duration_ms:.1f} ms）")
    return "\n".join(lines).rstrip() + "\n"


def result_json(session: AuditSession) -> str:
    data = safe_session_dump(session, checkpoint=False)
    data["report_markdown"] = render_markdown(session)
    return json.dumps(data, ensure_ascii=False, indent=2)


def compare_sessions(baseline: AuditSession, agent: AuditSession) -> dict[str, Any]:
    baseline_ids = {item.finding_id for item in baseline.local_findings}
    agent_ids = {item.finding_id for item in agent.local_findings}
    return {
        "baseline_status": baseline.status.value,
        "agent_status": agent.status.value,
        "baseline_decision_source": baseline.decision_source,
        "agent_decision_source": agent.decision_source,
        "baseline_finding_ids": sorted(baseline_ids),
        "agent_finding_ids": sorted(agent_ids),
        "agent_only_findings": sorted(agent_ids - baseline_ids),
        "baseline_only_findings": sorted(baseline_ids - agent_ids),
        "model_hypothesis_count": len(agent.model_hypotheses),
        "baseline_steps": baseline.step_count,
        "agent_steps": agent.step_count,
        "agent_trace_ms": round(sum(item.duration_ms for item in agent.trace), 2),
    }
