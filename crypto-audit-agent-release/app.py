
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptoaudit.agent import AgentOrchestrator
from cryptoaudit.baseline import BaselineRunner
from cryptoaudit.contracts import AuditSession, ProviderError, SessionStatus
from cryptoaudit.provider import OfflineProvider, OpenAIProvider
from cryptoaudit.services import compare_sessions, render_markdown, result_json


ROOT = Path(__file__).resolve().parent
KNOWLEDGE = ROOT / "knowledge" / "cards.jsonl"
MODE_OPTIONS = ("离线基线", "GPT Agent", "对比实验")
MAX_SOURCE_BYTES = 200_000


def set_source_state(state: Any, source: str) -> None:
    """Keep the backing value and Streamlit editor value synchronized."""
    state["source_text"] = source
    state["source_editor"] = source


def build_provider(api_key: str, consent: bool, model: str, timeout: int):
    key = api_key.strip()
    if not key:
        return OfflineProvider()
    if not consent:
        raise ValueError("发送源码前必须明确勾选授权")
    return OpenAIProvider(key, model=model, timeout_seconds=timeout)


def provider_display_label(provider: Any) -> str:
    if isinstance(provider, OpenAIProvider):
        return "GPT Agent（OpenAI）"
    return "离线 Agent（OfflineProvider）"


def session_display_label(session: AuditSession) -> str:
    labels = {
        "baseline": "固定基线（BaselineRunner）",
        "offline": "离线 Agent（OfflineProvider）",
        "openai": "GPT Agent（OpenAI）",
        "scripted": "脚本 Agent（ScriptedProvider）",
    }
    return labels.get(session.decision_source, f"Agent（{session.decision_source}）")


def _sample_sources() -> dict[str, str]:
    return {
        "漏洞样例": (ROOT / "cases" / "vulnerable_login.py").read_text(encoding="utf-8"),
        "消息通信漏洞样例": (ROOT / "cases" / "vulnerable_messenger.py").read_text(encoding="utf-8"),
        "安全样例": (ROOT / "cases" / "secure_aes_gcm.py").read_text(encoding="utf-8"),
    }


def _display_session(st: Any, session: AuditSession, prefix: str = "") -> None:
    st.subheader(f"{prefix}{session.status.value}")
    st.caption(f"决策来源：{session_display_label(session)}")
    if session.status == SessionStatus.DEGRADED:
        st.error(f"GPT 请求未完成，当前结果已降级为本地基线。{session.completion_reason}")
    elif session.completion_reason:
        st.caption(f"完成说明：{session.completion_reason}")
    cols = st.columns(4)
    cols[0].metric("算法", len(session.algorithms))
    cols[1].metric("本地 Finding", len(session.local_findings))
    cols[2].metric("Agent 假设", len(session.model_hypotheses))
    cols[3].metric("步骤", session.step_count)
    if session.status == SessionStatus.AWAITING_USER:
        st.warning(session.pending_question)
    with st.expander("Agent Trace", expanded=True):
        for event in session.trace:
            st.write(f"`{event.actor}` · {event.action} · {event.detail} · {event.duration_ms:.1f} ms")
    left, right = st.columns(2)
    with left:
        st.markdown("#### 算法盘点")
        st.dataframe([item.model_dump(mode="json") for item in session.algorithms], use_container_width=True, hide_index=True)
        st.markdown("#### 本地确认 Finding")
        for item in session.local_findings:
            st.error(f"{item.finding_id} · {item.title} · 第 {item.line} 行 · {item.severity.value}")
            st.caption(f"证据：{item.evidence} | {item.cwe} | {item.origin}")
    with right:
        st.markdown("#### Agent 假设")
        if session.model_hypotheses:
            st.dataframe([item.model_dump(mode="json") for item in session.model_hypotheses], use_container_width=True, hide_index=True)
        else:
            st.caption("没有额外的模型假设")
        st.markdown("#### 知识库引用")
        for item in session.citations:
            st.info(f"{item.knowledge_id} · {item.title}\n\n{item.source_name} / {item.source_ref} / {item.version}")
    if session.patch:
        st.markdown("#### 补丁 Diff")
        st.code(session.patch.diff or "没有可自动应用的补丁", language="diff")
    if session.verification:
        st.markdown("#### 独立验证")
        st.json(session.verification.model_dump(mode="json"))
    st.download_button("下载 JSON", result_json(session), file_name=f"{session.task_id}.json", mime="application/json", key=f"json-{prefix}-{session.task_id}")
    st.download_button("下载 Markdown", render_markdown(session), file_name=f"{session.task_id}.md", mime="text/markdown", key=f"md-{prefix}-{session.task_id}")


def main() -> None:
    try:
        import streamlit as st
    except ImportError as exc:  # pragma: no cover - exercised in packaging environment
        raise SystemExit("Streamlit is optional; install requirements-ai.txt to start the UI.") from exc

    st.set_page_config(page_title="CryptoAudit Agent", layout="wide")
    st.title("CryptoAudit Agent")
    st.caption("可验证的 Python 密码代码审查工作台")
    samples = _sample_sources()
    if "source_text" not in st.session_state:
        set_source_state(st.session_state, samples["漏洞样例"])
    elif "source_editor" not in st.session_state:
        st.session_state.source_editor = st.session_state.source_text
    if "active_session" not in st.session_state:
        st.session_state.active_session = None
    if "provider" not in st.session_state:
        st.session_state.provider = None

    with st.sidebar:
        st.header("审查设置")
        mode = st.radio("运行模式", MODE_OPTIONS)
        sample_name = st.selectbox("加载样例", list(samples))
        if st.button("加载样例"):
            set_source_state(st.session_state, samples[sample_name])
        model = st.text_input("模型", value=os.environ.get("OPENAI_MODEL", "gpt-5-mini"))
        timeout = st.number_input("单次超时（秒）", min_value=5, max_value=120, value=30)
        api_key = st.text_input("API Key 验证", type="password", key="api_key_input")
        consent = st.checkbox("我同意将脱敏后的源码发送给 OpenAI")
        if mode == "对比实验" and not api_key.strip():
            st.info("当前未输入 API Key：右侧将运行离线 Agent，不会调用 OpenAI。")
        elif mode == "GPT Agent" and not api_key.strip():
            st.warning("当前未输入 API Key：本次将运行离线 Agent；输入 Key 并授权后才会调用 OpenAI。")
        elif api_key.strip() and consent:
            st.caption("已准备 OpenAI GPT。点击“验证 API Key”可先检查 Key 和所选模型；开始审查时才会发送脱敏源码。")
        if st.button("验证 API Key"):
            try:
                provider = build_provider(api_key, consent, model, int(timeout))
                if isinstance(provider, OpenAIProvider):
                    provider.verify_key()
                    st.success("OpenAI API Key 和所选模型可用（未发送源码）")
                else:
                    st.info("当前未输入 Key，将使用离线模式")
            except (ValueError, ProviderError) as exc:
                st.error(str(exc))
        if st.button("清除 API Key"):
            st.session_state.api_key_input = ""
            st.session_state.provider = None
            st.rerun()

    uploaded = st.file_uploader("上传一个 Python 源文件", type=["py"])
    if uploaded is not None:
        if uploaded.size > MAX_SOURCE_BYTES:
            st.error("源码文件超过 200 KB 限制")
        else:
            set_source_state(st.session_state, uploaded.getvalue().decode("utf-8", errors="strict"))
    source = st.text_area("源码", height=360, key="source_editor")
    st.session_state.source_text = source
    run_clicked = st.button("开始审查", type="primary")
    if run_clicked:
        try:
            provider = build_provider(api_key, consent, model, int(timeout))
            st.session_state.provider = provider
            if mode == "离线基线":
                st.session_state.active_session = BaselineRunner(KNOWLEDGE).run(source, source_name="inline.py", task_id="ui-baseline")
            elif mode == "GPT Agent":
                session = AuditSession.from_source(source, source_name="inline.py", task_id="ui-agent", mode="agent")
                st.session_state.active_session = AgentOrchestrator(provider=provider, knowledge_path=KNOWLEDGE, max_steps=12).start(session)
            else:
                baseline = BaselineRunner(KNOWLEDGE).run(source, source_name="inline.py", task_id="ui-baseline")
                agent = AgentOrchestrator(provider=provider, knowledge_path=KNOWLEDGE, max_steps=12).start(
                    AuditSession.from_source(source, source_name="inline.py", task_id="ui-agent", mode="agent")
                )
                st.session_state.active_session = (baseline, agent)
        except (ValueError, ProviderError, UnicodeDecodeError) as exc:
            st.error(str(exc))

    active = st.session_state.active_session
    if isinstance(active, tuple):
        baseline, agent = active
        st.markdown(f"## 基线与 {session_display_label(agent)} 对比")
        st.caption("左侧是固定顺序的本地基线；右侧显示本次实际使用的决策来源。没有 API Key 时，右侧是离线 Agent；GPT 请求失败时会明确标记为降级结果。")
        st.json(compare_sessions(baseline, agent))
        left, right = st.columns(2)
        with left:
            _display_session(st, baseline, "固定基线：")
        with right:
            _display_session(st, agent, f"{session_display_label(agent)}：")
        if agent.status == SessionStatus.AWAITING_USER:
            answer = st.text_input("Agent 的问题", key="compare_pending_answer")
            if st.button("提交 Agent 回答"):
                provider = st.session_state.provider or OfflineProvider()
                orchestrator = AgentOrchestrator(provider=provider, knowledge_path=KNOWLEDGE, max_steps=12)
                st.session_state.active_session = (baseline, orchestrator.resume(agent, answer))
                st.rerun()
    elif isinstance(active, AuditSession):
        _display_session(st, active, f"{session_display_label(active)}：")
        if active.status == SessionStatus.AWAITING_USER:
            answer = st.text_input("Agent 的问题", key="pending_answer")
            if st.button("提交回答"):
                provider = st.session_state.provider or OfflineProvider()
                orchestrator = AgentOrchestrator(provider=provider, knowledge_path=KNOWLEDGE, max_steps=12)
                st.session_state.active_session = orchestrator.resume(active, answer)
                st.rerun()


if __name__ == "__main__":
    main()
