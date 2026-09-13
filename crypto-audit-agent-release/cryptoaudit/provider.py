"""OpenAI tool-calling provider and deterministic providers for offline tests."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from .contracts import AgentAction, ProviderError


class DecisionProvider(Protocol):
    mode: str

    def decide(
        self,
        system_prompt: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
    ) -> AgentAction:
        ...


SPECIAL_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "ask_user",
            "description": "Ask one targeted clarification or approval question and pause the audit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "minLength": 1},
                    "question_kind": {"type": "string", "enum": ["clarification", "approval"]},
                },
                "required": ["question", "question_kind"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish_audit",
            "description": "Request completion after all evidence and verification requirements are satisfied.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    "hypotheses": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "hypothesis_id": {"type": "string", "pattern": "^H-[0-9]+$"},
                                "title": {"type": "string"},
                                "summary": {"type": "string"},
                                "related_lines": {"type": "array", "items": {"type": "integer"}},
                                "requested_evidence": {"type": "array", "items": {"type": "string"}},
                                "status": {"type": "string", "enum": ["likely", "unknown"]},
                                "evidence_ids": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["hypothesis_id", "title", "summary", "status"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["summary"],
                "additionalProperties": False,
            },
        },
    },
]


def all_decision_tools(local_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [*local_tools, *SPECIAL_TOOL_DEFINITIONS]


def _offline_context_hypothesis(context: dict[str, Any]) -> dict[str, Any] | None:
    """Return one bounded uncertainty claim when the source exposes a context gap."""
    source = str(context.get("source", ""))
    lines = source.splitlines()
    evidence_ids: list[str] = []
    for observation in reversed(context.get("observations", [])):
        if isinstance(observation, dict):
            evidence_ids.extend(str(item) for item in observation.get("evidence_ids", []))
        if evidence_ids:
            break
    evidence_ids = list(dict.fromkeys(evidence_ids or ["E-LOCAL-SCAN"]))

    def line_number(pattern: str) -> int:
        for index, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                return index
        return 0

    if re.search(r"def\s+\w+\([^)]*\bcipher\b", source) and "cipher.encrypt" in source:
        line = line_number(r"cipher\.encrypt") or line_number(r"def\s+\w+")
        return {
            "hypothesis_id": "H-1",
            "title": "密码对象由调用方传入，当前文件无法确认实际模式",
            "summary": "当前文件只使用外部传入的 cipher，缺少实例化位置，无法仅凭本文件确认算法模式和 nonce 生命周期。",
            "related_lines": [line] if line else [],
            "requested_evidence": ["调用方创建 cipher 的位置", "实际模式和 nonce 的生命周期"],
            "status": "unknown",
            "evidence_ids": evidence_ids,
        }
    if "MODE_GCM" in source and re.search(r"\bget_nonce\s*\(", source):
        line = line_number(r"get_nonce\s*\(") or line_number(r"MODE_GCM")
        return {
            "hypothesis_id": "H-1",
            "title": "GCM nonce 来源和唯一性无法在当前文件内确认",
            "summary": "nonce 来自外部函数，当前文件没有实现该函数，不能确认每次加密是否使用唯一 nonce。",
            "related_lines": [line] if line else [],
            "requested_evidence": ["get_nonce 的实现", "跨调用和持久化场景下的 nonce 唯一性"],
            "status": "unknown",
            "evidence_ids": evidence_ids,
        }
    if re.search(r"AES\.new\([^,\n]+,\s*mode\s*\)", source):
        line = line_number(r"AES\.new\(")
        return {
            "hypothesis_id": "H-1",
            "title": "AES 模式由参数决定，当前文件无法完成兼容性判断",
            "summary": "AES 的 mode 由调用方传入，当前文件没有足够信息判断是否使用了安全模式以及 nonce 是否满足要求。",
            "related_lines": [line] if line else [],
            "requested_evidence": ["调用方传入的 mode", "对应模式的 nonce 和认证标签处理"],
            "status": "unknown",
            "evidence_ids": evidence_ids,
        }
    return None


class ScriptedProvider:
    """Test provider that returns prevalidated decisions in a known sequence."""

    mode = "scripted"

    def __init__(self, decisions: Sequence[AgentAction | dict[str, Any]]):
        self._decisions = [
            item if isinstance(item, AgentAction) else AgentAction.model_validate(item)
            for item in decisions
        ]

    def decide(self, system_prompt, messages, tools) -> AgentAction:
        if not self._decisions:
            raise ProviderError("scripted provider has no remaining decision")
        return self._decisions.pop(0)


class OfflineProvider:
    """Deterministic provider used for demos when GPT is unavailable."""

    mode = "offline"

    def __init__(self, chooser: Callable[[dict[str, Any]], AgentAction] | None = None):
        self.chooser = chooser

    def decide(self, system_prompt, messages, tools) -> AgentAction:
        try:
            context = json.loads(messages[-1]["content"])
        except (IndexError, KeyError, json.JSONDecodeError) as exc:
            raise ProviderError("offline context is invalid") from exc
        if self.chooser:
            return self.chooser(context)
        completed = set(context.get("completed_tools", []))
        findings = context.get("local_findings", [])
        proposal = context.get("proposal") or {}
        if "inventory_algorithms" not in completed:
            return AgentAction(action="call_tool", tool_name="inventory_algorithms")
        if "scan_python_source" not in completed:
            return AgentAction(action="call_tool", tool_name="scan_python_source")
        if findings and "retrieve_crypto_guidance" not in completed:
            query = "\n".join(sorted({str(item.get("title", "")) for item in findings}))
            return AgentAction(action="call_tool", tool_name="retrieve_crypto_guidance", arguments={"query": query})
        if "propose_patch" not in completed:
            return AgentAction(action="call_tool", tool_name="propose_patch")
        if proposal.get("requires_human_review") and not context.get("human_decision"):
            return AgentAction(
                action="ask_user",
                question="该迁移可能影响历史密文或协议兼容性。是否确认进入人工复核？系统不会自动改写算法。",
                question_kind="approval",
            )
        if "verify_patch" not in completed:
            return AgentAction(action="call_tool", tool_name="verify_patch")
        hypothesis = _offline_context_hypothesis(context)
        return AgentAction(
            action="finish",
            summary="本地证据和独立复扫均已完成；无法从当前文件确认的上下文已保留为 unknown。",
            hypotheses=[hypothesis] if hypothesis else [],
        )


class OpenAIProvider:
    """Lazy OpenAI Chat Completions tool caller; the API key never leaves this object."""

    mode = "openai"

    def __init__(self, api_key: str, model: str = "gpt-5-mini", timeout_seconds: int = 30):
        if not api_key or not api_key.strip():
            raise ProviderError("an OpenAI API key is required")
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ProviderError("install requirements-ai.txt to enable GPT mode") from exc
        self.model = model
        self._client = OpenAI(api_key=api_key, timeout=timeout_seconds)
        self.last_usage: dict[str, Any] = {}

    def decide(self, system_prompt, messages, tools) -> AgentAction:
        request_messages = [{"role": "system", "content": system_prompt}, *messages]
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=request_messages,
                tools=tools,
                tool_choice="auto",
            )
        except Exception as exc:  # pragma: no cover - network/provider dependent
            raise ProviderError(f"OpenAI request failed: {type(exc).__name__}") from exc
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = {
                "prompt_tokens": getattr(usage, "prompt_tokens", 0),
                "completion_tokens": getattr(usage, "completion_tokens", 0),
                "total_tokens": getattr(usage, "total_tokens", 0),
            }
        message = response.choices[0].message
        calls = getattr(message, "tool_calls", None) or []
        if not calls:
            raise ProviderError("model returned no structured action")
        call = calls[0]
        name = call.function.name
        try:
            arguments = json.loads(call.function.arguments or "{}")
        except json.JSONDecodeError as exc:
            raise ProviderError("model returned invalid tool arguments") from exc
        if not isinstance(arguments, dict):
            raise ProviderError("model tool arguments must be an object")
        try:
            if name == "ask_user":
                return AgentAction(action="ask_user", **arguments)
            if name == "finish_audit":
                return AgentAction(action="finish", **arguments)
            return AgentAction(action="call_tool", tool_name=name, arguments=arguments)
        except Exception as exc:
            raise ProviderError("model action failed local schema validation") from exc

    def verify_key(self) -> bool:
        """Validate credentials and selected model access without sending source text."""
        try:
            self._client.models.retrieve(self.model)
        except Exception as exc:  # pragma: no cover - network/provider dependent
            raise ProviderError(f"OpenAI key/model verification failed: {type(exc).__name__}") from exc
        return True
