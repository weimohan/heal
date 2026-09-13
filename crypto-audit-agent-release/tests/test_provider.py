import json
import sys
import types
from types import SimpleNamespace

import pytest

from cryptoaudit.contracts import AgentAction, ProviderError
from cryptoaudit.provider import OfflineProvider, OpenAIProvider, all_decision_tools


def test_decision_tool_catalog_contains_finish_and_ask_user():
    names = {item["function"]["name"] for item in all_decision_tools([])}
    assert {"finish_audit", "ask_user"} <= names


def test_offline_provider_selects_tools_from_state():
    provider = OfflineProvider()
    context = {"completed_tools": [], "local_findings": [], "proposal": None, "human_decision": ""}
    action = provider.decide("", [{"role": "user", "content": __import__("json").dumps(context)}], [])
    assert action == AgentAction(action="call_tool", tool_name="inventory_algorithms")


def test_offline_provider_preserves_context_gaps_as_unknown_hypothesis():
    provider = OfflineProvider()
    context = {
        "source": "def encrypt(cipher, data):\n    return cipher.encrypt(data)\n",
        "completed_tools": ["inventory_algorithms", "scan_python_source", "propose_patch", "verify_patch"],
        "local_findings": [],
        "proposal": {"status": "not_applicable"},
        "human_decision": "",
        "observations": [{"evidence_ids": ["E-VERIFY:RESCAN"]}],
    }

    action = provider.decide("", [{"role": "user", "content": __import__("json").dumps(context)}], [])

    assert action.action == "finish"
    assert action.hypotheses[0].status == "unknown"
    assert action.hypotheses[0].evidence_ids == ["E-VERIFY:RESCAN"]


def test_openai_provider_requires_key_before_optional_import():
    with pytest.raises(ProviderError):
        OpenAIProvider("")


def test_openai_provider_forwards_tool_request_and_parses_tool_call(monkeypatch):
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured["request"] = kwargs
            return SimpleNamespace(
                usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7, total_tokens=18),
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            tool_calls=[
                                SimpleNamespace(
                                    function=SimpleNamespace(
                                        name="inventory_algorithms",
                                        arguments=json.dumps({}),
                                    )
                                )
                            ]
                        )
                    )
                ],
            )

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured["client"] = kwargs
            self.chat = SimpleNamespace(completions=FakeCompletions())

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    provider = OpenAIProvider("sk-test", model="gpt-5-mini", timeout_seconds=7)
    action = provider.decide("system", [{"role": "user", "content": "{}"}], [{"type": "function"}])

    assert action == AgentAction(action="call_tool", tool_name="inventory_algorithms")
    assert captured["client"] == {"api_key": "sk-test", "timeout": 7}
    assert captured["request"]["model"] == "gpt-5-mini"
    assert captured["request"]["tool_choice"] == "auto"
    assert captured["request"]["tools"] == [{"type": "function"}]
    assert captured["request"]["messages"][0] == {"role": "system", "content": "system"}
    assert provider.last_usage == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


def test_openai_provider_verifies_selected_model(monkeypatch):
    captured = {}

    class FakeModels:
        def retrieve(self, model):
            captured["model"] = model
            return object()

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.models = FakeModels()

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)

    provider = OpenAIProvider("sk-test", model="gpt-5-mini")

    assert provider.verify_key() is True
    assert captured["model"] == "gpt-5-mini"
