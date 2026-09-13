from pathlib import Path

import pytest

import app
from app import MODE_OPTIONS, build_provider, set_source_state
from cryptoaudit.provider import OfflineProvider


def test_ui_exposes_three_clear_modes():
    assert MODE_OPTIONS == ("离线基线", "GPT Agent", "对比实验")


def test_ui_without_key_uses_offline_provider():
    assert isinstance(build_provider("", False, "gpt-5-mini", 30), OfflineProvider)


def test_ui_labels_offline_provider_explicitly():
    labeler = getattr(app, "provider_display_label", lambda _provider: "")
    assert labeler(OfflineProvider()) == "离线 Agent（OfflineProvider）"


def test_source_consent_is_required_for_a_key():
    with pytest.raises(ValueError):
        build_provider("sk-example", False, "gpt-5-mini", 30)


def test_loading_source_updates_the_editor_widget_state():
    state = {"source_text": "old", "source_editor": "old"}

    set_source_state(state, "new")

    assert state == {"source_text": "new", "source_editor": "new"}


def test_launcher_disables_streamlit_usage_stats_for_portable_runs():
    launcher = (Path(__file__).resolve().parents[1] / "start.ps1").read_text(encoding="utf-8")

    assert '$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = "false"' in launcher


def test_launcher_starts_streamlit_without_interactive_onboarding():
    launcher = (Path(__file__).resolve().parents[1] / "start.ps1").read_text(encoding="utf-8")

    assert "--server.headless false" in launcher
    assert "--server.address localhost" in launcher
    assert "--server.showEmailPrompt false" in launcher


def test_launcher_ignores_candidates_without_streamlit():
    launcher = (Path(__file__).resolve().parents[1] / "start.ps1").read_text(encoding="utf-8")

    assert "try {" in launcher
    assert "catch {" in launcher
    assert "return $false" in launcher


def test_double_click_launcher_bypasses_policy_prompt():
    launcher = (Path(__file__).resolve().parents[1] / "start.cmd").read_text(encoding="utf-8")

    assert "ExecutionPolicy Bypass" in launcher
