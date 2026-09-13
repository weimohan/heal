
from __future__ import annotations

import os
from dataclasses import dataclass


def _positive_int(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    model: str = os.environ.get("OPENAI_MODEL", "gpt-5-mini")
    max_steps: int = _positive_int("CRYPTOAUDIT_MAX_STEPS", 8, 32)
    timeout_seconds: int = _positive_int("CRYPTOAUDIT_TIMEOUT_SECONDS", 30, 120)
    knowledge_path: str = os.environ.get("CRYPTOAUDIT_KNOWLEDGE_PATH", "knowledge/cards.jsonl")


settings = Settings()
