"""Small deterministic retriever over versioned local guidance cards."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .contracts import KnowledgeCitation


def _tokens(text: str) -> set[str]:
    lowered = text.lower()
    words = re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]", lowered)
    return set(words)


class KnowledgeBase:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.cards = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        cards = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            card = json.loads(line)
            if not isinstance(card, dict):
                continue
            required = {"knowledge_id", "title", "content", "source_name", "source_ref", "version", "tags"}
            if required <= set(card):
                cards.append(card)
        return cards

    def search(self, query: str, limit: int = 3) -> list[KnowledgeCitation]:
        if not query.strip():
            return []
        query_tokens = _tokens(query)
        ranked: list[tuple[float, dict[str, Any]]] = []
        for card in self.cards:
            searchable = " ".join(
                [str(card["title"]), str(card["content"]), " ".join(map(str, card.get("tags", [])))]
            )
            card_tokens = _tokens(searchable)
            overlap = query_tokens & card_tokens
            if not overlap:
                continue
            score = float(len(overlap))
            if _tokens(str(card["title"])) & query_tokens:
                score += 1.5
            ranked.append((score, card))
        ranked.sort(key=lambda item: (-item[0], str(item[1]["knowledge_id"])))
        return [
            KnowledgeCitation(
                knowledge_id=card["knowledge_id"],
                title=card["title"],
                excerpt=card["content"],
                source_name=card["source_name"],
                source_ref=card["source_ref"],
                version=card["version"],
                score=score,
            )
            for score, card in ranked[: max(1, min(limit, 5))]
        ]

    def search_many(self, queries: list[str], limit: int = 5, per_query_limit: int = 2) -> list[KnowledgeCitation]:
        """Merge small, focused searches so one broad query does not hide local evidence."""
        merged: dict[str, KnowledgeCitation] = {}
        for query in queries:
            for citation in self.search(query, limit=per_query_limit):
                previous = merged.get(citation.knowledge_id)
                if previous is None or citation.score > previous.score:
                    merged[citation.knowledge_id] = citation
        return sorted(merged.values(), key=lambda item: (-item.score, item.knowledge_id))[: max(1, min(limit, 10))]
