from pathlib import Path

from cryptoaudit.knowledge import KnowledgeBase


def test_retrieval_returns_stable_citations():
    base = KnowledgeBase(Path(__file__).parents[1] / "knowledge" / "cards.jsonl")
    results = base.search("AES GCM nonce", limit=2)
    assert results
    assert results[0].knowledge_id == "KB-AES-GCM"
    assert results[0].source_ref
    assert results[0].version


def test_empty_or_unknown_query_is_safe():
    base = KnowledgeBase(Path(__file__).parents[1] / "knowledge" / "cards.jsonl")
    assert base.search("") == []
    assert base.search("qwerty zyx") == []


def test_card_content_is_data_not_an_instruction():
    base = KnowledgeBase(Path(__file__).parents[1] / "knowledge" / "cards.jsonl")
    result = base.search("prompt injection tool policy")
    assert result
    assert result[0].knowledge_id == "KB-UNTRUSTED-CODE"


def test_search_many_merges_citations_for_distinct_findings():
    base = KnowledgeBase(Path(__file__).parents[1] / "knowledge" / "cards.jsonl")
    results = base.search_many(["Nonce uniqueness", "Deprecated RC4 stream cipher"])
    ids = {item.knowledge_id for item in results}
    assert {"KB-NONCE", "KB-RC4"} <= ids
