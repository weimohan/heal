from cryptoaudit.baseline import BaselineRunner
from cryptoaudit.contracts import SessionStatus


def test_baseline_is_explicitly_labeled_and_offline():
    session = BaselineRunner().run("from Crypto.Cipher import DES3\ncipher = DES3.new(k)\n")
    assert session.mode == "baseline"
    assert session.status == SessionStatus.COMPLETED_WITH_REVIEW
    assert any(item.rule_id == "CRYPTO-3DES-001" for item in session.local_findings)


def test_baseline_includes_local_knowledge_citations_for_confirmed_findings():
    source = "from Crypto.Cipher import AES\nnonce = b'fixed-nonce'\nAES.new(key, AES.MODE_GCM, nonce=nonce)\n"
    session = BaselineRunner().run(source)
    assert session.citations
    assert any(item.knowledge_id == "KB-NONCE" for item in session.citations)
