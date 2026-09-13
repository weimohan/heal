from cryptoaudit.tools import (
    ToolRegistry,
    inventory_algorithms,
    redact_sensitive_text,
    scan_python_source,
)


def test_ast_scan_ignores_comments_and_unrelated_strings():
    source = '''
# DES.new(key) and hashlib.md5(data) are only documentation.
text = "random.seed(1) MODE_ECB"
from Crypto.Cipher import AES
AES.new(key, AES.MODE_GCM)
'''
    findings = scan_python_source(source)
    assert [item.rule_id for item in findings] == []
    assert {item.name for item in inventory_algorithms(source)} == {"AES"}


def test_alias_imports_and_3des_have_local_evidence():
    source = '''
import hashlib as h
from Crypto.Cipher import DES3 as Legacy
digest = h.md5(data)
cipher = Legacy.new(key)
'''
    findings = scan_python_source(source)
    assert {item.rule_id for item in findings} == {"CRYPTO-HASH-001", "CRYPTO-3DES-001"}
    assert {item.name for item in inventory_algorithms(source)} == {"MD5", "3DES"}


def test_hardcoded_secret_is_redacted_and_patch_tool_is_bound_to_source():
    source = 'api_key = "real-secret-value"\n'
    findings = scan_python_source(source)
    assert findings[0].evidence == 'api_key = "<REDACTED>"'
    registry = ToolRegistry(source)
    result = registry.call("propose_patch")
    assert result.success
    assert "real-secret-value" not in str(result.payload)


def test_tool_registry_rejects_unknown_and_unexpected_arguments():
    registry = ToolRegistry("print(1)\n")
    assert not registry.call("run_shell_command").success
    assert not registry.call("inventory_algorithms", {"path": "x.py"}).success


def test_redaction_preserves_assignment_shape():
    assert redact_sensitive_text('token = "abc"') == 'token = "<REDACTED>"'


def test_extended_crypto_rules_cover_messenger_vulnerabilities():
    source = r'''
import binascii
import hashlib
import hmac
from Crypto.Cipher import RC4, AES
from Crypto.PublicKey import RSA

SHARED_SECRET = "super_secret_key_12345"
IV = b"\x00" * 16
NONCE = b"123456789012"

def create_message(content):
    body = RC4.new(SHARED_SECRET.encode()).encrypt(content.encode())
    digest = hashlib.md4(content.encode()).hexdigest()
    mac = hmac.new(SHARED_SECRET.encode(), body, hashlib.md5).hexdigest()
    token_data = f"{content}_{SHARED_SECRET}"
    return body, digest, mac, token_data

def verify_message(msg):
    expected = hmac.new(SHARED_SECRET.encode(), msg["body"], hashlib.md5).hexdigest()
    if expected == msg["mac"]:
        pass
    actual_hash = hashlib.md4(msg["body"]).hexdigest()
    if actual_hash != msg["hash"]:
        raise ValueError("bad hash")
    return msg

def encrypt_file(data):
    key = RSA.generate(512)
    cipher = AES.new(SHARED_SECRET.encode()[:32], AES.MODE_CBC, iv=b"\x01\x02\x03" * 5 + b"\x04")
    return key, cipher.encrypt(data)

def derive(password, salt):
    return hashlib.pbkdf2_hmac("md5", password.encode(), salt, iterations=100, dklen=32)

def quick_hash(data):
    return format(binascii.crc32(data), "08x")

def debug():
    print(f"[DEBUG] shared key: {SHARED_SECRET}")

def encrypt_with_fixed_nonce(data):
    return AES.new(SHARED_SECRET.encode()[:32], AES.MODE_GCM, nonce=NONCE).encrypt(data)
'''
    findings = scan_python_source(source)
    rule_ids = {item.rule_id for item in findings}
    assert {
        "CRYPTO-RC4-001",
        "CRYPTO-HASH-001",
        "CRYPTO-HMAC-001",
        "CRYPTO-SECRET-001",
        "CRYPTO-IV-001",
        "CRYPTO-NONCE-001",
        "CRYPTO-RSA-KEYSIZE-001",
        "CRYPTO-PBKDF2-001",
        "CRYPTO-PBKDF2-HASH-001",
        "CRYPTO-LOG-LEAK-001",
        "CRYPTO-CHECKSUM-001",
        "CRYPTO-KEY-LEAK-001",
        "CRYPTO-COMPARE-001",
    } <= rule_ids
    assert any(item.rule_id == "CRYPTO-SECRET-001" and "super_secret" not in item.evidence for item in findings)
    assert {item.name for item in inventory_algorithms(source)} >= {"RC4", "MD4", "PBKDF2", "CRC32"}


def test_algorithm_inventory_does_not_count_digest_method_as_new_hash():
    source = "import hashlib\nsha1_hash = hashlib.sha1(data)\nsha1_hash.hexdigest()\n"
    uses = [item for item in inventory_algorithms(source) if item.name == "SHA-1"]
    assert [item.line for item in uses] == [2]


def test_extended_rules_do_not_flag_safe_parameters_or_constant_time_compare():
    source = '''
import hmac
import os
from Crypto.Cipher import AES
from secrets import token_bytes

MASTER_KEY = os.environ["MASTER_KEY"]
nonce = token_bytes(12)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
if hmac.compare_digest(expected, provided):
    pass
derived = hashlib.pbkdf2_hmac("sha256", password, salt, iterations=200000)
'''
    assert scan_python_source(source) == []


def test_redaction_covers_named_key_and_credential_variants():
    source = 'MASTER_KEY = "master-value"\nADMIN_TOKEN = "admin-value"\nSHARED_SECRET = "shared-value"'
    redacted = redact_sensitive_text(source)
    assert redacted == 'MASTER_KEY = "<REDACTED>"\nADMIN_TOKEN = "<REDACTED>"\nSHARED_SECRET = "<REDACTED>"'


def test_algorithm_inventory_keeps_multiple_algorithms_from_one_import():
    source = "from Crypto.Cipher import RC4, AES, DES3\n"
    assert {item.name for item in inventory_algorithms(source)} >= {"RC4", "AES", "3DES"}
