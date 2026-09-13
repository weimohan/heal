"""Executable cryptographic policies used by local evidence tools."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import Severity


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    cwe: str
    remediation: str
    priority: int
    pattern: str


POLICY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        "CRYPTO-SECRET-001",
        "Hard-coded credential material",
        Severity.HIGH,
        0.95,
        "CWE-798",
        "Read the value from an environment variable or an approved secret manager; rotate exposed values.",
        1,
        r"credential-assignment",
    ),
    PolicyRule(
        "CRYPTO-RC4-001",
        "Deprecated RC4 stream cipher",
        Severity.HIGH,
        0.99,
        "CWE-327",
        "Replace RC4 with an authenticated encryption construction such as AES-GCM or ChaCha20-Poly1305.",
        1,
        r"RC4",
    ),
    PolicyRule(
        "CRYPTO-RANDOM-001",
        "Predictable random generator used for security material",
        Severity.HIGH,
        0.90,
        "CWE-338",
        "Use secrets.token_bytes, secrets.token_urlsafe, or os.urandom for keys, tokens, and nonces.",
        1,
        r"random\.\w+",
    ),
    PolicyRule(
        "CRYPTO-DES-001",
        "Deprecated DES cipher",
        Severity.HIGH,
        0.98,
        "CWE-327",
        "Plan a compatibility-reviewed migration to AES-GCM or SM4 with authenticated encryption.",
        1,
        r"\bDES(?:\.new)?\b",
    ),
    PolicyRule(
        "CRYPTO-3DES-001",
        "Deprecated 3DES cipher",
        Severity.HIGH,
        0.98,
        "CWE-327",
        "Plan a compatibility-reviewed migration from 3DES to AES-GCM or SM4.",
        1,
        r"\b(?:3DES|DES3|TripleDES)(?:\.new)?\b",
    ),
    PolicyRule(
        "CRYPTO-ECB-001",
        "ECB encryption mode leaks plaintext patterns",
        Severity.HIGH,
        0.99,
        "CWE-327",
        "Use authenticated encryption such as AES-GCM with a fresh nonce for every encryption operation.",
        1,
        r"\bMODE_ECB\b",
    ),
    PolicyRule(
        "CRYPTO-NONCE-001",
        "Fixed or reused nonce in authenticated encryption",
        Severity.CRITICAL,
        0.99,
        "CWE-323",
        "Generate a fresh nonce for every encryption under the same key and store it with the ciphertext.",
        1,
        r"fixed-or-reused-nonce",
    ),
    PolicyRule(
        "CRYPTO-IV-001",
        "Fixed or predictable initialization vector",
        Severity.HIGH,
        0.98,
        "CWE-329",
        "Generate an unpredictable IV for CBC encryption and authenticate it with the ciphertext.",
        1,
        r"fixed-or-predictable-iv",
    ),
    PolicyRule(
        "CRYPTO-HASH-001",
        "Weak MD4, MD5 or SHA-1 hash",
        Severity.HIGH,
        0.96,
        "CWE-328",
        "Use SHA-256 or SM3 for integrity; use Argon2, scrypt, bcrypt, or PBKDF2 for passwords.",
        2,
        r"\b(?:md4|md5|sha1|MD4|MD5|SHA1)\b",
    ),
    PolicyRule(
        "CRYPTO-HMAC-001",
        "HMAC uses a weak digest algorithm",
        Severity.HIGH,
        0.97,
        "CWE-327",
        "Use HMAC with a modern digest such as SHA-256 or a project-approved national cryptographic hash.",
        1,
        r"weak-hmac-digest",
    ),
    PolicyRule(
        "CRYPTO-RSA-KEYSIZE-001",
        "RSA key size below 2048 bits",
        Severity.HIGH,
        0.98,
        "CWE-326",
        "Use an RSA key size approved for the required lifetime, normally at least 2048 bits, and review padding separately.",
        1,
        r"rsa-key-size",
    ),
    PolicyRule(
        "CRYPTO-PBKDF2-001",
        "PBKDF2 iteration count is too low",
        Severity.HIGH,
        0.97,
        "CWE-916",
        "Benchmark a substantially higher iteration count for the deployment hardware and make the cost parameter upgradeable.",
        1,
        r"pbkdf2-iterations",
    ),
    PolicyRule(
        "CRYPTO-PBKDF2-HASH-001",
        "PBKDF2 uses a weak digest algorithm",
        Severity.HIGH,
        0.97,
        "CWE-916",
        "Use PBKDF2 with a modern approved digest and retain a migration path for stored password records.",
        1,
        r"pbkdf2-digest",
    ),
    PolicyRule(
        "CRYPTO-LOG-LEAK-001",
        "Sensitive data is written to a debug log",
        Severity.HIGH,
        0.95,
        "CWE-532",
        "Remove secrets and plaintext message content from logs; use structured, redacted diagnostics instead.",
        1,
        r"sensitive-log",
    ),
    PolicyRule(
        "CRYPTO-CHECKSUM-001",
        "Non-cryptographic checksum used for integrity",
        Severity.MEDIUM,
        0.95,
        "CWE-328",
        "Use a cryptographic MAC or authenticated encryption when an integrity or authenticity guarantee is required.",
        2,
        r"non-cryptographic-checksum",
    ),
    PolicyRule(
        "CRYPTO-KEY-LEAK-001",
        "Key material is included in derived token data",
        Severity.HIGH,
        0.94,
        "CWE-200",
        "Do not concatenate key material into tokens or messages; use a separate random token or a reviewed KDF/MAC construction.",
        1,
        r"key-material-flow",
    ),
    PolicyRule(
        "CRYPTO-COMPARE-001",
        "Sensitive value compared with a non-constant-time operator",
        Severity.HIGH,
        0.92,
        "CWE-208",
        "Use hmac.compare_digest for password digests, MACs, tokens, and other attacker-influenced sensitive values.",
        1,
        r"sensitive-compare",
    ),
)


def rule_by_id(rule_id: str) -> PolicyRule:
    for rule in POLICY_RULES:
        if rule.rule_id == rule_id:
            return rule
    raise KeyError(rule_id)


def pattern_matches(rule: PolicyRule, text: str) -> bool:
    return re.search(rule.pattern, text, re.IGNORECASE) is not None


ALGORITHM_NOTES = {
    "AES": ("对称分组密码", "recommended", "AES 应优先使用认证加密模式，例如 GCM。"),
    "SM2": ("国密公钥密码", "recommended", "SM2 的参数、证书和签名格式应符合适用标准。"),
    "SM3": ("国密哈希", "recommended", "SM3 适合国密摘要场景，口令存储仍需慢哈希。"),
    "SM4": ("国密对称分组密码", "recommended", "SM4 应配合安全模式和新鲜 nonce 使用。"),
    "RSA": ("非对称密码", "review", "RSA 的密钥长度、填充和密钥生命周期必须单独审查。"),
    "ChaCha20": ("流密码", "review", "ChaCha20 应与 Poly1305 组合成认证加密构造。"),
    "DES": ("对称分组密码", "deprecated", "DES 有效密钥长度不足，迁移前必须进行兼容性评审。"),
    "3DES": ("对称分组密码", "deprecated", "3DES 不适合新系统，应规划迁移。"),
    "RC4": ("流密码", "deprecated", "RC4 已不适合新的安全设计，应迁移到认证加密构造。"),
    "CRC32": ("非密码学校验和", "review", "CRC32 只能检测部分传输错误，不能提供密码学完整性或真实性。"),
    "PBKDF2": ("口令密钥派生函数", "review", "PBKDF2 的摘要算法、成本参数和升级策略需要结合部署环境审查。"),
    "MD4": ("哈希摘要", "deprecated", "MD4 已不适合任何新的安全摘要或完整性设计。"),
    "MD5": ("哈希摘要", "deprecated", "MD5 不得用于安全完整性或口令存储。"),
    "SHA-1": ("哈希摘要", "deprecated", "SHA-1 已不适合新的安全设计。"),
    "SHA-256": ("哈希摘要", "recommended", "SHA-256 是主流安全哈希，口令场景仍需慢哈希。"),
}
