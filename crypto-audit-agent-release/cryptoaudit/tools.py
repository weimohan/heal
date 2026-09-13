"""Read-only source analysis and tightly constrained in-memory repair tools."""

from __future__ import annotations

import ast
import difflib
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from .contracts import AlgorithmUse, LocalFinding, Observation, PatchProposal, source_sha256
from .knowledge import KnowledgeBase
from .policies import ALGORITHM_NOTES, POLICY_RULES, rule_by_id


_SECRET_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "api-key",
    "token",
    "access_key",
    "master_key",
    "shared_secret",
    "admin_token",
    "private_key",
    "encryption_key",
    "signing_key",
}
_HASH_NAMES = {"md4": "MD4", "md5": "MD5", "sha1": "SHA-1", "sha_1": "SHA-1", "sha256": "SHA-256"}
_SAFE_NAME_SUFFIXES = {"id", "ids", "count", "length", "name", "size", "type", "index"}
_SENSITIVE_SUFFIXES = {"key", "secret", "token", "password", "passwd", "credential", "credentials"}
_HASH_NAME_PARTS = {"hash", "digest", "mac", "checksum"}
_AEAD_MODES = {"MODE_GCM", "MODE_CCM", "MODE_EAX", "MODE_SIV", "MODE_OCB"}
_NONCE_MODES = _AEAD_MODES | {"MODE_CTR"}
_PBKDF2_MIN_ITERATIONS = 100_000


def redact_sensitive_text(text: str) -> str:
    pattern = re.compile(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<assignment>\s*=\s*(?:[bBrRuU]{0,2})?)"
        r"(?P<quote>[\"'])(?P<value>[^\"']*)(?P=quote)"
    )

    def replace(match: re.Match[str]) -> str:
        if not _looks_sensitive_name(match.group("name")):
            return match.group(0)
        return f"{match.group('name')}{match.group('assignment')}{match.group('quote')}<REDACTED>{match.group('quote')}"

    return pattern.sub(replace, text)


def redacted_source(source: str) -> str:
    return redact_sensitive_text(source)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _source_segment(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    if segment:
        return segment.replace("\r", "")[:240]
    lines = source.splitlines()
    line = getattr(node, "lineno", 1)
    return lines[line - 1][:240] if 0 < line <= len(lines) else ""


def _aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    aliases: dict[str, str] = {}
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".")[0]
                aliases[local] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                local = item.asname or item.name
                imported[local] = f"{module}.{item.name}" if module else item.name
    return aliases, imported


def _canonical_name(name: str, aliases: dict[str, str], imported: dict[str, str]) -> str:
    if not name:
        return name
    parts = name.split(".")
    if parts[0] in imported:
        return ".".join([imported[parts[0]], *parts[1:]])
    if parts[0] in aliases:
        return ".".join([aliases[parts[0]], *parts[1:]])
    return name


def _node_candidates(tree: ast.AST) -> list[ast.AST]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Call, ast.Attribute, ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign))
    ]


def _algorithm_name(canonical: str, segment: str) -> str | None:
    canonical_value = canonical.lower()
    segment_value = segment.lower()
    canonical_parts = {part for part in canonical_value.split(".") if part}
    if "pbkdf2_hmac" in canonical_value:
        return "PBKDF2"
    if "crc32" in canonical_value:
        return "CRC32"
    if "rc4" in canonical_parts:
        return "RC4"
    if "md4" in canonical_parts:
        return "MD4"
    if "md5" in canonical_parts:
        return "MD5"
    if "sha1" in canonical_parts or "sha_1" in canonical_parts:
        return "SHA-1"
    if "sha256" in canonical_parts:
        return "SHA-256"
    if "des3" in canonical_parts or "3des" in canonical_parts or "tripledes" in canonical_parts:
        return "3DES"
    if "chacha20" in canonical_value:
        return "ChaCha20"
    if "sm4" in canonical_value:
        return "SM4"
    if "sm3" in canonical_value:
        return "SM3"
    if "sm2" in canonical_value:
        return "SM2"
    if "aes" in canonical_parts:
        return "AES"
    if "des" in canonical_parts:
        return "DES"
    if "rsa" in canonical_parts:
        return "RSA"

    # Imports can expose class names such as ChaCha20Poly1305 or CryptSM4;
    # executable names above stay component-based to avoid sha1_hash false positives.
    if re.search(r"\b(?:from|import)\b", segment_value):
        if "chacha20" in segment_value:
            return "ChaCha20"
        if "cryptsm4" in segment_value or re.search(r"\bsm4\b", segment_value):
            return "SM4"
        if re.search(r"\bsm3\b", segment_value):
            return "SM3"
        if re.search(r"\bsm2\b", segment_value):
            return "SM2"
        if re.search(r"\brsa\b", segment_value):
            return "RSA"
        if re.search(r"\b(?:rc4)\b", segment_value):
            return "RC4"
        if re.search(r"\bmd4\b", segment_value):
            return "MD4"
        if re.search(r"\bmd5\b", segment_value):
            return "MD5"
        if re.search(r"\b(?:sha1|sha_1)\b", segment_value):
            return "SHA-1"
        if re.search(r"\bsha256\b", segment_value):
            return "SHA-256"
        if re.search(r"\b(?:des3|3des|tripledes)\b", segment_value):
            return "3DES"
        if re.search(r"\baes\b", segment_value):
            return "AES"
        if re.search(r"\bdes\b", segment_value):
            return "DES"
    return None


def _import_algorithm_names(segment: str) -> list[str]:
    patterns = (
        ("ChaCha20", r"\bChaCha20(?:Poly1305)?\b"),
        ("3DES", r"\b(?:3DES|DES3|TripleDES)\b"),
        ("PBKDF2", r"\bpbkdf2_hmac\b"),
        ("CRC32", r"\bcrc32\b"),
        ("RC4", r"\bRC4\b"),
        ("MD4", r"\bmd4\b"),
        ("MD5", r"\bmd5\b"),
        ("SHA-1", r"\b(?:sha1|sha_1)\b"),
        ("SHA-256", r"\bsha256\b"),
        ("SM4", r"\b(?:SM4|CryptSM4)\b"),
        ("SM3", r"\bSM3\b"),
        ("SM2", r"\bSM2\b"),
        ("RSA", r"\bRSA\b"),
        ("AES", r"\bAES\b"),
        ("DES", r"\bDES\b"),
    )
    return [name for name, pattern in patterns if re.search(pattern, segment, re.IGNORECASE)]


def inventory_algorithms(source: str) -> list[AlgorithmUse]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = ast.parse("pass")
    aliases, imported = _aliases(tree)
    uses: list[AlgorithmUse] = []
    seen: set[tuple[str, int]] = set()
    inventory_nodes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Call, ast.Attribute, ast.Import, ast.ImportFrom))
    ]
    for node in inventory_nodes:
        segment = _source_segment(source, node)
        if isinstance(node, ast.Call):
            canonical = _canonical_name(_dotted_name(node.func), aliases, imported)
        elif isinstance(node, ast.Attribute):
            canonical = _canonical_name(_dotted_name(node), aliases, imported)
        elif isinstance(node, ast.ImportFrom):
            canonical = _canonical_name(segment, aliases, imported)
        else:
            canonical = segment
        names = _import_algorithm_names(segment) if isinstance(node, (ast.Import, ast.ImportFrom)) else [_algorithm_name(canonical, segment)]
        line = getattr(node, "lineno", 1)
        for name in names:
            if not name or name not in ALGORITHM_NOTES or (name, line) in seen:
                continue
            seen.add((name, line))
            category, status, note = ALGORITHM_NOTES[name]
            uses.append(
                AlgorithmUse(
                    name=name,
                    category=category,
                    status=status,
                    line=line,
                    evidence=redact_sensitive_text(segment),
                    security_note=note,
                    evidence_type="ast",
                )
            )
    return sorted(uses, key=lambda item: (item.line, item.name))


def _finding(rule_id: str, line: int, segment: str, origin: str = "ast") -> LocalFinding:
    rule = rule_by_id(rule_id)
    evidence_id = f"E-{rule_id}:{line}"
    return LocalFinding(
        finding_id=f"{rule_id}:{line}",
        rule_id=rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        line=line,
        end_line=line,
        evidence=redact_sensitive_text(segment),
        cwe=rule.cwe,
        remediation=rule.remediation,
        origin=origin,
        evidence_ids=[evidence_id],
        evidence_type="ast",
    )


def _normalized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _looks_sensitive_name(name: str) -> bool:
    normalized = _normalized_name(name)
    if not normalized:
        return False
    if normalized in _SECRET_NAMES:
        return True
    if normalized.endswith(tuple(f"_{suffix}" for suffix in _SAFE_NAME_SUFFIXES)):
        return False
    return normalized in _SENSITIVE_SUFFIXES or normalized.endswith(
        tuple(f"_{suffix}" for suffix in _SENSITIVE_SUFFIXES)
    )


def _looks_hash_name(name: str) -> bool:
    parts = set(_normalized_name(name).split("_"))
    return bool(parts & _HASH_NAME_PARTS)


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for item in target.elts:
            names.extend(_target_names(item))
        return names
    return []


def _assignment_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    names: list[str] = []
    for target in targets:
        names.extend(_target_names(target))
    return names


def _is_static_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes, int))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
        if isinstance(node.op, ast.Mult):
            return _is_static_expression(node.left) and isinstance(node.right, ast.Constant) and isinstance(
                node.right.value, int
            )
        return _is_static_expression(node.left) and _is_static_expression(node.right)
    return False


def _static_assignments(tree: ast.AST) -> dict[str, bool]:
    values: dict[str, bool] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            is_static = _is_static_expression(node.value)
            for name in _assignment_names(node):
                values[name] = is_static
    return values


def _is_static_reference(node: ast.AST | None, static_assignments: dict[str, bool]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return static_assignments.get(node.id, False)
    return _is_static_expression(node)


def _expression_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _is_sensitive_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return _looks_sensitive_name(node.id) or _looks_hash_name(node.id)
    if isinstance(node, ast.Attribute):
        return _looks_sensitive_name(node.attr) or _looks_hash_name(node.attr)
    if isinstance(node, ast.Subscript):
        slice_node = node.slice
        if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
            return _looks_sensitive_name(slice_node.value) or _looks_hash_name(slice_node.value)
    if isinstance(node, ast.Call):
        return _looks_hash_name(_dotted_name(node.func))
    return False


def _assignment_secret(node: ast.Assign | ast.AnnAssign) -> bool:
    value = node.value
    if not isinstance(value, ast.Constant) or not isinstance(value.value, (str, bytes)) or len(value.value) < 3:
        return False
    return any(_looks_sensitive_name(name) for name in _assignment_names(node))


def _is_nonce_name(name: str) -> bool:
    normalized = _normalized_name(name)
    return normalized == "nonce" or normalized.endswith("_nonce")


def _is_iv_name(name: str) -> bool:
    normalized = _normalized_name(name)
    return normalized in {"iv", "initialization_vector", "init_vector"} or normalized.endswith("_iv")


def _is_leak_sink(name: str) -> bool:
    normalized = _normalized_name(name)
    if normalized in {"raw", "token_data", "payload", "message", "header", "url"}:
        return True
    return bool(set(normalized.split("_")) & {"token", "payload", "header", "message", "log"})


def _call_keyword(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _contains_weak_digest(node: ast.Call, aliases: dict[str, str], imported: dict[str, str]) -> bool:
    weak_names = set(_HASH_NAMES) - {"sha256"}
    for child in ast.walk(node):
        if not isinstance(child, (ast.Name, ast.Attribute)):
            continue
        canonical = _canonical_name(_dotted_name(child), aliases, imported).lower()
        if canonical.split(".")[-1] in weak_names:
            return True
    return False


def _contains_sensitive_log_value(node: ast.Call, segment: str) -> bool:
    if any(_looks_sensitive_name(name) for name in _expression_names(node)):
        return True
    return bool(re.search(r"\b(?:decrypt|verify_and_decrypt|plaintext|cleartext)\b", segment, re.IGNORECASE))


def scan_python_source(source: str) -> list[LocalFinding]:
    """Scan executable AST nodes and small local data-flow patterns for evidence-backed findings."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    aliases, imported = _aliases(tree)
    static_assignments = _static_assignments(tree)
    static_nonce_names = {
        name for name, is_static in static_assignments.items() if is_static and _is_nonce_name(name)
    }
    static_iv_names = {name for name, is_static in static_assignments.items() if is_static and _is_iv_name(name)}
    static_nonce_uses: set[str] = set()
    static_iv_uses: set[str] = set()
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call):
            continue
        candidate_segment = _source_segment(source, candidate)
        if not any(mode in candidate_segment for mode in _NONCE_MODES):
            continue
        nonce_value = _call_keyword(candidate, "nonce")
        if isinstance(nonce_value, ast.Name) and nonce_value.id in static_nonce_names:
            static_nonce_uses.add(nonce_value.id)
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call):
            continue
        candidate_segment = _source_segment(source, candidate)
        if "MODE_CBC" not in candidate_segment:
            continue
        iv_value = _call_keyword(candidate, "iv")
        if isinstance(iv_value, ast.Name) and iv_value.id in static_iv_names:
            static_iv_uses.add(iv_value.id)
    findings: dict[str, LocalFinding] = {}
    reported_nonce_refs: set[str] = set()
    reported_iv_refs: set[str] = set()

    def add(rule_id: str, node: ast.AST, segment: str | None = None) -> None:
        line = getattr(node, "lineno", 1)
        evidence = segment if segment is not None else _source_segment(source, node)
        findings[f"{rule_id}:{line}"] = _finding(rule_id, line, evidence)

    for node in ast.walk(tree):
        line = getattr(node, "lineno", 1)
        segment = _source_segment(source, node)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            names = _assignment_names(node)
            if _assignment_secret(node):
                add("CRYPTO-SECRET-001", node, segment)
            if any(
                _is_nonce_name(name) and name not in static_nonce_uses for name in names
            ) and _is_static_expression(node.value):
                add("CRYPTO-NONCE-001", node, segment)
            if any(_is_iv_name(name) and name not in static_iv_uses for name in names) and _is_static_expression(
                node.value
            ):
                add("CRYPTO-IV-001", node, segment)
            source_names = _expression_names(node.value)
            if any(_looks_sensitive_name(name) for name in source_names) and any(
                _is_leak_sink(name) for name in names
            ):
                add("CRYPTO-KEY-LEAK-001", node, segment)

        if isinstance(node, ast.Call):
            canonical = _canonical_name(_dotted_name(node.func), aliases, imported)
            lower = canonical.lower()
            if lower.startswith("random."):
                add("CRYPTO-RANDOM-001", node, segment)
            if lower.endswith(tuple(f".{name}" for name in ("md4", "md5", "sha1", "sha_1"))):
                add("CRYPTO-HASH-001", node, segment)
            if re.search(r"(?:^|\.)DES\.new$", canonical, re.IGNORECASE):
                add("CRYPTO-DES-001", node, segment)
            if re.search(r"(?:^|\.)(?:DES3|TripleDES|3DES)\.new$", canonical, re.IGNORECASE):
                add("CRYPTO-3DES-001", node, segment)
            if re.search(r"(?:^|\.)RC4\.new$", canonical, re.IGNORECASE):
                add("CRYPTO-RC4-001", node, segment)
            if (lower == "hmac.new" or lower.endswith(".hmac.new")) and _contains_weak_digest(node, aliases, imported):
                add("CRYPTO-HMAC-001", node, segment)
            if lower.endswith(".crc32") or lower == "crc32":
                add("CRYPTO-CHECKSUM-001", node, segment)
            if lower.endswith(".pbkdf2_hmac"):
                algorithm = _literal_string(node.args[0] if node.args else None)
                iterations = _call_keyword(node, "iterations")
                if isinstance(iterations, ast.Constant) and isinstance(iterations.value, int) and iterations.value < _PBKDF2_MIN_ITERATIONS:
                    add("CRYPTO-PBKDF2-001", node, segment)
                if algorithm and algorithm.lower() in {"md4", "md5", "sha1", "sha-1"}:
                    add("CRYPTO-PBKDF2-HASH-001", node, segment)
            if re.search(r"(?:^|\.)rsa\.generate$", lower, re.IGNORECASE):
                key_size = node.args[0] if node.args else None
                if isinstance(key_size, ast.Constant) and isinstance(key_size.value, int) and key_size.value < 2048:
                    add("CRYPTO-RSA-KEYSIZE-001", node, segment)
            if re.search(r"(?:^|\.)rsa\.generate_private_key$", lower, re.IGNORECASE):
                key_size = _call_keyword(node, "key_size")
                if isinstance(key_size, ast.Constant) and isinstance(key_size.value, int) and key_size.value < 2048:
                    add("CRYPTO-RSA-KEYSIZE-001", node, segment)
            if any(mode in segment for mode in _AEAD_MODES):
                nonce_value = _call_keyword(node, "nonce")
                nonce_ref = nonce_value.id if isinstance(nonce_value, ast.Name) else f"literal:{line}"
                if _is_static_reference(nonce_value, static_assignments) and nonce_ref not in reported_nonce_refs:
                    add("CRYPTO-NONCE-001", node, segment)
                    reported_nonce_refs.add(nonce_ref)
            if "MODE_CTR" in segment and _is_static_reference(_call_keyword(node, "nonce"), static_assignments):
                nonce_value = _call_keyword(node, "nonce")
                nonce_ref = nonce_value.id if isinstance(nonce_value, ast.Name) else f"literal:{line}"
                if nonce_ref not in reported_nonce_refs:
                    add("CRYPTO-NONCE-001", node, segment)
                    reported_nonce_refs.add(nonce_ref)
            if "MODE_CBC" in segment:
                iv_value = _call_keyword(node, "iv")
                iv_ref = iv_value.id if isinstance(iv_value, ast.Name) else f"literal:{line}"
                if _is_static_reference(iv_value, static_assignments) and iv_ref not in reported_iv_refs:
                    add("CRYPTO-IV-001", node, segment)
                    reported_iv_refs.add(iv_ref)
            if lower in {"print", "logging.debug", "logger.debug"} or lower.endswith(".debug"):
                if _contains_sensitive_log_value(node, segment):
                    add("CRYPTO-LOG-LEAK-001", node, segment)
            if "MODE_ECB" in segment:
                add("CRYPTO-ECB-001", node, segment)

        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            expressions = [node.left, *node.comparators]
            if any(_is_sensitive_expression(expression) for expression in expressions):
                add("CRYPTO-COMPARE-001", node, segment)

    return sorted(findings.values(), key=lambda item: (item.line, item.rule_id))


def inspect_source_context(source: str, line: int, radius: int = 3) -> dict[str, Any]:
    lines = source.splitlines()
    if not 1 <= line <= max(len(lines), 1):
        raise ValueError("line is outside the source")
    radius = max(0, min(radius, 8))
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return {
        "line_start": start,
        "line_end": end,
        "context": "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1)),
        "evidence_ids": [f"E-CONTEXT:{line}:{start}-{end}"],
    }


def find_related_calls(source: str, symbol: str = "") -> dict[str, Any]:
    if not symbol or len(symbol) > 80 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", symbol):
        raise ValueError("symbol must be a simple Python name")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"error": f"syntax_error:{exc}", "definitions": [], "calls": [], "evidence_ids": []}
    definitions = []
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
            definitions.append({"line": node.lineno, "kind": type(node).__name__})
        if isinstance(node, ast.Call) and symbol in _dotted_name(node.func):
            calls.append({"line": node.lineno, "expression": _source_segment(source, node)})
    return {
        "symbol": symbol,
        "definitions": definitions,
        "calls": calls,
        "evidence_ids": [f"E-CALLS:{symbol}"],
    }


def _diff(before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="original.py",
            tofile="proposed.py",
        )
    )


def propose_patch(source: str, findings: list[LocalFinding]) -> PatchProposal:
    finding_ids = [finding.finding_id for finding in findings]
    if any(finding.rule_id in {"CRYPTO-DES-001", "CRYPTO-3DES-001", "CRYPTO-ECB-001"} for finding in findings):
        return PatchProposal(
            status="requires_review",
            rationale="Cipher and mode migration may change protocol compatibility and requires human approval.",
            requires_human_review=True,
            target_finding_ids=finding_ids,
            source_sha256=source_sha256(source),
        )
    pattern = re.compile(
        r"^(?P<indent>\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*=\s*(?:b)?[\"'][^\"']+[\"']\s*$",
        re.IGNORECASE,
    )
    lines = source.splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = pattern.match(line.rstrip("\r\n"))
        if match is None or not _looks_sensitive_name(match.group("name")):
            continue
        name = match.group("name")
        env_name = re.sub(r"[^A-Z0-9_]", "_", name.upper())
        newline = "\n" if line.endswith("\n") else ""
        lines[index] = f'{match.group("indent")}{name} = os.environ["{env_name}"]{newline}'
        patched = "".join(lines)
        if not re.search(r"^\s*import\s+os\b|^\s*from\s+os\s+import\b", patched, re.MULTILINE):
            patched = "import os\n" + patched
        return PatchProposal(
            status="proposed",
            diff=_diff(redacted_source(source), patched),
            patched_code=patched,
            rationale="Replace hard-coded credential material with an environment variable reference.",
            target_finding_ids=[finding.finding_id for finding in findings if finding.rule_id == "CRYPTO-SECRET-001"],
            source_sha256=source_sha256(source),
        )
    return PatchProposal(
        status="not_applicable",
        rationale="No deterministic low-risk repair template matched the confirmed findings.",
        target_finding_ids=finding_ids,
        source_sha256=source_sha256(source),
    )


def apply_patch_to_source(source: str, proposal: PatchProposal) -> str:
    if proposal.status != "proposed" or not proposal.patched_code:
        raise ValueError("proposal is not automatically applicable")
    if source_sha256(source) != proposal.source_sha256:
        raise ValueError("source changed after proposal creation")
    return proposal.patched_code


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    function: Callable[..., Any]


@dataclass(frozen=True)
class ToolResult:
    success: bool
    payload: Any
    evidence_ids: list[str]
    duration_ms: float
    error: str = ""


class ToolRegistry:
    """Bind tools to one source; no tool accepts arbitrary filesystem paths or code."""

    def __init__(self, source: str, knowledge: KnowledgeBase | None = None, approval: str = ""):
        self.source = source
        self.knowledge = knowledge
        self.approval = approval
        self._specs = {
            "inventory_algorithms": ToolSpec(
                "inventory_algorithms", "Identify cryptographic algorithms and modes in the supplied source.", {"type": "object", "properties": {}}, self._inventory
            ),
            "scan_python_source": ToolSpec(
                "scan_python_source", "Collect confirmed local policy findings from executable Python AST nodes.", {"type": "object", "properties": {}}, self._scan
            ),
            "inspect_source_context": ToolSpec(
                "inspect_source_context", "Return a bounded, line-numbered context window.", {"type": "object", "properties": {"line": {"type": "integer", "minimum": 1}, "radius": {"type": "integer", "minimum": 0, "maximum": 8}}, "required": ["line"]}, self._inspect
            ),
            "find_related_calls": ToolSpec(
                "find_related_calls", "Find local definitions and calls for one Python symbol.", {"type": "object", "properties": {"symbol": {"type": "string", "maxLength": 80}}, "required": ["symbol"]}, self._related
            ),
            "retrieve_crypto_guidance": ToolSpec(
                "retrieve_crypto_guidance", "Retrieve versioned local guidance with citations.", {"type": "object", "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 240}}, "required": ["query"]}, self._retrieve
            ),
            "propose_patch": ToolSpec(
                "propose_patch", "Create a constrained in-memory repair proposal from local findings.", {"type": "object", "properties": {}, "additionalProperties": False}, self._propose
            ),
            "verify_patch": ToolSpec(
                "verify_patch", "Apply an exact-context proposal in memory and rescan it, or record a no-patch verification.", {"type": "object", "properties": {}, "additionalProperties": False}, self._verify
            ),
        }

    def names(self) -> list[str]:
        return list(self._specs)

    def definitions(self) -> list[dict[str, Any]]:
        return [
            {"type": "function", "function": {"name": spec.name, "description": spec.description, "parameters": spec.parameters}}
            for spec in self._specs.values()
        ]

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        arguments = arguments or {}
        if name not in self._specs:
            return ToolResult(False, None, [], 0.0, f"unknown_tool:{name}")
        spec = self._specs[name]
        allowed = set(spec.parameters.get("properties", {}))
        if set(arguments) - allowed:
            return ToolResult(False, None, [], 0.0, "unexpected_tool_argument")
        started = time.perf_counter()
        try:
            payload = spec.function(**arguments)
            evidence_ids = list(payload.get("evidence_ids", [])) if isinstance(payload, dict) else []
            return ToolResult(True, payload, evidence_ids, (time.perf_counter() - started) * 1000)
        except Exception as exc:
            return ToolResult(False, None, [], (time.perf_counter() - started) * 1000, f"{type(exc).__name__}:{exc}")

    def _inventory(self) -> dict[str, Any]:
        uses = inventory_algorithms(self.source)
        return {"algorithms": [item.model_dump(mode="json") for item in uses], "completed": True, "evidence_ids": ["E-INVENTORY"]}

    def _scan(self) -> dict[str, Any]:
        findings = scan_python_source(self.source)
        return {"findings": [item.model_dump(mode="json") for item in findings], "completed": True, "evidence_ids": ["E-LOCAL-SCAN", *[item.evidence_ids[0] for item in findings]]}

    def _inspect(self, line: int, radius: int = 3) -> dict[str, Any]:
        return inspect_source_context(self.source, line, radius)

    def _related(self, symbol: str) -> dict[str, Any]:
        return find_related_calls(self.source, symbol)

    def _retrieve(self, query: str) -> dict[str, Any]:
        if self.knowledge is None:
            return {"citations": [], "evidence_ids": ["E-KNOWLEDGE:EMPTY"]}
        queries = [item.strip() for item in query.splitlines() if item.strip()]
        citations = self.knowledge.search_many(queries) if len(queries) > 1 else self.knowledge.search(query)
        return {"citations": [item.model_dump(mode="json") for item in citations], "evidence_ids": [f"E-KNOWLEDGE:{item.knowledge_id}" for item in citations]}

    def _propose(self) -> dict[str, Any]:
        return {"proposal": propose_patch(self.source, scan_python_source(self.source)).model_dump(mode="json"), "evidence_ids": ["E-PATCH-PROPOSAL"]}

    def _verify(self) -> dict[str, Any]:
        from .verifier import verify_source

        findings = scan_python_source(self.source)
        proposal = propose_patch(self.source, findings)
        verification = verify_source(self.source, findings, proposal, self.approval)
        return {"proposal": proposal.model_dump(mode="json"), "verification": verification.model_dump(mode="json"), "evidence_ids": verification.evidence_ids}
