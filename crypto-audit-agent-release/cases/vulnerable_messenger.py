"""Synthetic secure-messenger sample containing multiple crypto mistakes."""

import base64
import binascii
import hashlib
import hmac
import os

from Crypto.Cipher import AES, DES3, RC4
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


SERVER_PUB_KEY = RSA.import_key(
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sTIy4Z3Kl8gU\n"
    "8F4Y9V3KlFmJnVHsLqKp7rXN2YqGhT5JkLmNpQrStUvWxYzAbCdEfGhIjKlMnOpQr\n"
    "StUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCd\n"
    "EfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQ\n"
    "rStUvWxYzAbCdEfGhIjKlMnOpQIDAQAB\n"
    "-----END RSA PUBLIC KEY-----"
)
SHARED_SECRET = "super_secret_key_12345"
IV = b"\x00" * 16


def create_message(sender: str, recipient: str, content: str) -> dict:
    """Create an intentionally weak encrypted message."""
    rc4_cipher = RC4.new(key=SHARED_SECRET.encode("utf-8"))
    encrypted_body = rc4_cipher.encrypt(content.encode("utf-8"))
    msg_hash = hashlib.md4(content.encode("utf-8")).hexdigest()
    mac = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        f"{sender}:{recipient}:{encrypted_body}".encode("utf-8"),
        hashlib.md5,
    ).hexdigest()
    return {
        "sender": base64.b64encode(sender.encode()).decode(),
        "recipient": recipient,
        "body": base64.b64encode(encrypted_body).decode(),
        "hash": msg_hash,
        "mac": mac,
        "iv": base64.b64encode(IV).decode(),
    }


def verify_and_decrypt(msg: dict) -> str:
    """Verify and decrypt an intentionally weak message format."""
    expected_mac = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        f"{msg['sender']}:{msg['recipient']}:{msg['body']}".encode("utf-8"),
        hashlib.md5,
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, msg["mac"]):
        raise ValueError("message authentication failed")
    iv = base64.b64decode(msg["iv"])
    cipher = AES.new(SHARED_SECRET.encode("utf-8")[:32], AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(msg["body"])), 16)
    content = decrypted.decode("utf-8")
    actual_hash = hashlib.md4(content.encode("utf-8")).hexdigest()
    if actual_hash != msg["hash"]:
        raise ValueError("content integrity check failed")
    return content


def encrypt_file_key(file_data: bytes) -> dict:
    """Use intentionally weak RSA and CBC parameters for evaluation."""
    key = RSA.generate(512)
    pub_key = key.publickey()
    session_key = os.urandom(16)
    encrypted_key = pub_key.encrypt(session_key, None)[0]
    cipher = AES.new(session_key, AES.MODE_CBC, iv=b"\x01\x02\x03" * 5 + b"\x04")
    encrypted_data = cipher.encrypt(pad(file_data, 16))
    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "key_size": key.size(),
        "iv": base64.b64encode(cipher.iv).decode(),
    }


def generate_session_token(user_id: str, role: str) -> str:
    raw = f"{user_id}:{role}:{SHARED_SECRET}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def log_message_debug(msg: dict) -> None:
    print(f"[DEBUG] sender: {msg['sender']}")
    print(f"[DEBUG] recipient: {msg['recipient']}")
    print(f"[DEBUG] plaintext: {verify_and_decrypt(msg)}")
    print(f"[DEBUG] shared key: {SHARED_SECRET}")


def derive_keys(password: str, salt: bytes) -> dict:
    dk = hashlib.pbkdf2_hmac(
        "md5",
        password.encode("utf-8"),
        salt,
        iterations=100,
        dklen=32,
    )
    return {"encrypt_key": dk[:16], "mac_key": dk[16:]}


def quick_hash(data: bytes) -> str:
    return format(binascii.crc32(data), "08x")


def decrypt_with_fixed_nonce(key: bytes, data: bytes) -> bytes:
    nonce = b"123456789012"
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(data)

